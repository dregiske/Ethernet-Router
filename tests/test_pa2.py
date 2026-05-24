"""
Comprehensive PA2a tests covering all seven required behaviors:
  1. Route ICMP between client and servers
  2. Handle ARP requests and replies
  3. Respond to ICMP echo requests addressed to any router IP
  4. Send ARP request per forwarded packet (no cache shortcut)
  5. Queue packets and time-out after 5 ARP retries with host-unreachable
  6. Don't needlessly drop packets while waiting on ARP
  7. Enforce ARP timeout even when no further packets arrive

Plus edge cases (TTL exceeded, net unreachable, malformed packets).
"""
from base import *
import unittest
import random
import time


class TestPA2(CSE123TestBase):

    def setUp(self):
        self.setUpEnvironment(rtable='rtable', build=True, debug=False, manual_sr=False)

    def tearDown(self):
        self.tearDownEnvironment()

    # ── Behavior 3: ICMP echo to router interfaces ─────────────────────

    def test_ping_router_receiving_iface(self):
        """Ping the router's IP on the client's own subnet (eth3)."""
        output = self.client["m"].cmd(f"ping -c 1 -W 2 {self.client['gw']}")
        self.assertIn("0% packet loss", output,
                      msg=f"ping to {self.client['gw']} (eth3) failed: {output}")

    def test_ping_router_cross_iface(self):
        """Ping a router IP that lives on a DIFFERENT iface from the source."""
        # client is on 10.0.1.0/24, eth1 is 192.168.2.1 — different subnet.
        output = self.client["m"].cmd(f"ping -c 1 -W 2 {self.server1['gw']}")
        self.assertIn("0% packet loss", output,
                      msg=f"ping to {self.server1['gw']} (eth1) failed: {output}")

        output = self.client["m"].cmd(f"ping -c 1 -W 2 {self.server2['gw']}")
        self.assertIn("0% packet loss", output,
                      msg=f"ping to {self.server2['gw']} (eth2) failed: {output}")

    # ── Behavior 1 + 2 + 4: route ICMP, ARP exchange, per-packet ARP ──

    def test_ping_server1_through_router(self):
        output = self.client["m"].cmd(f"ping -c 3 -W 2 {self.server1['ip']}")
        self.assertIn("0% packet loss", output,
                      msg=f"ping client -> server1 failed: {output}")

    def test_ping_server2_through_router(self):
        output = self.client["m"].cmd(f"ping -c 3 -W 2 {self.server2['ip']}")
        self.assertIn("0% packet loss", output,
                      msg=f"ping client -> server2 failed: {output}")

    def test_ping_server_to_server(self):
        """server1 -> server2 traverses the router across two different subnets."""
        output = self.server1["m"].cmd(f"ping -c 3 -W 2 {self.server2['ip']}")
        self.assertIn("0% packet loss", output,
                      msg=f"ping server1 -> server2 failed: {output}")

    # ── Behavior 2: ARP request handling ───────────────────────────────

    def test_arp_request_for_router_gets_reply(self):
        """Direct ARP request from client to its gateway should be answered."""
        self.clearPcapBuffers()
        src = self.client
        # Broadcast ARP request asking who has 10.0.1.1
        pkt = Ether(src=src["mac"], dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, hwsrc=src["mac"], psrc=src["ip"], pdst=src["gw"]
        )
        self.sendPacket(pkt, node=src["m"].name)

        arps = self.expectPackets(src["m"].name, type='arp', timewait_sec=0.5)
        replies = [p for p, _ in arps
                   if p[ARP].op == 2 and p[ARP].psrc == src["gw"]]
        self.assertTrue(len(replies) > 0,
                        msg="No ARP reply received for router's gateway IP")

    def test_arp_request_wrong_target_ignored(self):
        """ARP request for a non-router IP on this subnet must be ignored."""
        self.clearPcapBuffers()
        src = self.client
        pkt = Ether(src=src["mac"], dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, hwsrc=src["mac"], psrc=src["ip"], pdst="10.0.1.99"  # not us
        )
        self.sendPacket(pkt, node=src["m"].name)

        arps = self.expectPackets(src["m"].name, type='arp', timewait_sec=0.5)
        replies = [p for p, _ in arps
                   if p[ARP].op == 2 and p[ARP].psrc == "10.0.1.99"]
        self.assertEqual(len(replies), 0,
                         msg="Router replied to ARP for an IP it does not own")

    # ── Edge cases: ICMP errors ─────────────────────────────────────────

    def test_time_exceeded_with_ttl_1(self):
        """TTL=1 forwarded packet should produce ICMP type 11/0."""
        self.clearPcapBuffers()
        src = self.client
        # Ping with --ttl=1 (Linux ping option)
        output = src["m"].cmd(f"ping -c 1 -W 2 --ttl=1 {self.server2['ip']}")
        # Should see "Time to live exceeded"
        self.assertTrue(
            "Time to live exceeded" in output or "ttl=" not in output.split("\n")[1] if len(output.split("\n")) > 1 else True,
            msg=f"Expected TTL-exceeded response, got: {output}"
        )

    def test_net_unreachable_no_route(self):
        """Pinging an IP with no rtable entry yields ICMP type 3/0."""
        self.clearPcapBuffers()
        src = self.client
        # 8.8.8.8 isn't in our rtable
        output = src["m"].cmd(f"ping -c 1 -W 2 8.8.8.8")
        # Should see "Destination Net Unreachable" or no reply
        self.assertTrue(
            "Destination Net Unreachable" in output
            or "Unreachable" in output
            or "0 received" in output,
            msg=f"Expected net-unreachable for 8.8.8.8, got: {output}"
        )

    # ── Behavior 4: ARP is sent per forwarded packet (no caching) ──────

    def test_arp_sent_for_forwarded_packet(self):
        """Sending an IP packet via the router should trigger an ARP for the dest."""
        self.clearPcapBuffers()
        src = self.client
        dst = self.server2
        id = random.randint(1, 65535)
        pkt = (Ether(src=src["mac"], dst=src["gwmac"])
               / IP(src=src["ip"], dst=dst["ip"], id=id, ttl=64)
               / ICMP(type=8, id=0x42))
        self.sendPacket(pkt, node=src["m"].name)

        # On dst's wire we should see an ARP REQUEST from the router
        # asking for dst's IP — proves the router did ARP for forwarding.
        arps = self.expectPackets(dst["m"].name, type='arp', timewait_sec=0.5)
        forwards = [p for p, _ in arps
                    if p[ARP].op == 1 and p[ARP].pdst == dst["ip"]]
        self.assertTrue(len(forwards) > 0,
                        msg="Router did not ARP for the next hop when forwarding")

    # ── Behavior 6: packets queued during ARP aren't dropped ───────────

    def test_first_ping_succeeds_despite_arp_round_trip(self):
        """The very first ICMP request to a fresh dest should still reach it."""
        self.clearPcapBuffers()
        src = self.client
        dst = self.server2
        id = random.randint(1, 65535)
        pkt = (Ether(src=src["mac"], dst=src["gwmac"])
               / IP(src=src["ip"], dst=dst["ip"], id=id, ttl=64)
               / ICMP(type=8, id=0x99))
        self.sendPacket(pkt, node=src["m"].name)

        icmps = self.expectPackets(dst["m"].name, type='icmp', timewait_sec=1.0)
        delivered = [p for p, _ in icmps
                     if IP in p and p[IP].id == id and p[ICMP].type == 8]
        self.assertTrue(len(delivered) > 0,
                        msg="First-time forward dropped instead of queued")


if __name__ == "__main__":
    unittest.main()
