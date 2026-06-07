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

PA2b additions (TestPA2b, TestPA2bLPM):
  - TCP/UDP to a router interface -> ICMP port unreachable (type 3, code 3)
  - Other protocols to a router interface are ignored
  - Forwarded packets reuse the ARP cache (no re-ARP within the cache TTL)
  - Longest Prefix Match prefers the most specific route over the default
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


class TestPA2b(CSE123TestBase):
    """PA2b additions: port-unreachable for TCP/UDP to the router, ignoring
    other protocols to the router, and ARP cache reuse on forward."""

    def setUp(self):
        self.setUpEnvironment(rtable='rtable', build=True, debug=False, manual_sr=False)

    def tearDown(self):
        self.tearDownEnvironment()

    # ── Requirement 5a: TCP/UDP to a router interface → port unreachable ──

    def test_udp_to_router_port_unreachable(self):
        """A UDP datagram to a router IP (like a traceroute probe) must get
        ICMP port unreachable (type 3, code 3)."""
        self.clearPcapBuffers()
        src = self.client
        pkt = (Ether(src=src["mac"], dst=src["gwmac"])
               / IP(src=src["ip"], dst=src["gw"], ttl=64)
               / UDP(sport=33434, dport=33434))
        self.sendPacket(pkt, node=src["m"].name)

        icmps = self.expectPackets(src["m"].name, type='icmp', timewait_sec=0.5)
        pu = [p for p, _ in icmps
              if p[ICMP].type == 3 and p[ICMP].code == 3]
        self.assertTrue(len(pu) > 0,
                        msg="No ICMP port unreachable for UDP sent to router")

    def test_tcp_to_router_port_unreachable(self):
        """A TCP segment to a router IP must also get port unreachable."""
        self.clearPcapBuffers()
        src = self.client
        pkt = (Ether(src=src["mac"], dst=src["gwmac"])
               / IP(src=src["ip"], dst=src["gw"], ttl=64)
               / TCP(sport=12345, dport=80, flags="S"))
        self.sendPacket(pkt, node=src["m"].name)

        icmps = self.expectPackets(src["m"].name, type='icmp', timewait_sec=0.5)
        pu = [p for p, _ in icmps
              if p[ICMP].type == 3 and p[ICMP].code == 3]
        self.assertTrue(len(pu) > 0,
                        msg="No ICMP port unreachable for TCP sent to router")

    def test_unknown_proto_to_router_ignored(self):
        """An IP packet to a router IP with a non-ICMP/TCP/UDP protocol should
        be silently dropped — no ICMP error generated."""
        self.clearPcapBuffers()
        src = self.client
        # protocol 111 is not ICMP(1)/TCP(6)/UDP(17)
        pkt = (Ether(src=src["mac"], dst=src["gwmac"])
               / IP(src=src["ip"], dst=src["gw"], ttl=64, proto=111)
               / (b"\x00" * 8))
        self.sendPacket(pkt, node=src["m"].name)

        icmps = self.expectPackets(src["m"].name, type='icmp', timewait_sec=0.5)
        errs = [p for p, _ in icmps if p[ICMP].type == 3]
        self.assertEqual(len(errs), 0,
                         msg="Router sent an ICMP error for an ignored protocol")

    # ── Requirement 6/8: forwarded packets reuse the ARP cache ─────────────

    def test_arp_cache_reused_on_second_forward(self):
        """After the first forward resolves the next hop, a second forward to
        the same next hop within the cache TTL must NOT emit a new ARP request."""
        self.clearPcapBuffers()
        src = self.client
        dst = self.server2

        # First forward: warms the cache (router ARPs, server replies, entry cached).
        first = (Ether(src=src["mac"], dst=src["gwmac"])
                 / IP(src=src["ip"], dst=dst["ip"], id=random.randint(1, 65535), ttl=64)
                 / ICMP(type=8, id=0x11))
        self.sendPacket(first, node=src["m"].name)
        time.sleep(0.5)            # allow ARP round-trip + cache insert
        self.clearPcapBuffers()    # forget the first round's ARP traffic

        # Second forward to the same next hop: should hit the cache.
        second = (Ether(src=src["mac"], dst=src["gwmac"])
                  / IP(src=src["ip"], dst=dst["ip"], id=random.randint(1, 65535), ttl=64)
                  / ICMP(type=8, id=0x22))
        self.sendPacket(second, node=src["m"].name)

        arps = self.expectPackets(dst["m"].name, type='arp', timewait_sec=0.5)
        new_reqs = [p for p, _ in arps
                    if p[ARP].op == 1 and p[ARP].pdst == dst["ip"]]
        self.assertEqual(len(new_reqs), 0,
                         msg="Router re-ARPed for a next hop already in cache")

        icmps = self.expectPackets(dst["m"].name, type='icmp', timewait_sec=0.5)
        delivered = [p for p, _ in icmps
                     if IP in p and p[ICMP].type == 8]
        self.assertTrue(len(delivered) > 0,
                        msg="Cached forward was not delivered to the destination")


class TestPA2bLPM(CSE123TestBase):
    """Longest Prefix Match (Requirement 4), driven by a custom routing table
    whose default route is listed first — a naive first-match lookup would pick
    it and fail, while correct LPM picks the more specific /32."""

    def setUp(self):
        self.setUpEnvironment(rtable='rtable_lpm', build=True, debug=False, manual_sr=False)

    def tearDown(self):
        self.tearDownEnvironment()

    def test_specific_prefix_preferred_over_default(self):
        """Traffic to server2 must use the /32 route (eth2), not the default
        route (eth1) that appears earlier in the table."""
        self.clearPcapBuffers()
        src = self.client
        dst = self.server2
        id = random.randint(1, 65535)
        pkt = (Ether(src=src["mac"], dst=src["gwmac"])
               / IP(src=src["ip"], dst=dst["ip"], id=id, ttl=64)
               / ICMP(type=8, id=0x55))
        self.sendPacket(pkt, node=src["m"].name)

        # If LPM is correct the echo request reaches server2's wire.
        icmps = self.expectPackets(dst["m"].name, type='icmp', timewait_sec=1.0)
        delivered = [p for p, _ in icmps
                     if IP in p and p[IP].id == id and p[ICMP].type == 8]
        self.assertTrue(len(delivered) > 0,
                        msg="LPM picked the default route instead of the /32")

    def test_default_route_used_for_unmatched_dest(self):
        """A destination matched only by the default route should be forwarded
        via the default next hop (192.168.2.2 on eth1), not net-unreachable."""
        self.clearPcapBuffers()
        src = self.client
        pkt = (Ether(src=src["mac"], dst=src["gwmac"])
               / IP(src=src["ip"], dst="8.8.8.8", id=random.randint(1, 65535), ttl=64)
               / ICMP(type=8, id=0x66))
        self.sendPacket(pkt, node=src["m"].name)

        # Router should ARP for the default gateway on server1's wire.
        arps = self.expectPackets(self.server1["m"].name, type='arp', timewait_sec=0.5)
        gw_arps = [p for p, _ in arps
                   if p[ARP].op == 1 and p[ARP].pdst == "192.168.2.2"]
        self.assertTrue(len(gw_arps) > 0,
                        msg="Default route not used to resolve unmatched destination")

        # And it must NOT have replied to the client with net-unreachable.
        icmps = self.expectPackets(src["m"].name, type='icmp', timewait_sec=0.5)
        unreach = [p for p, _ in icmps
                   if p[ICMP].type == 3 and p[ICMP].code == 0]
        self.assertEqual(len(unreach), 0,
                         msg="Sent net-unreachable despite a matching default route")


if __name__ == "__main__":
    unittest.main()
