from unittest import TestCase, main
from scapy.all import *
from json import dumps


from srv6_ping.ping import ping1, new_srh_tlv


class TestSRv6Ping(TestCase):

    def test_ping_destination_srh(self):
        results = []
        for _ in range(3):
            result = ping1(dst="2001:db8:10::2", including_srh=True, return_pkt=True)
            if result:
                results.append(result)
        
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            result1 = results[0]
            self.assertEqual("EchoReply", result1["msg"])
            # check return_pkt
            self.assertTrue(result1["sent_pkt"][IPv6].src == result1["recv_pkt"][IPv6].dst)
    
    def test_srv6_ping(self):
        results = []
        for _ in range(3):
            result = ping1(dst="2001:db8:30::2", segs=["2001:db8:10::2", "2001:db8:20::2"])
            if result:
                results.append(result)
        
        # echo reply
        self.assertTrue(len(results) > 0)
        if len(results) > 0:
            self.assertEqual("EchoReply", results[0]["msg"])
            
        # time exceeded
        result = ping1(dst="2001:db8:30::2", segs=["2001:db8:10::2", "2001:db8:20::2"], hlim=1)
        self.assertEqual("TimeExceeded", result["msg"])

        # test tlv
        tlv = new_srh_tlv(type=124, value='\x00\x18\x00\x00\x00\x08')
        result = ping1(dst="2001:db8:30::2", segs=["2001:db8:10::2", "2001:db8:20::2"], srh_tlvs=[tlv])
        self.assertEqual("EchoReply", result["msg"])
