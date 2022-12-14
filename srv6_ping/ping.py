import time
from typing import List, Optional

from scapy.all import IPv6, ICMPv6EchoRequest, IPv6ExtHdrSegmentRouting, ICMPv6EchoReply, sr1


def ping_and_show(dst: str, segs: List[str] = None, timeout: int = 1):
    try:
        while True:
            result = ping1(dst, segs, timeout)
            if result:
                print(result)
    except KeyboardInterrupt:
        print("end.")


def ping1(dst: str, segs: List[str] = None, timeout: int = 1) -> Optional[dict]:
    packet = get_icmp_packet(dst, segs)
    start = time.time()
    rep = sr1(packet, timeout=timeout)
    if rep:
        end = time.time()
        result = {}
        result["hlim"] = rep[IPv6].hlim
        result["rep_src"] = rep[IPv6].src
        result["rtt"] = end - start
        return result
    else:
        return None


def get_icmp_packet(dst: str, segs: List[str] = None):
    if segs:
        return IPv6(dst=dst)/IPv6ExtHdrSegmentRouting(addresses=segs)/ICMPv6EchoRequest(data="x"*32)
    else:
        return IPv6(dst=dst)/ICMPv6EchoRequest(data="x"*32)

