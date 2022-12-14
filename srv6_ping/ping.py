import time
from typing import List, Optional

from scapy.all import IPv6, ICMPv6EchoRequest, IPv6ExtHdrSegmentRouting, ICMPv6EchoReply, sr1
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6DestUnreach, ICMPv6PacketTooBig, ICMPv6TimeExceeded, ICMPv6ParamProblem


def ping_and_show(dst: str, segs: List[str] = None, timeout: int = 1):
    try:
        while True:
            result = ping1(dst, segs, timeout)
            if result:
                print("%s code=%d from=%s hlim=%d rtt=%d" % \
                      (result["msg"], result["code"], result["rep_src"], result["hlim"], result["rtt"]))
            time.sleep(1)
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

        code = -1
        msg = "UNKOWN MESSAGE"
        if ICMPv6EchoReply in rep:
            code = rep[ICMPv6EchoReply].code
            msg = "ICMPv6EchoReply"
        elif ICMPv6DestUnreach in rep:
            code = rep[ICMPv6DestUnreach].code
            msg = "ICMPv6DestUnreach"
        elif ICMPv6PacketTooBig in rep:
            code = rep[ICMPv6PacketTooBig].code
            msg = "ICMPv6PacketTooBig"
        elif ICMPv6TimeExceeded in rep:
            code = rep[ICMPv6TimeExceeded].code
            msg = "ICMPv6TimeExceeded"
        elif ICMPv6ParamProblem in rep:
            code = rep[ICMPv6ParamProblem].code
            msg = "ICMPv6ParamProblem"
        result["code"] = code
        result["msg"] = msg

        return result
    else:
        return None


def get_icmp_packet(dst: str, segs: List[str] = None):
    if segs and len(segs) > 0:
        return IPv6(dst=dst)/IPv6ExtHdrSegmentRouting(addresses=segs)/ICMPv6EchoRequest(data="x"*32)
    else:
        return IPv6(dst=dst)/ICMPv6EchoRequest(data="x"*32)

