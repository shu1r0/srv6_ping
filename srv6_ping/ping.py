import time
from typing import List, Optional

from scapy.all import IPv6, ICMPv6EchoRequest, IPv6ExtHdrSegmentRouting, ICMPv6EchoReply, sr1, sr
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6DestUnreach, ICMPv6PacketTooBig, ICMPv6TimeExceeded, ICMPv6ParamProblem


def ping_and_show(dst: str, segs: List[str] = None, timeout: int = 3):
    try:
        while True:
            result = ping1(dst, segs, timeout)
            if result:
                print("%s code=%d from=%s hlim=%d rtt=%f" % \
                      (result["msg"], result["code"], result["rep_src"], result["hlim"], result["rtt"]))
            else:
                print("Timeout.")
            time.sleep(1)
    except KeyboardInterrupt:
        print("")


def ping1(dst: str, segs: List[str] = None, timeout: int = 3, verbose=1) -> Optional[dict]:
    packet = get_icmp_packet(dst, segs)
    start = time.time()
    rep = sr1(packet, timeout=timeout, verbose=verbose)
    if rep:
        end = time.time()
        result = {}
        result["hlim"] = rep[IPv6].hlim
        result["rep_src"] = rep[IPv6].src
        result["rtt"] = (end - start)*1000

        code = -1
        msg = "UNKOWN MESSAGE"
        if ICMPv6EchoReply in rep:
            code = rep[ICMPv6EchoReply].code
            msg = "EchoReply"
        elif ICMPv6DestUnreach in rep:
            code = rep[ICMPv6DestUnreach].code
            msg = "DestUnreach"
        elif ICMPv6PacketTooBig in rep:
            code = rep[ICMPv6PacketTooBig].code
            msg = "PacketTooBig"
        elif ICMPv6TimeExceeded in rep:
            code = rep[ICMPv6TimeExceeded].code
            msg = "TimeExceeded"
        elif ICMPv6ParamProblem in rep:
            code = rep[ICMPv6ParamProblem].code
            msg = "ParamProblem"
        result["code"] = code
        result["msg"] = msg

        return result
    else:
        return None


def get_icmp_packet(dst: str, segs: List[str] = None):
    if segs and len(segs) > 0 and segs[0] != "":
        s = segs[::-1]
        s.insert(0, dst)
        return IPv6(dst=s[-1])/IPv6ExtHdrSegmentRouting(addresses=s)/ICMPv6EchoRequest(data="x"*32)
    else:
        return IPv6(dst=dst)/ICMPv6EchoRequest(data="x"*32)

