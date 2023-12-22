import time
import json
import random
from typing import List, Optional

from scapy.all import Packet, IPv6, ICMPv6EchoRequest, IPv6ExtHdrSegmentRouting, IPv6ExtHdrSegmentRoutingTLV, ICMPv6EchoReply, UDP, Raw, sr1, RandString, RandNum, debug
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6DestUnreach, ICMPv6PacketTooBig, ICMPv6TimeExceeded, ICMPv6ParamProblem

import srv6_ping


def ping_and_show(timeout=3, max_count=-1, iface=None, json_format=False, pkt_params=None):
    pkt_params = pkt_params if pkt_params else dict()
    verbose = 1 if srv6_ping.verbose else 0
    try:
        count = 1
        icmp_id = random.randint(0x0000, 0xffff)
        while (max_count < 0) or (count <= max_count):
            result = ping1(timeout=timeout, verbose=verbose, return_pkt=False, iface=iface, icmp_id=icmp_id, icmp_seq=count, **pkt_params)
            if result:
                if json_format:
                    result_format = {"result": result}
                    print(json.dumps(result_format))
                else:
                    print("%s: code=%d from=%s hlim=%d rtt=%f" % \
                          (result["msg"], result["code"], result["recv_from"], result["hlim"], result["rtt"]))
            else:
                if json_format:
                    result_format = {"result": "timeout"}
                    print(json.dumps(result_format))
                else:
                    print("timeout.")
            count += 1
            time.sleep(1)
    except KeyboardInterrupt:
        if not json_format:
            print("end.")


def traceroute_and_show(dst: str, segs: List[str] = None, timeout=2, max_count=30, srh_tlvs: List[IPv6ExtHdrSegmentRoutingTLV] = None, json_format=False, protocol="udp"):
    try:
        count=1
        before_src = ""
        while (count <= max_count):
            packet = new_probe_packet(dst, segs, hlim=count, protocol=protocol)
            
            if srh_tlvs and IPv6ExtHdrSegmentRouting in packet:
                for tlv in srh_tlvs:
                    packet[IPv6ExtHdrSegmentRouting].tlv_objects.append(tlv)
            
            result = _ping1(packet, timeout, verbose=0, return_pkt=False)
            if result:
                if json_format:
                    result_format = {"count": count, "result": result}
                    print(json.dumps(result_format))
                else:
                    print("%d: from=%s rtt=%f" % \
                          (count, result["recv_from"], result["rtt"]))
                
                if dst == packet[IPv6].src or before_src == packet[IPv6].src:
                    break
                before_src = packet[IPv6].src
            else:
                if json_format:
                    result_format = {"count": count, "result": "timeout"}
                    print(json.dumps(result_format))
                else:
                    print("%d: *" % (count))
            count += 1
            time.sleep(1)
    except KeyboardInterrupt:
        if not json_format:
            print("end.")


def ping1(timeout=3, verbose=0, srh_tlvs: List[IPv6ExtHdrSegmentRoutingTLV] = None, return_pkt=False, iface=None, **pkt_param) -> Optional[dict]:
    packet = new_probe_packet(**pkt_param)
    if srh_tlvs:
        if IPv6ExtHdrSegmentRouting in packet:
            for tlv in srh_tlvs:
                packet[IPv6ExtHdrSegmentRouting].tlv_objects.append(tlv)
        else:
            raise ValueError()
    return _ping1(packet, timeout, verbose, return_pkt=return_pkt, iface=iface)


def _ping1(packet: Packet, timeout: int, verbose: int, return_pkt: bool, iface: str = None) -> Optional[dict]:
    if verbose:
        print("Send pkt: " + packet.__repr__())
    start = time.time()
    rep = sr1(packet, iface=iface, timeout=timeout, verbose=verbose, chainCC=True)
    if rep:
        end = time.time()
        result = {}
        result["hlim"] = rep[IPv6].hlim
        result["recv_from"] = rep[IPv6].src
        result["rtt"] = (end - start)*1000
        
        if return_pkt:
            result["sent_pkt"] = packet
            result["recv_pkt"] = rep

        code = -1
        msg = "UNKOWN"
        if ICMPv6EchoReply in rep:
            code = rep[ICMPv6EchoReply].code
            result["id"] = rep[ICMPv6EchoReply].id
            result["seq"] = rep[ICMPv6EchoReply].seq
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


def new_probe_packet(dst: str, segs: List[str] = None, hlim=64, including_srh=True, protocol="icmp", data_len=32, oam=True, src=None, icmp_id=0, icmp_seq=1) -> Packet:
    packet = None

    payload = None
    if protocol == "icmp":
        payload = ICMPv6EchoRequest(id=icmp_id, seq=icmp_seq, data=RandString(data_len))
    elif protocol == "udp":
        payload = UDP(dport=int(RandNum(33434, 33534)))/Raw(load=RandString(data_len))
    else:
        raise ValueError()

    # SRH
    if segs and len(segs) > 0 and segs[0] != "":
        s = segs[::-1]
        s.insert(0, dst)
        packet = IPv6(dst=s[-1], hlim=hlim)/IPv6ExtHdrSegmentRouting(addresses=s)/payload
    else:
        if including_srh:
            packet = IPv6(dst=dst, hlim=hlim)/IPv6ExtHdrSegmentRouting(addresses=[dst])/payload
        else:
            packet = IPv6(dst=dst, hlim=hlim)/payload

    if oam and IPv6ExtHdrSegmentRouting in packet:
        packet[IPv6ExtHdrSegmentRouting].oam = 1

    if src:
        packet[IPv6].src = src

    return packet


def new_srh_tlv(type, value) -> IPv6ExtHdrSegmentRoutingTLV:
    length = len(value)
    return IPv6ExtHdrSegmentRoutingTLV(type=type, len=length, value=value)
