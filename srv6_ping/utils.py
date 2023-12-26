from scapy.all import Packet, IPv6, IPv6ExtHdrSegmentRouting, IPv6ExtHdrSegmentRoutingTLV


def new_srh_tlv(type, value) -> IPv6ExtHdrSegmentRoutingTLV:
    length = len(value)
    return IPv6ExtHdrSegmentRoutingTLV(type=type, len=length, value=value)


def get_dst(pkt: Packet) -> str:
    dst = pkt[IPv6].dst
    if IPv6ExtHdrSegmentRouting in pkt:
        dst = pkt[IPv6ExtHdrSegmentRouting].addresses[0]
    return dst


def parse_pktparam_from_conf(dst_d: dict) -> dict:
    srh_tlvs = []
    for tlv in dst_d.get("srh_tlvs", []):
        srh_tlvs.append(new_srh_tlv(type=tlv["type"], value=tlv["value"]))
    
    pkt_params = {
        "src": dst_d.get("source"),
        "dst": dst_d["destination"],
        "segs": dst_d.get("segs"),
        "srh_tlvs": srh_tlvs,
    }
    if "hlim" in dst_d.keys():
        pkt_params["hlim"] = dst_d["hlim"]
    if "including_srh" in dst_d.keys():
        pkt_params["including_srh"] = dst_d["including_srh"]
    if "oam" in dst_d.keys():
        pkt_params["oam"] = dst_d["oam"]
    if "icmp_id" in dst_d.keys():
        pkt_params["icmp_id"] = dst_d["icmp_id"]
    if "protocol" in dst_d.keys():
        pkt_params["protocol"] = dst_d["protocol"]
    
    return pkt_params
