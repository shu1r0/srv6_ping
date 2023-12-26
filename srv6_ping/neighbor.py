from scapy.all import in6_getifaddr
from scapy.config import conf
from scapy.layers.inet6 import neighsol, ICMPv6NDOptDstLLAddr, ICMPv6ND_NA


def neighsol_and_chache(addr, iface):
    src = [ifaddr[0] for ifaddr in in6_getifaddr() if ifaddr[2] == iface][0]
    if conf.netcache.in6_neighbor.get(addr) is None:
        sol = neighsol(addr, src, iface, chainCC=True)
        if ICMPv6ND_NA in sol:
            taddr = sol[ICMPv6NDOptDstLLAddr].lladdr
            conf.netcache.in6_neighbor[addr] = taddr
