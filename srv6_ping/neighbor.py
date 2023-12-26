from scapy.config import conf
from scapy.layers.inet6 import neighsol, ICMPv6NDOptDstLLAddr, ICMPv6ND_NA


def neighsol_and_chache(addr, src, iface):
    if conf.netcache.in6_neighbor.get(addr) is None:
        sol = neighsol(addr, src, iface, chainCC=True)
        if ICMPv6ND_NA in sol:
            taddr = sol[ICMPv6NDOptDstLLAddr].lladdr
            conf.netcache.in6_neighbor[addr] = taddr
