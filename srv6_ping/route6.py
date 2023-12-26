from scapy.config import conf
from scapy.utils6 import in6_ptop, in6_isincluded

from srv6_ping.neighbor import neighsol_and_chache


def parse_addr6(addr: str) -> str:
    addr = ":".join([addr[i:i+4] for i in range(0, len(addr), 4)])
    return in6_ptop(addr)


def add_target_routes6(dst: str, src="::"):
    with open("/proc/net/ipv6_route", "r") as f:
        line = f.readline()
        while line:
            line = line.strip().split()
            d, nh, dev = line[0], line[4], line[9]
            prefix = int(line[1], 16)
            metric = int(line[5], 16)
            d = parse_addr6(d)
            nh = parse_addr6(nh)
            if d != "::" and in6_isincluded(dst, d, prefix):
                if (d, prefix) not in [(r[0], r[1]) for r in conf.route6.routes]:
                    r = list(conf.route6.make_route(dst="%s/%d" % (d, prefix), gw=nh, dev=dev))
                    r[4].append(src)  # Todo: lookup source address
                    r[5] = metric
                    conf.route6.routes.append(tuple(r))
                    if nh != "::":
                        neighsol_and_chache(nh, r[2], dev)
            line = f.readline()