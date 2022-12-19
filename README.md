# SRv6 Ping
This SRv6Ping send ICMP messages containing the SID lists.
Currently, `sr1()` of `scapy` is used to send and receive ICMP.

## Usage
```bash
python srv6_ping -d fd00:2::1 -s fd00:a::2,fd00:d::2
```

## Examples
Ping reaching `fd00:2::1` via `fd00:a::2` and `fd00:d::2`.
```bash
python srv6_ping -d fd00:2::1 -s fd00:a::2,fd00:d::2
```

