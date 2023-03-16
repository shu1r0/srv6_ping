# SRv6 Ping

## Installation
```bash
$ sudo ./install.sh
$ which srv6ping
/usr/local/bin/srv6ping
```

## Usage
```bash
$ srv6ping -h                                                                                                                                                                                                       12:38:25
usage: srv6ping [-h] [-c COUNT] [-d DESTINATION] [-s SEGS] [-t TIMEOUT] [-j] [-f CONF_FILE] [--hlim HLIM]

optional arguments:
  -h, --help            show this help message and exit
  -c COUNT, --count COUNT
                        ping count
  -d DESTINATION, --destination DESTINATION
                        destination
  -s SEGS, --segs SEGS  segment_list. (e.g. fd0a::,fd0b::,fd0c::)
  -t TIMEOUT, --timeout TIMEOUT
                        timeout
  -j, --json_format
  -f CONF_FILE, --conf_file CONF_FILE
                        config file
  --hlim HLIM           IPv6 hop limit
```

## Examples
Ping reaching `fd00:2::1` via `2001:db8:10::2` and `2001:db8:20::2`.

```bash
$ sudo srv6ping -d 2001:db8:30::2 -s 2001:db8:10::2,2001:db8:20::2 -c 3
EchoReply: code=0 from=2001:db8:30::2 hlim=62 rtt=108.961582
EchoReply: code=0 from=2001:db8:30::2 hlim=62 rtt=45.726061
EchoReply: code=0 from=2001:db8:30::2 hlim=62 rtt=58.127642
```

use config file.
```bash
$ sudo srv6ping -f examples/test1_linear.yaml
EchoReply: code=0 from=2001:db8:10::2 hlim=64 rtt=67.047596
{"result": {"hlim": 62, "rep_src": "2001:db8:30::2", "rtt": 46.15139961242676, "code": 0, "msg": "EchoReply"}}
{"result": {"hlim": 62, "rep_src": "2001:db8:30::2", "rtt": 30.368566513061523, "code": 0, "msg": "EchoReply"}}
{"result": {"hlim": 62, "rep_src": "2001:db8:30::2", "rtt": 30.353546142578125, "code": 0, "msg": "EchoReply"}}
```


## SRv6 traceroute

**The `srv6traceroute` is in progress.**

```bash
$ srv6traceroute -h
usage: srv6traceroute [-h] [-c COUNT] [-d DESTINATION] [-s SEGS] [-t TIMEOUT] [-j] [-f CONF_FILE] [-p {icmp,udp}]

options:
  -h, --help            show this help message and exit
  -c COUNT, --count COUNT
                        ping count
  -d DESTINATION, --destination DESTINATION
                        destination
  -s SEGS, --segs SEGS  segment_list. (e.g. fd0a::,fd0b::,fd0c::)
  -t TIMEOUT, --timeout TIMEOUT
                        timeout
  -j, --json_format
  -f CONF_FILE, --conf_file CONF_FILE
                        config file
  -p {icmp,udp}, --protocol {icmp,udp}
                        probe packet protocol
```
