# SRv6 Ping

## Installation
```bash
$ sudo ./install.sh
$ which srv6ping
/usr/local/bin/srv6ping
```

## Usage
```bash
$ srv6ping -h
usage: srv6ping [-h] [-c COUNT] -d DESTINATION [-s SEGS] [-t TIMEOUT] [-j]

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
```

## Examples
Ping reaching `fd00:2::1` via `2001:db8:10::2` and `2001:db8:20::2`.

```bash
$ sudo srv6ping -d 2001:db8:30::2 -s 2001:db8:10::2,2001:db8:20::2 -c 3
EchoReply: code=0 from=2001:db8:30::2 hlim=62 rtt=108.961582
EchoReply: code=0 from=2001:db8:30::2 hlim=62 rtt=45.726061
EchoReply: code=0 from=2001:db8:30::2 hlim=62 rtt=58.127642
```

