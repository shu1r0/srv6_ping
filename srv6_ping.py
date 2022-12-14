import argparse
from srv6_ping.ping import ping_and_show


def get_args(description=None):
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument('-d', '--destination', help="destination")
    parser.add_argument('-s', '--segs', default="", help="segment_list. eg.) fd0a::,fd0b::,fd0c::")
    parser.add_argument('-t', '--timeout', default=3, help="timeout")

    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = get_args()
    ping_and_show(args.destination, args.segs.split(","), timeout=args.timeout)
