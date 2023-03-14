"""This is a patch to scapy.


This file uses Scapy which has GPLv2 License.
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see http://www.gnu.org/licenses/.
"""
import os

from scapy.all import ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.sendrecv import AsyncSniffer, SndRcvHandler, debug, QueryAnswer
from scapy.config import conf

# conf.use_pcap = True
# conf.debug_match = True


def get_icmpv6_echo(pkt):
    if ICMPv6EchoReply in pkt:
        return pkt[ICMPv6EchoReply]
    if ICMPv6EchoRequest in pkt:
        return pkt[ICMPv6EchoRequest]


def compare_echorep_payload(pkt1, pkt2):
    icmp1 = get_icmpv6_echo(pkt1)
    icmp2 = get_icmpv6_echo(pkt2)
    if icmp1 is not None and icmp2 is not None:
        return icmp1.type != icmp2.type and icmp1.payload == icmp2.payload
    return False


def _new_process_packet(self, r):
    """This method forked from scapy: https://github.com/secdev/scapy/blob/master/scapy/sendrecv.py
    # For licensing information pertaining to this method, see the comments at the top of this file.
    """
    if r is None:
        return
    ok = False

    for hlst in self.hsent.values():
        for i, sentpkt in enumerate(hlst):
            if r.answers(sentpkt) or compare_echorep_payload(r, sentpkt):
                self.ans.append(QueryAnswer(sentpkt, r))
                if self.verbose > 1:
                    os.write(1, b"*")
                ok = True
                if not self.multi:
                    del hlst[i]
                    self.notans -= 1
                else:
                    if not hasattr(sentpkt, '_answered'):
                        self.notans -= 1
                    sentpkt._answered = 1
                break
    if self.notans <= 0 and not self.multi:
        if self.sniffer:
            self.sniffer.stop(join=False)
    if not ok:
        if self.verbose > 1:
            os.write(1, b".")
        self.nbrecv += 1
        if conf.debug_match:
            debug.recv.append(r)


def _sndrcv_rcv(self, callback):
    """This method forked from scapy: https://github.com/secdev/scapy/blob/master/scapy/sendrecv.py
    # For licensing information pertaining to this method, see the comments at the top of this file.
    """
    self.sniffer = None
    try:
        self.sniffer = AsyncSniffer()
        self.sniffer._run(
            prn=self._new_process_packet,
            timeout=self.timeout,
            store=False,
            opened_socket=self.rcv_pks,
            session=self.session,
            started_callback=callback
        )
    except KeyboardInterrupt:
        if self.chainCC:
            raise


setattr(SndRcvHandler, "_new_process_packet", _new_process_packet)
SndRcvHandler._sndrcv_rcv = _sndrcv_rcv
