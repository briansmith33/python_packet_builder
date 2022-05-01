from utils import checksum
from constants import *
import socket
import struct
import random


class TCP:

    def __init__(self, src_port, dst_port, flags=None, payload=None, doff=None, acknum=None):
        self.src_ip = None
        self.dst_ip = None
        self.src_port = src_port
        self.dst_port = dst_port
        self.doff = doff
        self.acknum = acknum
        if flags is None:
            self.flags = ["syn"]
        else:
            self.flags = flags

        if payload is None:
            self.payload = b""
        else:
            self.payload = payload

    def get_pseudo_header_chksum(self, length):
        src_addr = socket.inet_aton(self.src_ip)
        dst_addr = socket.inet_aton(self.dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, length)
        psh = psh + self.build_header()
        return checksum(psh)

    def build_header(self, chksum=0):
        seq = random.randrange(1, GB)
        if self.acknum is None:
            ack_seq = random.randrange(1, GB)
        else:
            ack_seq = self.acknum
        fin = int("fin" in self.flags)
        syn = int("syn" in self.flags)
        rst = int("rst" in self.flags)
        psh = int("psh" in self.flags)
        ack = int("ack" in self.flags)
        urg = int("urg" in self.flags)
        if self.doff is None:
            data_offset = 0x5
        else:
            data_offset = self.doff
        window = socket.htons(0x16d0)
        # window = random.randrange(1, GB)
        urg_ptr = 0x0
        offset_res = (data_offset << 4) + 0
        tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
        return struct.pack('!HHLLBBHHH',
                           self.src_port,
                           self.dst_port,
                           seq,
                           ack_seq,
                           offset_res,
                           tcp_flags,
                           window,
                           chksum,
                           urg_ptr)

    def get_tcp_header(self):
        header_nochksum = self.build_header()
        length = len(header_nochksum)
        return self.build_header(self.get_pseudo_header_chksum(length)) + self.payload