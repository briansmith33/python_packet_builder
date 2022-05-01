from utils import checksum
from constants import *
import struct
import socket


class UDP:

    def __init__(self, src_port, dst_port, payload=None):
        self.src_ip = None
        self.dst_ip = None
        self.src_port = src_port
        self.dst_port = dst_port
        if payload is None:
            self.payload = b" \r\n\r\n"
        else:
            self.payload = payload

    def get_pseudo_header_chksum(self, length):
        src_addr = socket.inet_aton(self.src_ip)
        dst_addr = socket.inet_aton(self.dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_UDP
        psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, length)
        psh = psh + self.build_header()
        return checksum(psh)

    def build_header(self, chksum=0):
        length = UDP_HL + len(self.payload)
        return struct.pack('!HHHH',
                           self.src_port,
                           self.dst_port,
                           length,
                           chksum)

    def get_udp_header(self):
        header_nochksum = self.build_header()
        length = len(header_nochksum)
        return self.build_header(self.get_pseudo_header_chksum(length)) + self.payload