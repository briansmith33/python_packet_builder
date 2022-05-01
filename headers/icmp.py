from utils import checksum
import struct
import os


class ICMP:

    def __init__(self, tos=8):
        self.tos = tos

    def build_header(self, chksum=0):
        code = 0
        identifier = os.getpid() & 0xFFFF
        seq = 1
        return struct.pack('!BBHHH',
                           self.tos,
                           code,
                           chksum,
                           identifier,
                           seq)

    def get_icmp_header(self):
        return self.build_header(checksum(self.build_header()))
