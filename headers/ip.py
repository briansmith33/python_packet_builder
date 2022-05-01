from headers.http import HTTP
from headers.icmp import ICMP
from headers.tcp import TCP
from headers.udp import UDP
from constants import *
import struct
import socket
import random
import re
import os


class IP:

    def __init__(self, src_ip="127.0.0.1", dst_ip="127.0.0.1", flags=None, ttl=64, spoof=False):
        if spoof:
            self.src_ip = self.random_public_ipv4()
        else:
            self.src_ip = src_ip

        self.dst_ip = dst_ip
        if not self.version(src_ip) == self.version(dst_ip):
            raise Exception("IP versions don't match")
        self.ip_version = self.version(src_ip)
        if flags is None:
            flags = ["df"]
        r_flag = int("evil" in flags)
        df_flag = int("df" in flags)
        mf_flag = int("mf" in flags)

        self.flags = self.get_flags(r_flag, df_flag, mf_flag)
        self.ttl = ttl
        self.proto = None

    def __bytes__(self):
        return self.get_ip_header()

    def __truediv__(self, other):
        if isinstance(other, TCP):
            self.proto = socket.IPPROTO_TCP
            other.src_ip = self.src_ip
            other.dst_ip = self.dst_ip
            return self.src_ip, self.dst_ip, other.src_port, other.dst_port, self.proto, self.get_ip_header() + other.get_tcp_header()

        if isinstance(other, UDP):
            self.proto = socket.IPPROTO_UDP
            other.src_ip = self.src_ip
            other.dst_ip = self.dst_ip
            return self.get_ip_header() + other.get_udp_header()

        if isinstance(other, ICMP):
            self.proto = socket.IPPROTO_ICMP
            self.ttl = 0x40
            return self.get_ip_header() + other.get_icmp_header()

        if isinstance(other, HTTP):
            self.proto = socket.IPPROTO_TCP
            return self.get_ip_header() + other.get_http_header()

    @staticmethod
    def version(ip):
        ipv4_regex = r'''^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'''
        if re.match(ipv4_regex, ip) is not None:
            return 4
        ipv6_regex = r'''^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|
            ^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|
            ^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|
            ^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|
            ^(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|
            ^(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|
            ^(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)?[0-9a-fA-F]{1,4}$|
            ^(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$|
            ^(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}::$'''
        if re.match(ipv6_regex, ip) is not None:
            return 6

    @staticmethod
    def is_private_ip(ip):
        oct1 = int(ip.split(".")[0])
        oct2 = int(ip.split(".")[1])
        if oct1 == 0:
            return True
        if oct1 == 10:
            return True
        if oct1 == 100:
            if 64 <= oct2 <= 127:
                return True
        if oct1 == 127:
            return True
        if oct1 == 169:
            if oct2 == 254:
                return True
        if oct1 == 172:
            if 16 <= oct2 <= 31:
                return True
        if oct1 == 192:
            if oct2 == 168:
                return True
        if oct1 == 198:
            if oct2 == 18 or oct2 == 19:
                return True
        if oct1 == 255:
            return True

        return False

    def random_public_ipv4(self):
        octet1 = random.SystemRandom().randint(128, 173)
        octet2 = random.SystemRandom().randint(0, 266)
        octet3 = random.SystemRandom().randint(0, 266)
        octet4 = random.SystemRandom().randint(0, 266)
        ip = f"{octet1}.{octet2}.{octet3}.{octet4}"

        if self.is_private_ip(ip) or not self.version(ip) == 4:
            return self.random_public_ipv4()
        return ip

    @staticmethod
    def get_flags(r_flag, df_flag, mf_flag):
        r_flag <<= 15
        r_flag = ~(0x8000 & r_flag) + 0x1

        df_flag <<= 14
        df_flag = ~(0x4000 & df_flag) + 0x1

        mf_flag <<= 13
        mf_flag = ~(0x2000 & mf_flag) + 0x1

        return -(r_flag + df_flag + mf_flag)

    def get_ip_header(self, payload_size=0):
        ihl = 0x5
        ihl_ver = (self.ip_version << 4) + ihl
        dscp = 0x0
        ip_header_length = 0
        if self.ip_version == 4:
            ip_header_length = IPV4_HL
        if self.ip_version == 6:
            ip_header_length = IPV6_HL

        proto_header_length = 0
        if self.proto == socket.IPPROTO_TCP:
            proto_header_length = TCP_HL
        if self.proto == socket.IPPROTO_UDP:
            proto_header_length = UDP_HL
        length = ip_header_length + proto_header_length + payload_size

        identifier = os.getpid() & 0xFFFF
        offset = self.flags & 0x1FFF
        chksum = 0x0
        src_ip = socket.inet_aton(self.src_ip)
        dst_ip = socket.inet_aton(self.dst_ip)

        return struct.pack('!BBHHHBBH4s4s',
                           ihl_ver,
                           dscp,
                           length,
                           identifier,
                           self.flags,
                           self.ttl,
                           self.proto,
                           chksum,
                           src_ip,
                           dst_ip)
