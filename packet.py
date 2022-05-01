from constants import *
import socket
import struct
import re


class Packet:

    def __init__(self, data):
        self.src = data[0]
        self.dst = data[1]
        self.sport = data[2]
        self.dport = data[3]
        self.proto = data[4]
        self.data = data[5]

    @staticmethod
    def get_tos(data):
        d = data & 0x10
        d >>= 4

        t = data & 0x8
        t >>= 3

        r = data & 0x4
        r >>= 2

        m = data & 0x2
        m >>= 1

        tabs = "\n\t\t\t\t\t\t\t"
        return PRECEDENCE[data >> 5] + tabs + DELAY[d] + tabs + THROUGHPUT[t] + tabs + RELIABILITY[r] + tabs + COST[m]

    @staticmethod
    def get_ip_flags(data):
        r = data & 0x8000
        r >>= 15

        df = data & 0x4000
        df >>= 14

        mf = data & 0x2000
        mf >>= 13

        tabs = "\n\t\t\t\t\t\t\t"
        return tabs + FLAG_R[r] + tabs + FLAG_DF[df] + tabs + FLAG_MF[mf]

    @staticmethod
    def get_protocol(proto_num):
        with open("data/protocols.txt", "r") as f:
            protocol_data = f.read()
        protocol = re.findall(r"\n" + str(proto_num) + r" (?:.)+\n", protocol_data)
        if protocol:
            protocol = protocol[0]
            protocol = protocol.replace("\n", "")
            protocol = protocol.replace(str(proto_num), "")
            protocol = protocol.strip()
            return protocol
        else:
            print("No such protocol found!")

    @staticmethod
    def get_tcp_flags(value):
        flags = ["syn", "rst", "psh", "ack", "urg"]
        flagged = []
        for i in range(-5, 0):
            if value >> -i == 1:
                flagged.append(flags[(-i) - 1])
                value -= (1 << -i)
        flagged.reverse()
        if value > 0:
            flagged.append("fin")
        return flagged

    def unpacket(self, data):
        unpacked_data = struct.unpack("!BBHHHBBH4s4s", data[:IPV4_HL])
        version_ihl = unpacked_data[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xf
        tos_val = unpacked_data[1]
        total_length = unpacked_data[2]
        id_num = unpacked_data[3]
        flags = unpacked_data[4]
        fragment_offset = unpacked_data[4] & 0x1FFF
        ttl = unpacked_data[5]
        proto_num = unpacked_data[6]
        checksum = unpacked_data[7]
        source_address = socket.inet_ntoa(unpacked_data[8])
        destination_address = socket.inet_ntoa(unpacked_data[9])
        if source_address == self.dst and destination_address == self.src:
            if proto_num == self.proto:
                if proto_num == socket.IPPROTO_TCP:
                    tcp_header = self.unpack_tcp(data[IPV4_HL:])
                    if tcp_header:
                        ip_header = {
                            "version": version,
                            "header_length": ihl * 4,
                            "tos": self.get_tos(tos_val),
                            "length": total_length,
                            "id": hex(id_num),
                            "flags": self.get_ip_flags(flags),
                            "offset": fragment_offset,
                            "ttl": ttl,
                            "proto": self.get_protocol(proto_num),
                            "checksum": checksum,
                            "source": source_address,
                            "dest": destination_address
                        }
                        return ip_header, tcp_header
        return None

    def unpack_tcp(self, data):
        tcp_header = struct.unpack('!HHLLBBHHH', data[:TCP_HL])
        src_port = tcp_header[0]
        dst_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        data_offset = tcp_header[4]
        tcp_flags = tcp_header[5]
        window_size = tcp_header[6]
        checksum = tcp_header[7]
        urg_ptr = tcp_header[8]
        data = data[TCP_HL:]
        if src_port == self.dport and dst_port == self.sport:
            return {
                "src_port": src_port,
                "dst_port": dst_port,
                "seq_num": seq_num,
                "ack_num": ack_num,
                "data_offset": data_offset,
                "flags": self.get_tcp_flags(tcp_flags),
                "window": window_size,
                "checksum": checksum,
                "urg_ptr": urg_ptr,
                "data": data
            }
        return None

    def send(self):
        print(self.data)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.proto)
        except socket.error as e:
            raise Exception(f"Socket could not be created. Error: {str(e)}")
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.sendto(self.data, (self.dst, 0))
        except socket.error as e:
            raise Exception(f"Sending packet failed. Error: {str(e)}")

    def receive(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.proto)
            sock.bind((socket.gethostbyname(socket.gethostname()), 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            while True:
                data = sock.recvfrom(MAX_BUFFER_SIZE)
                packet = self.unpacket(data)
                if packet:
                    return packet

        except socket.error as e:
            raise Exception(f"Socket could not be created. Error: {str(e)}")

    def sr1(self):
        self.send()
        return self.receive()

    def sr(self, n_packets):
        received = []
        for _ in range(n_packets):
            self.send()
            received.append(self.receive())
        return received
