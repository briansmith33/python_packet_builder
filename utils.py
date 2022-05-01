import array as arr
import struct


def checksum(pkt):
    if len(pkt) % 2 == 1:
        pkt += b"\0"
    s = sum(arr.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s

    def endian_transform(chk):
        return ((chk >> 8) & 0xff) | chk << 8 if ord(struct.pack("H", 1).decode()[0]) else chk

    return endian_transform(s) & 0xffff
