#!/usr/bin/env python3
"""
Minimal MaxMind DB (.mmdb) reader — pure Python 3 stdlib, no dependencies.

Implements enough of the MaxMind DB binary format to look up an IPv4/IPv6
address and decode the record:
  https://maxmind.github.io/MaxMind-DB/

Only the decode types the GeoLite2 City/Country/ASN databases actually use are
implemented (map, utf8_string, uint16/32/64, double, array, pointer, boolean).
Enough for country / city / ASN enrichment. Not a general-purpose library.

Usage:
    r = MMDB("/var/lib/GeoIP/GeoLite2-City.mmdb")
    rec = r.get("8.8.8.8")        # -> dict, or None if not found
"""
import ipaddress
import struct

_METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


class MMDBError(Exception):
    pass


class _Decoder:
    def __init__(self, buf, data_start):
        self.buf = buf
        self.data_start = data_start  # offset where the data section begins

    def decode(self, offset):
        ctrl = self.buf[offset]
        offset += 1
        dtype = ctrl >> 5
        if dtype == 1:  # pointer
            return self._pointer(ctrl, offset)
        if dtype == 0:  # extended type
            dtype = 7 + self.buf[offset]
            offset += 1
        size, offset = self._size(ctrl, offset)
        return self._value(dtype, size, offset)

    def _size(self, ctrl, offset):
        size = ctrl & 0x1F
        if size < 29:
            return size, offset
        if size == 29:
            return 29 + self.buf[offset], offset + 1
        if size == 30:
            return 285 + struct.unpack(">H", self.buf[offset:offset + 2])[0], offset + 2
        # size == 31
        b = self.buf[offset:offset + 3]
        return 65821 + ((b[0] << 16) | (b[1] << 8) | b[2]), offset + 3

    def _pointer(self, ctrl, offset):
        psize = (ctrl >> 3) & 0x3
        if psize == 0:
            p = ((ctrl & 0x7) << 8) | self.buf[offset]
            offset += 1
        elif psize == 1:
            p = ((ctrl & 0x7) << 16) | struct.unpack(">H", self.buf[offset:offset + 2])[0]
            p += 2048
            offset += 2
        elif psize == 2:
            b = self.buf[offset:offset + 3]
            p = ((ctrl & 0x7) << 24) | (b[0] << 16) | (b[1] << 8) | b[2]
            p += 526336
            offset += 3
        else:  # psize == 3
            p = struct.unpack(">I", self.buf[offset:offset + 4])[0]
            offset += 4
        value, _ = self._decode_at(self.data_start + p)
        return value, offset

    def _decode_at(self, offset):
        """decode() but also returns the new offset (for pointer targets)."""
        ctrl = self.buf[offset]
        offset += 1
        dtype = ctrl >> 5
        if dtype == 1:
            return self._pointer(ctrl, offset)
        if dtype == 0:
            dtype = 7 + self.buf[offset]
            offset += 1
        size, offset = self._size(ctrl, offset)
        return self._value_pair(dtype, size, offset)

    # the two value helpers differ only in what they return (value vs value,offset)
    def _value(self, dtype, size, offset):
        return self._value_pair(dtype, size, offset)[0]

    def _value_pair(self, dtype, size, offset):
        if dtype == 2:  # utf8_string
            return self.buf[offset:offset + size].decode("utf-8", "replace"), offset + size
        if dtype == 5:  # uint16
            return self._uint(size, offset), offset + size
        if dtype == 6:  # uint32
            return self._uint(size, offset), offset + size
        if dtype == 9:  # uint64
            return self._uint(size, offset), offset + size
        if dtype == 10:  # uint128
            return self._uint(size, offset), offset + size
        if dtype == 8:  # int32
            v = self._uint(size, offset)
            if size and (self.buf[offset] & 0x80):
                v -= 1 << (8 * size)
            return v, offset + size
        if dtype == 3:  # double
            return struct.unpack(">d", self.buf[offset:offset + 8])[0], offset + 8
        if dtype == 15:  # float
            return struct.unpack(">f", self.buf[offset:offset + 4])[0], offset + 4
        if dtype == 4:  # bytes
            return self.buf[offset:offset + size], offset + size
        if dtype == 14:  # boolean
            return bool(size), offset
        if dtype == 7:  # map
            out = {}
            for _ in range(size):
                key, offset = self._decode_at(offset)
                val, offset = self._decode_at(offset)
                out[key] = val
            return out, offset
        if dtype == 11:  # array
            out = []
            for _ in range(size):
                val, offset = self._decode_at(offset)
                out.append(val)
            return out, offset
        if dtype in (12, 13):  # data cache container / end marker — unused
            return None, offset
        raise MMDBError(f"unknown data type {dtype}")

    @staticmethod
    def _uint_from(buf, size, offset):
        v = 0
        for i in range(size):
            v = (v << 8) | buf[offset + i]
        return v

    def _uint(self, size, offset):
        return self._uint_from(self.buf, size, offset)


class MMDB:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.buf = f.read()
        meta_off = self.buf.rfind(_METADATA_MARKER)
        if meta_off == -1:
            raise MMDBError("not a MaxMind DB file (metadata marker missing)")
        meta_dec = _Decoder(self.buf, meta_off + len(_METADATA_MARKER))
        self.metadata = meta_dec.decode(meta_off + len(_METADATA_MARKER))
        self.node_count = self.metadata["node_count"]
        self.record_size = self.metadata["record_size"]  # bits per record (24/28/32)
        self.ip_version = self.metadata["ip_version"]
        self.node_byte_size = (self.record_size * 2) // 8
        self.search_tree_size = self.node_count * self.node_byte_size
        # data section starts 16 bytes after the search tree
        self.data_section = self.search_tree_size + 16
        self.decoder = _Decoder(self.buf, self.data_section)

    def _read_node(self, node, index):
        base = node * self.node_byte_size
        rs = self.record_size
        if rs == 24:
            off = base + index * 3
            b = self.buf[off:off + 3]
            return (b[0] << 16) | (b[1] << 8) | b[2]
        if rs == 28:
            if index == 0:
                b = self.buf[base:base + 3]
                mid = self.buf[base + 3]
                return ((mid & 0xF0) << 20) | (b[0] << 16) | (b[1] << 8) | b[2]
            b = self.buf[base + 4:base + 7]
            mid = self.buf[base + 3]
            return ((mid & 0x0F) << 24) | (b[0] << 16) | (b[1] << 8) | b[2]
        if rs == 32:
            off = base + index * 4
            return struct.unpack(">I", self.buf[off:off + 4])[0]
        raise MMDBError(f"unsupported record size {rs}")

    def get(self, ip_str):
        addr = ipaddress.ip_address(ip_str)
        bits = format(int(addr), f"0{addr.max_prefixlen}b")
        # IPv4 lookup inside an IPv6 tree: walk the first 96 bits (::ffff:0:0)
        if self.ip_version == 6 and addr.version == 4:
            bits = "0" * 96 + bits
        node = 0
        for bit in bits:
            if node >= self.node_count:
                break
            node = self._read_node(node, int(bit))
        if node == self.node_count:
            return None  # no record
        if node > self.node_count:
            data_off = (node - self.node_count) + self.search_tree_size
            return self.decoder.decode(data_off)
        return None


# convenience: one reader per db path, cached
_readers = {}


def reader(path):
    r = _readers.get(path)
    if r is None:
        r = MMDB(path)
        _readers[path] = r
    return r


if __name__ == "__main__":
    import sys
    db = sys.argv[1] if len(sys.argv) > 1 else "/var/lib/GeoIP/GeoLite2-City.mmdb"
    ip = sys.argv[2] if len(sys.argv) > 2 else "8.8.8.8"
    rec = reader(db).get(ip)
    import json
    print(json.dumps(rec, ensure_ascii=False, indent=2, default=str))
