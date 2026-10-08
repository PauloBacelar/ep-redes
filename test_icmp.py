"""Testes offline (não precisam de rede nem de root): python3 -m unittest -v test_icmp"""

import socket
import struct
import unittest

import icmp_lib as icmp


def ip_header(src, dst, proto=socket.IPPROTO_ICMP, ttl=64, total_len=0):
    # versão/IHL=0x45, TOS, tamanho, id, flags/frag, TTL, protocolo, checksum(0), src, dst
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0, ttl, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))


def with_checksum(icmp_msg: bytes) -> bytes:
    chk = icmp.checksum(icmp_msg)
    return icmp_msg[:2] + struct.pack("!H", chk) + icmp_msg[4:]


class TestChecksum(unittest.TestCase):
    def test_rfc1071_example(self):
        # Exemplo da RFC 1071: soma = 0xddf2 -> checksum = 0x220d
        data = bytes([0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7])
        self.assertEqual(icmp.checksum(data), 0x220D)

    def test_odd_length(self):
        self.assertEqual(icmp.checksum(b"\x01"), icmp.checksum(b"\x01\x00"))

    def test_built_packet_validates_to_zero(self):
        pkt = icmp.build_echo_request(0x1234, 7, 56)
        self.assertEqual(icmp.checksum(pkt), 0)
        self.assertEqual(len(pkt), 8 + 56)
        tipo, codigo, _, ident, seq = struct.unpack(icmp.ICMP_HEADER, pkt[:8])
        self.assertEqual((tipo, codigo, ident, seq), (8, 0, 0x1234, 7))


class TestParse(unittest.TestCase):
    def test_echo_reply(self):
        msg = with_checksum(struct.pack("!BBHHH", 0, 0, 0, 42, 5) + b"dados123")
        pkt = ip_header("8.8.8.8", "10.0.0.2", ttl=117) + msg
        info = icmp.parse_packet(pkt)
        self.assertEqual(info["type"], icmp.ICMP_ECHO_REPLY)
        self.assertEqual((info["src"], info["ttl"], info["ident"], info["seq"]),
                         ("8.8.8.8", 117, 42, 5))

    def test_time_exceeded_carries_original_probe(self):
        original = ip_header("10.0.0.2", "8.8.8.8") + \
            struct.pack("!BBHHH", 8, 0, 0, 99, 3)  # nossa sonda: ident=99, seq=3
        msg = with_checksum(struct.pack("!BBHI", 11, 0, 0, 0) + original)
        pkt = ip_header("192.168.0.1", "10.0.0.2", ttl=250) + msg
        info = icmp.parse_packet(pkt)
        self.assertEqual(info["type"], icmp.ICMP_TIME_EXCEEDED)
        self.assertEqual((info["src"], info["ident"], info["seq"]), ("192.168.0.1", 99, 3))

    def test_corrupted_checksum_is_rejected(self):
        msg = bytearray(with_checksum(struct.pack("!BBHHH", 0, 0, 0, 1, 1) + b"abcdefgh"))
        msg[-1] ^= 0xFF
        self.assertIsNone(icmp.parse_packet(ip_header("1.1.1.1", "10.0.0.2") + bytes(msg)))

    def test_truncated_and_non_icmp(self):
        self.assertIsNone(icmp.parse_packet(b"\x45\x00"))
        msg = with_checksum(struct.pack("!BBHHH", 0, 0, 0, 1, 1))
        self.assertIsNone(icmp.parse_packet(ip_header("1.1.1.1", "10.0.0.2", proto=17) + msg))


if __name__ == "__main__":
    unittest.main()
