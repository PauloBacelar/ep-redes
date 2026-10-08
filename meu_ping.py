#!/usr/bin/env python3
"""
meu_ping.py - Ping implementado com ICMP Echo Request/Reply sobre raw socket.

Uso (precisa de root/administrador):
    sudo python3 meu_ping.py google.com
    sudo python3 meu_ping.py 8.8.8.8 -c 5 -i 0.5 -s 100 -t 2
"""

import argparse
import math
import os
import time

import icmp_lib as icmp


def main():
    ap = argparse.ArgumentParser(description="Ping com ICMP (raw sockets)")
    ap.add_argument("host", help="nome ou endereço IPv4 de destino")
    ap.add_argument("-c", "--count", type=int, default=4, help="nº de pacotes (0 = infinito)")
    ap.add_argument("-i", "--interval", type=float, default=1.0, help="intervalo entre envios (s)")
    ap.add_argument("-t", "--timeout", type=float, default=2.0, help="tempo limite por resposta (s)")
    ap.add_argument("-s", "--size", type=int, default=56, help="bytes de dados (padrão: 56)")
    ap.add_argument("--ttl", type=int, default=64, help="TTL dos pacotes enviados")
    args = ap.parse_args()

    dest = icmp.resolve(args.host)
    sock = icmp.open_icmp_socket()
    ident = os.getpid() & 0xFFFF
    size = max(args.size, icmp.MIN_PAYLOAD)

    print(f"PING {args.host} ({dest}): {size} bytes de dados")

    rtts = []
    sent = 0
    seq = 0
    try:
        while args.count == 0 or sent < args.count:
            seq += 1
            sent += 1
            info, rtt = icmp.send_probe(sock, dest, ident, seq, args.ttl, args.timeout, size)

            if info is None:
                print(f"Tempo esgotado para icmp_seq={seq}")
            elif info["type"] == icmp.ICMP_ECHO_REPLY:
                rtts.append(rtt)
                print(f"{info['size']} bytes de {info['src']}: "
                      f"icmp_seq={seq} ttl={info['ttl']} tempo={rtt:.2f} ms")
            elif info["type"] == icmp.ICMP_TIME_EXCEEDED:
                print(f"De {info['src']}: icmp_seq={seq} TTL excedido em trânsito")
            elif info["type"] == icmp.ICMP_DEST_UNREACHABLE:
                motivo = icmp.DEST_UNREACH_CODES.get(info["code"], f"código {info['code']}")
                print(f"De {info['src']}: icmp_seq={seq} destino inalcançável ({motivo})")

            if args.count == 0 or sent < args.count:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print()
    finally:
        sock.close()
        print_stats(args.host, sent, rtts)


def print_stats(host, sent, rtts):
    received = len(rtts)
    loss = 100.0 * (sent - received) / sent if sent else 0.0
    print(f"--- estatísticas de ping de {host} ---")
    print(f"{sent} pacotes transmitidos, {received} recebidos, {loss:.0f}% de perda")
    if rtts:
        avg = sum(rtts) / received
        mdev = math.sqrt(sum((r - avg) ** 2 for r in rtts) / received)
        print(f"rtt mín/méd/máx/desvio = {min(rtts):.2f}/{avg:.2f}/{max(rtts):.2f}/{mdev:.2f} ms")


if __name__ == "__main__":
    main()
