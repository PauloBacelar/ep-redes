#!/usr/bin/env python3
"""
meu_traceroute.py - Traceroute com ICMP Echo Request e TTL crescente.

Funcionamento (como nos slides):
  1. Envia sondas com TTL = 1, 2, 3, ...
  2. O n-ésimo roteador do caminho decrementa o TTL para 0, descarta o
     datagrama e devolve ao remetente um ICMP "Time Exceeded" (tipo 11).
  3. O endereço de origem dessa mensagem identifica o roteador; o tempo entre
     envio e resposta é o RTT até ele.
  4. Ao chegar ao destino, ele responde com Echo Reply (tipo 0) e o programa para.

Uso (precisa de root/administrador):
    sudo python3 meu_traceroute.py google.com
    sudo python3 meu_traceroute.py 8.8.8.8 -m 20 -q 3 -w 2 -n
"""

import argparse
import os

import icmp_lib as icmp


def main():
    ap = argparse.ArgumentParser(description="Traceroute com ICMP (raw sockets)")
    ap.add_argument("host", help="nome ou endereço IPv4 de destino")
    ap.add_argument("-m", "--max-hops", type=int, default=30, help="nº máximo de saltos")
    ap.add_argument("-q", "--queries", type=int, default=3, help="sondas por salto")
    ap.add_argument("-w", "--timeout", type=float, default=2.0, help="tempo limite por sonda (s)")
    ap.add_argument("-s", "--size", type=int, default=40, help="bytes de dados por sonda")
    ap.add_argument("-n", "--numeric", action="store_true", help="não resolver nomes (mais rápido)")
    args = ap.parse_args()

    dest = icmp.resolve(args.host)
    sock = icmp.open_icmp_socket()
    ident = os.getpid() & 0xFFFF
    seq = 0

    print(f"traceroute para {args.host} ({dest}), máx. {args.max_hops} saltos, "
          f"{args.size} bytes de dados")

    names = {}  # cache de resolução reversa

    try:
        for ttl in range(1, args.max_hops + 1):
            line = f"{ttl:2d}  "
            last_addr = None
            reached = False

            for _ in range(args.queries):
                seq += 1
                info, rtt = icmp.send_probe(sock, dest, ident, seq, ttl, args.timeout, args.size)

                if info is None:
                    line += " *"
                    continue

                # Imprime o endereço só quando muda (vários roteadores podem responder no mesmo TTL)
                if info["src"] != last_addr:
                    last_addr = info["src"]
                    if args.numeric:
                        line += f" {last_addr}"
                    else:
                        if last_addr not in names:
                            names[last_addr] = icmp.reverse_name(last_addr)
                        line += f" {names[last_addr]} ({last_addr})"
                line += f"  {rtt:.2f} ms"

                if info["type"] == icmp.ICMP_ECHO_REPLY:
                    reached = True
                elif info["type"] == icmp.ICMP_DEST_UNREACHABLE:
                    line += " !U"  # destino inalcançável: não adianta continuar
                    reached = True

            print(line, flush=True)
            if reached:
                break
        else:
            print("Número máximo de saltos atingido sem alcançar o destino.")
    except KeyboardInterrupt:
        print("\nInterrompido.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
