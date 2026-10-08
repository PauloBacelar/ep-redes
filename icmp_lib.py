"""
icmp_lib.py - Funções compartilhadas por meu_ping.py e meu_traceroute.py

Conceitos dos slides (Camada de Rede, ICMP):
  - ICMP é usado por hospedeiros e roteadores para comunicar informações de
    nível de rede (relato de erros, "eco" de ping).
  - Mensagem ICMP = tipo + código + checksum + (cabeçalho específico) + dados.
  - Mensagens de erro (tipo 3 e 11) carregam o cabeçalho IP e os primeiros
    8 bytes do datagrama que causou o erro: é assim que sabemos a qual
    sonda a resposta se refere.

Requer privilégios de administrador (root / CAP_NET_RAW) para abrir o raw socket.
"""

import socket
import struct
import time

# Tipos ICMP usados
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11

DEST_UNREACH_CODES = {
    0: "rede de destino inalcançável",
    1: "hospedeiro de destino inalcançável",
    2: "protocolo de destino inalcançável",
    3: "porta de destino inalcançável",
    4: "fragmentação necessária, mas DF ativo",
    5: "falha na rota de origem",
    13: "comunicação proibida administrativamente",
}

ICMP_HEADER = "!BBHHH"  # tipo, código, checksum, identificador, nº de sequência
ICMP_HEADER_LEN = 8
MIN_PAYLOAD = 8  # espaço para o timestamp


def checksum(data: bytes) -> int:
    """Checksum da Internet (RFC 1071): complemento de 1 da soma de palavras de 16 bits."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)  # "vai-um" circular
    total += total >> 16
    return ~total & 0xFFFF


def build_echo_request(ident: int, seq: int, payload_size: int = 56) -> bytes:
    """Monta uma mensagem ICMP Echo Request (tipo 8, código 0) com checksum válido."""
    payload_size = max(payload_size, MIN_PAYLOAD)
    timestamp = struct.pack("!d", time.time())
    padding = bytes(i & 0xFF for i in range(payload_size - len(timestamp)))
    payload = timestamp + padding

    # 1ª passada com checksum = 0; 2ª com o valor calculado
    header = struct.pack(ICMP_HEADER, ICMP_ECHO_REQUEST, 0, 0, ident, seq & 0xFFFF)
    chk = checksum(header + payload)
    header = struct.pack(ICMP_HEADER, ICMP_ECHO_REQUEST, 0, chk, ident, seq & 0xFFFF)
    return header + payload


def parse_packet(packet: bytes):
    """
    Interpreta um datagrama IP recebido (o raw socket entrega o cabeçalho IP junto).

    Retorna um dict com: src, ttl, type, code, ident, seq, size
      - Para Echo Reply: ident/seq vêm do próprio cabeçalho ICMP.
      - Para Time Exceeded / Dest. Unreachable: ident/seq vêm do pacote ORIGINAL
        embutido na mensagem de erro.
    Retorna None se o pacote for inválido ou não for relevante.
    """
    if len(packet) < 20 + ICMP_HEADER_LEN:
        return None

    ihl = (packet[0] & 0x0F) * 4
    if packet[9] != socket.IPPROTO_ICMP:
        return None
    src = socket.inet_ntoa(packet[12:16])
    ttl = packet[8]

    icmp = packet[ihl:]
    if len(icmp) < ICMP_HEADER_LEN or checksum(icmp) != 0:
        return None  # truncado ou corrompido

    icmp_type, code = icmp[0], icmp[1]
    info = {"src": src, "ttl": ttl, "type": icmp_type, "code": code,
            "ident": None, "seq": None, "size": len(icmp)}

    if icmp_type in (ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST):
        info["ident"], info["seq"] = struct.unpack("!HH", icmp[4:8])
    elif icmp_type in (ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACHABLE):
        inner = icmp[8:]  # cabeçalho IP original + 8 primeiros bytes do ICMP original
        if len(inner) < 20 + 8:
            return None
        inner_ihl = (inner[0] & 0x0F) * 4
        if inner[9] != socket.IPPROTO_ICMP or len(inner) < inner_ihl + 8:
            return None
        info["ident"], info["seq"] = struct.unpack("!HH", inner[inner_ihl + 4:inner_ihl + 8])
    else:
        return None
    return info


def open_icmp_socket() -> socket.socket:
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        raise SystemExit("Erro: raw sockets exigem privilégios de administrador "
                         "(execute com sudo ou como Administrador).")


def send_probe(sock, dest_ip, ident, seq, ttl, timeout, payload_size=56):
    """
    Envia um Echo Request com o TTL indicado e espera a resposta correspondente.

    Retorna (info, rtt_ms). Se esgotar o tempo: (None, None).
    Respostas de outros processos / sondas antigas são ignoradas.
    """
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    packet = build_echo_request(ident, seq, payload_size)

    start = time.perf_counter()
    sock.sendto(packet, (dest_ip, 0))
    deadline = start + timeout

    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return None, None
        sock.settimeout(remaining)
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            return None, None
        rtt_ms = (time.perf_counter() - start) * 1000

        info = parse_packet(data)
        if info is None:
            continue
        if info["type"] == ICMP_ECHO_REQUEST:
            continue  # em loopback recebemos a nossa própria requisição
        if info["ident"] != ident or info["seq"] != (seq & 0xFFFF):
            continue  # resposta de outra sonda/processo
        return info, rtt_ms


def resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        raise SystemExit(f"Erro: não foi possível resolver '{host}'.")


def reverse_name(ip: str) -> str:
    """Resolução reversa (DNS) com fallback para o próprio IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ip
