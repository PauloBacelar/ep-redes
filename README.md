# EP Redes de Computadores

Implementação de ferramentas de diagnóstico de rede utilizando **ICMP e raw sockets em Python**.

O projeto implementa versões simplificadas dos comandos `ping` e `traceroute`, permitindo analisar o funcionamento desses mecanismos diretamente através do protocolo ICMP.

## Funcionalidades

* **Ping**

  * Envio de ICMP Echo Request
  * Recepção de ICMP Echo Reply
  * Cálculo do RTT
  * Estatísticas de perda de pacotes
  * Controle de quantidade de pacotes, intervalo, tamanho e TTL

* **Traceroute**

  * Descoberta dos roteadores no caminho até um destino
  * Utilização do campo TTL do IPv4
  * Tratamento de mensagens ICMP Time Exceeded
  * Medição do tempo de resposta de cada salto
  * Suporte a múltiplas sondas por salto

## Estrutura

```text
.
├── icmp_lib.py
├── meu_ping.py
├── meu_traceroute.py
└── test_icmp.py
```

* `icmp_lib.py` — funções auxiliares para comunicação utilizando ICMP.
* `meu_ping.py` — implementação do `ping`.
* `meu_traceroute.py` — implementação do `traceroute`.
* `test_icmp.py` — testes da biblioteca ICMP.

## Requisitos

* Python 3
* Sistema operacional com suporte a **raw sockets**
* Privilégios de administrador/root para executar os programas.

## Uso

### Ping

```bash
sudo python3 meu_ping.py google.com
```

Algumas opções disponíveis:

```bash
sudo python3 meu_ping.py -c 4 google.com
sudo python3 meu_ping.py -i 1 google.com
sudo python3 meu_ping.py -s 64 google.com
```

### Traceroute

```bash
sudo python3 meu_traceroute.py google.com
```

Algumas opções disponíveis:

```bash
sudo python3 meu_traceroute.py -m 20 google.com
sudo python3 meu_traceroute.py -q 3 google.com
sudo python3 meu_traceroute.py -w 2 google.com
```

## Conceitos estudados

O projeto aborda conceitos fundamentais de Redes de Computadores, como:

* Protocolo ICMP
* IPv4
* TTL
* Raw sockets
* RTT
* Echo Request / Echo Reply
* ICMP Time Exceeded
* Roteamento e descoberta de caminho
* Perda de pacotes

## Autores

**Paulo Guilherme B. Andrade - 16895603**
**Breno G. F. Lopes - 16857617**
