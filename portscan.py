#!/usr/bin/env python3
"""The program for TCP and UDP ports of a given host scanning."""
from argparse import ArgumentParser
from logging import warning
from threading import active_count
from concurrent.futures import ThreadPoolExecutor

from port_analyser import PortAnalyser


WORKERS_COUNT = 20


def main():
    """Opened ports getting and their protocols recognizing."""
    host, ports = argument_parse()

    print("Analysing...")
    ports_analysers = []
    with ThreadPoolExecutor(max_workers=WORKERS_COUNT) as thread_pool:
        for port in ports:
            if 0 <= port <= 65535:
                port_analyser = PortAnalyser(host, port)
                thread_pool.submit(port_analyser.run)
                ports_analysers.append(port_analyser)
            else:
                warning("Incorrect port: %s", port)

    while True:
        if active_count() == 1:
            # Only one active interface thread. All of ports have been anaysed.
            break

    # Making a table.
    print()
    print("\tPorts of {}".format(host))
    print("--------------------------------")
    print("Port\tTCP\tUDP\tProtocol")

    for analyser in ports_analysers:
        print("{}\t{}\t{}\t{}".format(analyser.port, analyser.opened_tcp, \
                                analyser.opened_udp, analyser.protocol))


def argument_parse():
    """Arguments parsing."""
    parser = ArgumentParser(prog="python3 portscan.py", \
        description='Opened TCP and UPD ports recognizing. \
        Also a protocol on port can be recognized if it \
        is one of following protocols: NTP, DNS, SMTP, FTP, POP3, HTTP. \
        Notations: "+" for opened ports, "-" for closed ports, \
        "f" for filtering UDP-ports, "?" for unknown positions.', \
        epilog="(c) Semyon Makhaev, 2016. All rights reserved.")
    parser.add_argument("host", type=str, help="A scanning host address.")
    parser.add_argument("ports", type=int, nargs="*", \
        help="A range of scanning ports.")
    args = parser.parse_args()
    return args.host, args.ports


if __name__ == "__main__":
    main()
