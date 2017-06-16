#!/usr/bin/env python3
"""The port analyser recogniznig properties of a port."""
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, \
                            IPPROTO_IP, timeout, error, IPPROTO_ICMP
from IN import IP_RECVERR
from struct import pack, unpack
from logging import debug, warning
from datetime import datetime
from os import linesep


TIMEOUT = 3


class PortAnalyser:
    """
    A representation of a new thread.
    Recognizing is the port of a given host opened or not.
    Following protocols recognizing: NTP, DNS, SMTP, FTP, POP3, HTTP.
    """
    def __init__(self, host, port):
        self.host = host
        self.port = port

        # It will be string values: '+' or '-'.
        # For UDP 'f' means that port is filtering.
        self.opened_tcp = "?"
        self.opened_udp = "?"

        # It will be a string value.
        # Available values are "NTP", "DNS", "SMTP", "FTP", "POP3", "HTTP".
        self.protocol = "?"


    def run(self):
        """Starting analysing tools for a given port."""
        self.tcp_request()
        self.udp_request()


    def tcp_request(self):
        """
        Recognizes is the port opened for TCP-requests.
        Also recognizes SMTP, FTP, POP3 and HTTP protocols working on this port.
        """
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        try:
            sock.connect((self.host, self.port))
            self.opened_tcp = "+"

            try:
                data = sock.recv(512).decode()

            except timeout:
                # It is not a post protocol because there is no greeting.
                # It may be HTTP.
                sock.send("GET / HTTP/1.1{0}{0}".format(linesep).encode())

                try:
                    data = sock.recv(512).decode()
                    if data.startswith("HTTP"):
                        self.protocol = "HTTP"
                except timeout:
                    # This is not a protocol from the list.
                    return

            else:
                # It may be a post server.
                if data.startswith("220"):
                    # Mail-server is connected to electrical power station.
                    data = data.lower()
                    if data.find("smtp") > 0:
                        self.protocol = "SMTP"
                    elif data.find("ftp") > 0:
                        self.protocol = "FTP"
                elif data.startswith("+OK"):
                    self.protocol = "POP3"

        # TCP is closed in following cases.
        except timeout:
            self.opened_tcp = "-"
        except error:
            debug("Can't get information about TCP on port: %s.", self.port)
            self.opened_tcp = "-"
        finally:
            sock.close()


    def udp_request(self):
        """
        Recognizes is the port opened for UDP-requests or not.
        Also checks NTP and DNS protocols.
        """

        # SNTP package assembling.
        li_vn_mode = 2 << 3
        li_vn_mode |= 3
        buff = pack("!BBBbiIIQQQQ", li_vn_mode, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        # A special socket for ICMP-messages (port ureachable) catching.
        try:
            icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            icmp_sock.setsockopt(IPPROTO_IP, IP_RECVERR, 1)
            icmp_sock.settimeout(TIMEOUT)
        except error:
            warning("Permission denied. UDP information is unavailable.")
            return

        sock = socket(AF_INET, SOCK_DGRAM)
        sock.settimeout(TIMEOUT)

        with sock:
            try:
                sock.sendto(buff, (self.host, self.port))
                icmp_err = icmp_sock.recv(512)# Error messages checking.

                if len(icmp_err) > 21 and icmp_err[20] == 3:
                    if icmp_err[21] == 3:
                        # ICMP message: port is unreachable.
                        self.opened_udp = "-"
                    else:
                        # Port is filtering.
                        self.opened_udp = "f"
                    return

            except timeout:
                self.opened_udp = "+"

            except error:
                debug("Can't get information about UDP on port: %s.", self.port)
                self.opened_udp = "-"
                return

            finally:
                icmp_sock.close()

            # Protocol recognizing.
            try:
                data = sock.recv(1024)
                self.recognize_udp_protocol(data, buff)

            except timeout:
                self.additionally_recognize_dns(sock)


    def recognize_udp_protocol(self, data, buff):
        """
        Recognizes a protocol working on this port
        of a given host if this protocol is DNS or NTP.
        """
        if len(data) == 48:
            buff = unpack("!BBBbiIIIIIIIIII", data)
            year = datetime.now().year
            if int(buff[11] / 31536000 + 1900) == year:
                self.protocol = "NTP"

        if len(data) > 3:
            number = data[:2]
            reply_code = data[3] & 15
            if number == buff[:2] and 0 <= reply_code <= 9:
                self.protocol = "DNS"


    def additionally_recognize_dns(self, sock):
        """
        Trying to recognize DNS is case of there
        is no answer from target host.
        DNS-request assembling and sending.
        """

        # A request for anytask.urgu.org.
        request = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00" \
                + b"\x00\x00\x00\x07\x61\x6e\x79\x74\x61" \
                + b"\x73\x6b\x04\x75\x72\x67\x75\x03\x6f" \
                + b"\x72\x67\x00\x00\x01\x00\x01"

        sock.sendto(request, (self.host, self.port))

        try:
            data = sock.recv(1024)
            self.recognize_udp_protocol(data, request)

        except timeout:
            # Nothing to recognize. It is not DNS.
            pass
