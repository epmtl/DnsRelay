#!/usr/bin/python3

from time import sleep
# from datetime import datetime
from dnslib import QTYPE, RR, RCODE
from dnslib import A, AAAA  # ,CNAME, MX, NS, SOA, TXT
from dnslib.server import DNSServer
from dnslib import DNSRecord
from dnslib import DNSHeader
import socket
import socketserver
import struct
import http.client
import json
import logging

__author__ = 'epmtl'


logging_level = logging.INFO
logging.basicConfig(
            format='%(asctime)s %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p',
            # filename='./dnslogs.txt',
            filemode='w',
            level=logging_level)

# Google DNS over HTTPS
external_https_dns_port = 443
external_https_dns_address = "dns.google.com"
external_https_dns_uri = "/resolve?name="
# SYSTEM SPECIFIC
local_dns_port = 10053
local_dns_address = ""  # "" by default = "0.0.0.0"
# ENVIRONMENT SPECIFIC
external_https_proxy_address = "proxy.example.com"
external_https_proxy_port = 8080
internal_dns_port = 53
internal_dns_address = "10.0.0.1"
internal_honeypot = "10.0.0.2"


class DNSRelayOverHTTPS:
    connection = None
    dns_request = None
    headers = {}

    def __init__(self, address, port=443, proxy_address=None, proxy_port=80):
        self.address = address
        self.port = port
        self.proxy_address = proxy_address
        self.proxy_port = proxy_port
        if self.proxy_address is not None:
            self.connection = http.client.HTTPSConnection(
                self.proxy_address,
                self.proxy_port)
            self.connection.set_tunnel(self.address, self.port)
        else:
            self.connection = http.client.HTTPSConnection(
                self.address,
                self.port)
        self.headers = {'Content-type': 'application/json'}

    def send_request(self, data):
        request = DNSRecord.parse(data)
        self.dns_request = request
        uri = external_https_dns_uri + str(request.q.qname)
        # logging.debug("uri="+str(uri))
        self.connection.request('GET', uri, body=None, headers=self.headers)
        response = self.connection.getresponse()
        return response.read().decode()

    def parse_answer(self, raw_answer):
        # OUTPUT EXAMPLE:
        # {
        #     "Status": 0,
        #     "TC": false,
        #     "RD": true,
        #     "RA": true,
        #     "AD": false,
        #     "CD": false,
        #     "Question": [
        #         {
        #             "name": "google.ca.",
        #             "type": 255
        #         }
        #     ],
        #     "Answer": [
        #         {
        #             "name": "google.ca.",
        #             "type": 1,
        #             "TTL": 299,
        #             "data": "172.217.10.67"
        #         },...
        #     ],
        #     "Comment": "Response from 216.239.32.10"
        # }

        d = self.dns_request.reply()
        dns_json_data = json.loads(raw_answer)
        if "Answer" in dns_json_data:
            for answer in dns_json_data["Answer"]:
                name = ""
                dns_type = 255
                ttl = 0
                data = ""
                for key, value in answer.items():
                        if key in "name":
                            name = value
                        elif key in "type":
                            dns_type = value
                        elif key in "TTL":
                            ttl = value
                        elif key in "data":
                            data = value
                if dns_type == QTYPE.A:
                    d.add_answer(RR(name, dns_type, ttl=ttl, rdata=A(data)))
                elif dns_type == QTYPE.AAAA:
                    d.add_answer(RR(name, dns_type, ttl=ttl, rdata=AAAA(data)))
                else:
                    logging.warning("+-------- DNS TYPE : " + str(dns_type) + " NOT SUPPORTED YET !")
        else:
            logging.info("+-------- OK - NO ANSWER FROM EXTERNAL DNS !!!")
        return d

    def close(self):
        self.connection.close()


class DNSRelayOverUDP:
    connection = None
    max_buffer = 1024

    def __init__(self, address, port=53):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.address = address
        self.port = port

    def send_request(self, data):
        self.connection.sendto(data, (self.address, self.port))
        raw_answer, from_address = self.connection.recvfrom(self.max_buffer)
        return raw_answer

    @staticmethod
    def parse_answer(raw_answer):
        internal_dns_answer = DNSRecord.parse(raw_answer)
        return internal_dns_answer

    def close(self):
        self.connection.close()


class CustomDNSHandler(socketserver.BaseRequestHandler):

    udp_len = 0  # Max udp packet length (0 = ignore)
    protocol = 'udp'  # Default one

    def handle(self):
        connection = None

        if self.server.socket_type == socket.SOCK_STREAM:
            self.protocol = 'tcp'
            data = self.request.recv(8192)
            length = struct.unpack("!H", bytes(data[:2]))[0]
            while len(data) - 2 < length:
                new_data = self.request.recv(8192)
                if not new_data:
                    break
                data += new_data
            data = data[2:]
        else:
            self.protocol = 'udp'
            data, connection = self.request

        # self.server.logger.log_recv(self, data)

        try:
            logging.info('---------------------------')
            r_data = self.get_reply(data)
            # self.server.logger.log_send(self, r_data)

            if self.protocol == 'tcp':
                r_data = struct.pack("!H", len(r_data)) + r_data
                self.request.sendall(r_data)
            else:
                connection.sendto(r_data, self.client_address)

        except Exception as e:
            # self.server.logger.log_error(self, e)
            logging.error('--------- DNS ERROR: ' + str(e))

    @staticmethod
    def get_ip(ip):
        # remove last character
        ip = str(ip).rstrip('.')
        try:
            socket.inet_aton(ip)
            return ip
        except socket.error:
            logging.debug('+-------- OK - DNS QUESTION IS NOT AN IP: ' + str(ip))
            return None

    def get_reply(self, data):
        request = DNSRecord.parse(data)
        # self.server.logger.log_request(self, request)

        ip = self.get_ip(request.q.qname)
        if ip is not None:
            logging.warning('--------- WARN - REVERSE NOT SUPPORTED YET FOR : ' + str(request.q.qname))
            error_record = DNSRecord(
                DNSHeader(id=request.header.id,
                          bitmap=request.header.bitmap,
                          qr=1,
                          ra=1,
                          aa=1,
                          rcode=RCODE.FORMERR),
                q=request.q)
            return error_record.pack()

        # Forward Resolution
        logging.info('--------- OK - REQUESTED URL: ' + str(request.q.qname))
        internal_dns = DNSRelayOverUDP(internal_dns_address, internal_dns_port)
        internal_dns_answer = internal_dns.send_request(data)
        # Return a DNS record
        r_data = internal_dns.parse_answer(internal_dns_answer)
        internal_dns.close()
        if r_data.get_a() is not None \
            and r_data.get_a().rdata is not None and \
                not str(r_data.get_a().rdata).startswith(internal_honeypot):
            internal_result_data = r_data.get_a().rdata
            logging.info('--------- OK - ANSWER INTERNAL DNS: ' + str(internal_result_data))
        else:
            logging.info('--------- OK - NO ANSWER FROM INTERNAL DNS...')
            external_dns = DNSRelayOverHTTPS(external_https_dns_address,
                                             external_https_dns_port,
                                             external_https_proxy_address,
                                             external_https_proxy_port)
            external_dns_answer = external_dns.send_request(data)
            r_data = external_dns.parse_answer(external_dns_answer)
            logging.info('--------- OK - ANSWER EXTERNAL DNS:' + str(external_dns_answer))
            external_dns.close()
        return r_data.pack()

servers = [
    DNSServer(None, port=local_dns_port, address=local_dns_address, tcp=True, handler=CustomDNSHandler),
    DNSServer(None, port=local_dns_port, address=local_dns_address, tcp=False, handler=CustomDNSHandler),
]

if __name__ == '__main__':
    for s in servers:
        s.start_thread()

    try:
        while 1:
            sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.stop()
