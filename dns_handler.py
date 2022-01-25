from ipaddress import AddressValueError, IPv4Address
import logging
from scapy.layers.dns import DNS
import socket
import socketserver
from typing import *

from yaml_helper import YamlHelper

class DNSServer(socketserver.UDPServer):
    fallback_servers: List[IPv4Address]
    lookup_servers: Dict[bytes, List[IPv4Address]]

    def __init__(self, address: IPv4Address, *, fallback_servers: List[IPv4Address], lookup_servers: Dict[bytes, List[IPv4Address]], port: int = 53):
        super().__init__((address.exploded, port), DNSServer._RequestHandler)
        self._client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.lookup_servers = lookup_servers
        self.fallback_servers = fallback_servers

    def close(self):
        self._client_sock.close()
        super().close()

    class _RequestHandler(socketserver.DatagramRequestHandler):
        def handle(self):
            def recvfrom() -> bytes:
                try:
                    return self.server._client_sock.recvfrom(512)[0]
                except Exception as e:
                    logging.error(f"Exception: {e}", exc_info=e)
                    return DNS(qr=1, rcode=2)

            data, reply_sock = self.request
            client_addr = self.client_address

            packet = DNS(data)
            logging.info(f"Received request from {client_addr[0]} for {packet.qd.qname.decode()}")

            def server_generator():
                for domain, servers in self.server.lookup_servers.items():
                    if packet.qd.qname.endswith(domain):
                        for each in servers:
                            if each == "fallback":
                                yield from self.server.fallback_servers
                            yield each
                else:
                    # send to a fallback servers otherwise
                    yield from self.server.fallback_servers

            for remote_server in server_generator():
                try:
                    logging.debug(f"Sending request to {remote_server}")
                    self.server._client_sock.sendto(data, (remote_server.exploded, 53))
                    reply = recvfrom()
                except Exception as e:
                    logging.error(f"Request to {remote_server.exploded} failed: {e}")
                    continue
                reply_sock.sendto(bytes(reply), client_addr)
                break


def dns_parser(data: bytes) -> Dict[str, Any]:
    """
    Manual parser for a DNS message
    """
    # question, answer, authoritative, additional
    sections = ["qn", "an", "aa", "ad"]
    
    packet = {
        'trans_id': int.from_bytes(data[0:2], "big"),
        'qr': data[2] & 0x80,
        'opcode': data[2] & 0x78,
        'aa': data[2] & 0x04, # 0b0000_0100
        'tc': data[2] & 0x02,
        'rd': data[2] & 0x01,
        'ra': data[3] & 0x80,
        'rcode': data[3] & 0x0F
    }

    index = 4
    for section in sections:
        packet[section + "len"] = int.from_bytes(data[index:index + 2], "big")
        index += 2

    for section in sections:
        records = []

        for _ in range(packet[section + "len"]):
            domain_name = []

            while True:
                length = data[index]
                if length == 0:
                    records.append({
                        'qname': b'.'.join(domain_name),
                        'type': int.from_bytes(data[index + 1: index + 3], "big"),
                        'class': int.from_bytes(data[index + 3 : index + 5], "big")
                    })
                    index += 4
                    break
                
                index += 1
                domain_name.append(data[index:index + length])
                index += length

        packet[section] = records
    
    return packet


def get_resolvers(yaml_conf: YamlHelper) -> Dict[bytes, List[IPv4Address]]:
    """
    Get the configuration for the resolvers for specific domains
    """
    # parse resolvers
    lookup_servers = {}

    if not yaml_conf:
        return lookup_servers

    for entry in yaml_conf.get_list('resolvers'):
        domain, server_list = list(entry.items())[0]

        if not isinstance(server_list, list):
            server_list = [server_list]

        if not domain.endswith('.'):
            domain += "."

        servers = lookup_servers.setdefault(domain.encode(), list())

        for server in server_list:
            try:
                # if specified, use the fallback server
                if server.casefold() == "fallback".casefold():
                    server = server.lower()
                else:
                    # otherwise just add the server to the list
                    server = IPv4Address(server)
                    
                servers.append(server)
            except AddressValueError:
                logging.error(f"While getting resolvers, invalid IP address: {server}")
                continue

    # remove domains with no valid lookup servers
    return dict(filter(lambda each: len(each[1]) > 0, lookup_servers.items()))


def get_dns_server(yaml_conf: YamlHelper, fallbacks: List[IPv4Address]) -> DNSServer:
    """
    Configure and return a DNSServer instance to use
    """
    lookup_servers = get_resolvers(yaml_conf)

    try:
        server_address = yaml_conf.get_as("dns-server/ip", IPv4Address)
    except AddressValueError:
        logging.error("Invalid IP address specified for the DNS server!")
        raise
    return DNSServer(server_address, fallback_servers=fallbacks, lookup_servers=lookup_servers)
