from ipaddress import AddressValueError, IPv4Address
import logging
from scapy.layers.dns import DNS
import socket
import socketserver
from typing import *
import dns

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
            data, reply_sock = self.request
            client_addr = self.client_address

            packet = dns.parse_dns(data)
            requested_domain = packet['qn'][0].qname
            logging.info(f"Received request from {client_addr[0]} for {requested_domain.decode()}")

            def recvfrom() -> bytes:
                try:
                    return self.server._client_sock.recvfrom(512)[0]
                except Exception as e:
                    logging.error(f"Exception: {e}", exc_info=e)

                    reply = dict(packet)
                    reply['rcode'] = dns.SERVFAIL
                    return dns.format_dns(**reply)

            def server_generator():
                for domain, servers in self.server.lookup_servers.items():
                    if requested_domain.endswith(domain):
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
                reply_sock.sendto(reply, client_addr)
                break


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
