from ipaddress import IPv4Address
import logging
import socket
import socketserver
from typing import *

from scapy.layers.dns import DNS


class DNSServer(socketserver.UDPServer, socketserver.ThreadingMixIn):
    fallback_servers: List[IPv4Address]
    lookup_servers: Dict[bytes, List[IPv4Address]]

    def __init__(self, address: IPv4Address, *, fallback_servers: List[IPv4Address], lookup_servers: Dict[bytes, List[IPv4Address]], port: int = 53):
        super().__init__((address.exploded, port), DNSServer._RequestHandler)
        self._client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._client_sock.settimeout(10)

        self.lookup_servers = lookup_servers
        self.fallback_servers = fallback_servers

    def close(self):
        self._client_sock.close()
        super().close()

    class _RequestHandler(socketserver.DatagramRequestHandler):
        def handle(self):
            req_raw, reply_sock = self.request
            client_addr = self.client_address

            req_packet = DNS(req_raw)
            requested_domain = req_packet.qd.qname
            logging.debug(f"Received request from {client_addr[0]} for {requested_domain.decode()}")

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
                    self.server._client_sock.sendto(req_raw, (remote_server.exploded, 53))

                    for _ in range(5):
                        try:
                            reply_raw, addr = self.server._client_sock.recvfrom(512)
                            if addr[0] == remote_server.exploded:
                                # data received was from the remote server we sent to
                                break

                        except socket.timeout:
                            logging.warning(f"Socket timed out while waiting for reply from {remote_server.exploded}")
                            continue
                    else:
                        raise Exception(f"Timed out too many times while waiting for reply from {remote_server.exploded}")

                    logging.debug(f"Reply received from {remote_server.exploded}")

                    reply_packet = DNS(reply_raw)
                    if reply_packet.rcode != 0:
                        # there was an error in getting the DNS data from this server
                        # so try another remote server
                        continue

                    reply_sock.sendto(reply_raw, client_addr)
                    logging.info(f"Received request for {requested_domain.decode()} from {client_addr[0]}, forwarded to {remote_server.exploded}")
                    break
                        
                except Exception as e:
                    logging.error(f"Request to {remote_server.exploded} failed: {e}")
                    continue
            else:
                # we could not retrieve DNS information from a remote server
                error_reply = req_packet
                error_reply.rcode = 2
                reply_sock.sendto(bytes(error_reply), client_addr)
                logging.info(f"Received request for {requested_domain.decode()} from {client_addr[0]}. Replied with SERVFAIL.")
