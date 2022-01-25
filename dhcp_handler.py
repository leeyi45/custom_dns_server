from ipaddress import IPv4Address
import logging
from operator import attrgetter
import random
from scapy.all import conf, get_if_addr, sniff
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import IP
import socket
from typing import *

from yaml_helper import YamlHelper


class DHCPHandler:
    dhcp_server: IPv4Address
    force_broadcast: bool
    local_iface_addr: IPv4Address
    send_decline: bool
    use_network_broadcast: bool

    def __init__(self, conf_options: YamlHelper) -> None:
        # if the user specified a specific DHCP server, use that directly
        dhcp_server = conf_options.get('dhcp-options/dhcp-server')
        dhcp_server = None if not dhcp_server else IPv4Address(dhcp_server)

        send_decline = conf_options.get_bool('dhcp-options/send-decline', True) # check if we should send the decline message
        use_network_broadcast = conf_options.get("dhcp-options/use-network-broadcast")
        force_broacast = conf_options.get("dhcp-options/force-broadcast")

        if iface_addr := conf_options.get_as('dhcp-options/local-addr', IPv4Address):
            # if an IP address was specified, use that directly
            iface = conf.route.route(iface_addr)[0]

        elif iface := conf_options.get('dhcp-options/local-iface'):
            # else if an interface was specified, get its ip address
            iface_addr = None
        else:
            # if neither was specified use the default interface
            iface_addr = None
            iface = conf.iface

        self.local_iface_addr = iface_addr if iface_addr is not None else IPv4Address(get_if_addr(iface))

        if dhcp_server is None:
            # use full broadcast or just network broadcast
            if use_network_broadcast:
                dhcp_server = IPv4Address("255.255.255.255")
            else:
                dhcp_server = IPv4Address(conf.route.get_if_bcast(iface))

        self.force_broadcast = force_broacast
        self.dhcp_server = dhcp_server
        self.send_decline = send_decline
        self.use_network_broadcast = use_network_broadcast

    def get_dhcp_options(self) -> Optional[Dict[str, Any]]:
        """
        Try and contact a DHCP server to retrieve information about the local network

        The addr parameter is used initially. When the DHCP server is already known, we can use that IP instead
        """
        DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'
        transaction_id = random.randbytes(4) # generate a random transaction id

        def get_zeroes(count: int) -> bytes:
            """
            Returns a bytes object consisting of the desired number of zeroes
            """
            return int.to_bytes(0, count, "big")

        def process_options(options: Dict[int, bytes]) -> bytes:
            """
            Process the DHCP options format into a bytes object

            DHCP option format:
            1 byte opcode
            1 byte oplength
            option data
            """
            def inner():
                for code, opval in options.items():
                    yield int.to_bytes(code, 1, "big")
                    yield int.to_bytes(len(opval), 1, "big")
                    yield opval
                yield b'\xFF'
            return b''.join(inner())

        def send_message(addr: IPv4Address, options: Dict[int, bytes]):
            """
            Send the DHCP message with the given options to the specified address
            """

            # i honestly don't know how to use scapy to send DHCP requests, so
            # here it is manually coded
            data = [
                b'\x01', # opcode
                b'\x01', # htype
                b'\x06', # hlen
                b'\x00', # hops
                transaction_id,
                get_zeroes(4), # secs, flags
                get_zeroes(16), # other address fields
                b'\x0A\x00\x27\x00\x00\x13', # mac address
                get_zeroes(10), # padding for mac address
                get_zeroes(192), # 192 octets of 0s
                DHCP_MAGIC_COOKIE
            ]

            data.append(process_options(options))
            sock.sendto(b''.join(data), (addr.exploded, 67))        

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(10)
            sock.bind((self.local_iface_addr.exploded, 68))

            send_message(self.dhcp_server, {
                53: b'\x01',    # indicate dhcp discover
                55: b'\x0F\x06' # request for domain and dns server
            })
            logging.info("Sent DHCP discover message")

            def packet_filter(p):
                # make sure the captured packet has IP and DHCP data
                if IP not in p or DHCP not in p:
                    return False

                # make sure the IP packet wasn't sent by ourselves
                ip_data = p[IP]
                return ip_data.src != self.local_iface_addr

            capture = sniff(count=1, lfilter=packet_filter)[0] # I think Windows eats DHCP messages, so let's use scapy instead
            relay_agent = capture[IP].src
            
            logging.debug(f"{capture[DHCP].show(dump=True)} received from {relay_agent}")

            # parse the DHCP options
            offer_options = {}
            for opval in capture[DHCP].options:
                opkey = opval[0]

                if opkey == "end":
                    break

                offer_options[opkey] = opval[1:] if len(opval) > 2 else opval[1]

            dhcp_server_temp = IPv4Address(offer_options['server_id'])
            logging.info("Received DHCP offer from " + dhcp_server_temp.exploded)

            if not self.dhcp_server and not self.force_broadcast:
                # if we want to force using the broadcast addresses, don't change
                # the dhcp_server entry
                self.dhcp_server = dhcp_server_temp

            if self.send_decline:
                # send dhcp decline if specified
                send_message(dhcp_server_temp, {
                    53: b'\x04' # indicate dhcp decline
                })
                logging.info(f"Sent DHCP decline message to {dhcp_server_temp}")

            local_domain = offer_options['domain'] # retrieve the local domain name
            local_dns = list(map(IPv4Address, offer_options['name_server'])) # retrieve the network's dns servers

            logging.info(f"Options retrieved from {dhcp_server_temp.exploded}:\n\tLocal Domain: {local_domain.decode()}\n\tLocal DNS Servers: [{', '.join(map(attrgetter('exploded'), local_dns))}]")

            return {
                "local_domain": local_domain, 
                "local_dns": local_dns,
                "local_dhcp": dhcp_server_temp
            }

