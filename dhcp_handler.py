from ipaddress import IPv4Address
import logging
from operator import attrgetter
import random
from scapy.all import conf, get_if_addr
import socket
from typing import *

import dhcp as dhcp
from yaml_helper import YamlHelper


class DHCPHandler:
    dhcp_server_addr: IPv4Address
    force_broadcast: bool
    local_iface_addr: IPv4Address
    send_decline: bool
    use_network_broadcast: bool

    def __init__(self, conf_options: YamlHelper) -> None:
        # if the user specified a specific DHCP server, use that directly
        dhcp_server = conf_options.get('dhcp-options/dhcp-server')
        dhcp_server = None if not dhcp_server else IPv4Address(dhcp_server)

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
        self.dhcp_server_addr = dhcp_server
        self.use_network_broadcast = use_network_broadcast

    def get_dhcp_options(self) -> Optional[Dict[str, Any]]:
        """
        Try and contact a DHCP server to retrieve information about the local network

        The addr parameter is used initially. When the DHCP server is already known, we can use that IP instead
        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(10)
            sock.bind(('172.31.134.165', 68))

            transaction_id = random.randbytes(4) # generate a random transaction id
            inform_msg = dhcp.format_dhcp(
                transaction_id=transaction_id,
                options={
                53: b'\x08',    # code for DHCPINFORM message
                55: b'\x0F\x06' # request for domain and dns server
            })

            sock.sendto(inform_msg, (self.dhcp_server_addr.exploded, 67))

            reply_raw, relay_agent = sock.recvfrom(512)
            logging.debug(f"{reply_raw} received from {relay_agent}")

            reply_data = dhcp.parse_dhcp(reply_raw)

            dhcp_server_temp = IPv4Address(reply_data['options'][54])
            logging.info("Received DHCP offer from " + dhcp_server_temp.exploded)

            if not self.dhcp_server_addr and not self.force_broadcast:
                # if we want to force using the broadcast addresses, don't change
                # the dhcp_server entry
                self.dhcp_server_addr = dhcp_server_temp

            local_domain = reply_data['options'][15] # retrieve the local domain name
            local_dns = reply_data['options'][6] # retrieve the network's dns servers
            local_dns = [IPv4Address(local_dns[i:i+4]) for i in range(0, len(local_dns), 4)]

            logging.info(f"Options retrieved from {dhcp_server_temp.exploded}:\n\tLocal Domain: {local_domain.decode()}\n\tLocal DNS Servers: [{', '.join(map(attrgetter('exploded'), local_dns))}]")

            return {
                "local_domain": local_domain, 
                "local_dns": local_dns,
                "local_dhcp": dhcp_server_temp
            }
