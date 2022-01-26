from ipaddress import IPv4Address
import logging
from operator import attrgetter
import random
import socket
from typing import *

from scapy.all import conf, get_if_addr
from scapy.layers.dhcp import BOOTP, DHCP

from dhcp.options import DHCP_MSG_TYPE, DHCP_PARAM_REQ, DHCP_SERV_ID, DOMAIN_NAME, DOMAIN_NAME_SERVER
from dhcp.msg import DHCPDISCOVER, DHCPINFORM

DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'


def parse_dhcp(data: bytes) -> Dict[str, Any]:
    """
    Parse a DHCP reply
    """
    fields = {
        'opcode': (1, None),        
        'htype': (1, None),
        'hlen':  (1, None),
        'hops':  (1, None),
        'transaction_id': (4, None),
        'secs': (2, None),
        'flags': (2, None),
        'ciaddr': (4, IPv4Address),
        'yiaddr': (4, IPv4Address),
        'siaddr': (4, IPv4Address),
        'giaddr': (4, IPv4Address),
        'chaddr': (16, None),
        'sname': (64, None),
        'file': (128, None)
    }

    packet = {}

    index = 0
    for key, field in fields.items():
        length, converter = field
        value = data[index: index + length]
        index += length

        if converter:
            value = converter(value)

        packet[key] = value
    
    if data[index:index + 4] != DHCP_MAGIC_COOKIE:
        raise ValueError("Invalid DHCP packet - Magic cookie did not match")

    index += 4 # skip the magic cookie
    options = {}

    while index < len(data):
        key = data[index]

        if key == 255:
            break

        oplen = data[index + 1]
        index += 2
        options[key] = data[index:index + oplen]
        index += oplen

    packet['options'] = options
    return packet


def format_dhcp(opcode: bytes = b'\x01', 
                htype: bytes  = b'\x01', 
                hlen: bytes   = b'\x06', 
                hops: bytes  = b'\x00',
                transaction_id: bytes = None, 
                secs: bytes  = b'\x00\x00',
                flags: bytes = b'\x00\x00', 
                ciaddr: IPv4Address = IPv4Address('0.0.0.0'), 
                yiaddr: IPv4Address = IPv4Address('0.0.0.0'), 
                siaddr: IPv4Address = IPv4Address('0.0.0.0'), 
                giaddr: IPv4Address = IPv4Address('0.0.0.0'),
                chaddr: bytes = b'\x00' * 16,
                sname: bytes  = b'\x00' * 64,
                file: bytes   = b'\x00' * 128,
                options: Dict[int, bytes] = None) -> bytes:
    """
    Format a DHCP message
    """
    if not transaction_id:
        transaction_id = random.randbytes(4)
    
    data = [opcode, htype, hlen, hops, transaction_id, secs, flags, ciaddr.packed, yiaddr.packed, 
            siaddr.packed, giaddr.packed, chaddr, sname, file, DHCP_MAGIC_COOKIE]

    if options:
        for code, opval in options.items():
            data.append(int.to_bytes(code, 1, "big"))
            data.append(int.to_bytes(len(opval), 1, "big"))
            data.append(opval)
        data.append(b'\xFF')

    return b''.join(data)


def get_dhcp_options(dhcp_server: IPv4Address) -> Dict[str, Any]:
    """
    Try and contact a DHCP server with a DHCPINFORM to retrieve information about the local network
    
    If the DHCP server's IP address is already known, send the DHCPINFORM straight to it by giving it
    as the address

    Otherwise give the global broadcast IP or the subnet broadcast IP
    """

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(10)
        sock.bind(('10.249.37.192', 68))

        transaction_id = random.randbytes(4) # generate a random transaction id
        inform_msg = format_dhcp(
            transaction_id=transaction_id,
            options={
            DHCP_MSG_TYPE: DHCPDISCOVER, # code for DHCPINFORM message
            DHCP_PARAM_REQ: b'\x0F\x06' # request for domain and dns server
        })

        sock.sendto(inform_msg, (dhcp_server.exploded, 67))

        reply_raw, relay_agent = sock.recvfrom(512)
        logging.debug(f"{reply_raw} received from {relay_agent}")

        reply_data = parse_dhcp(reply_raw)

        dhcp_server_temp = IPv4Address(reply_data['options'][DHCP_SERV_ID])
        logging.info("Received DHCPACK from " + dhcp_server_temp.exploded)

        local_domain = reply_data['options'][DOMAIN_NAME] # retrieve the local domain name
        local_dns = reply_data['options'][DOMAIN_NAME_SERVER]     # retrieve the network's dns servers
        local_dns = [IPv4Address(local_dns[i:i+4]) for i in range(0, len(local_dns), 4)]

        logging.info(f"Options retrieved from {dhcp_server_temp.exploded}:\n\tLocal Domain: {local_domain.decode()}\n\tLocal DNS Servers: [{', '.join(map(attrgetter('exploded'), local_dns))}]")

        return {
            "local_domain": local_domain, 
            "local_dns": local_dns,
            "local_dhcp": dhcp_server_temp
        }