from ipaddress import IPv4Address
import itertools
import logging
from operator import attrgetter
import random
import socket
import platform
from typing import *

from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.layers.dhcp import BOOTP, DHCP

DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'


def parse_dhcp(data: bytes) -> Dict[str, Any]:
    """
    Parse a DHCP reply
    """
    def to_int(val):
        return int.from_bytes(val, "big")

    fields = {
        'opcode': (1, to_int),        
        'htype':  (1, to_int),
        'hlen':   (1, to_int),
        'hops':   (1, to_int),
        'trans_id': (4, None),
        'secs':   (2, None),
        'flags':  (2, None),
        'ciaddr': (4, IPv4Address),
        'yiaddr': (4, IPv4Address),
        'siaddr': (4, IPv4Address),
        'giaddr': (4, IPv4Address),
        'chaddr': (16, None),
        'sname':  (64, None),
        'file':   (128, None)
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
                hops: bytes   = b'\x00',
                trans_id: bytes = None, 
                secs: bytes   = b'\x00\x00',
                flags: bytes  = b'\x00\x00', 
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
    if not trans_id:
        trans_id = random.randbytes(4)
    
    data = [opcode, htype, hlen, hops, trans_id, secs, flags, ciaddr.packed, yiaddr.packed, 
            siaddr.packed, giaddr.packed, chaddr, sname, file, DHCP_MAGIC_COOKIE]

    if options:
        for code, opval in options.items():
            data.append(int.to_bytes(code, 1, "big"))
            data.append(int.to_bytes(len(opval), 1, "big"))
            data.append(opval)
        data.append(b'\xFF')

    return b''.join(data)


def get_dhcp_options(dst_addr: IPv4Address, iface_name: str = None) -> Dict[str, Any]:
    """
    Try and contact a DHCP server with a DHCPINFORM to retrieve information about the local network
    
    If the DHCP server's IP address is already known, send the DHCPINFORM straight to it by giving it
    as the address

    Otherwise give the global broadcast IP or the subnet broadcast IP, specifying which interface to use
    """
    if not iface_name:
        iface_name, iface_addr, _ = conf.route.route(dst_addr.exploded)
    else:
        if platform.system() == "Windows":
            # Because Windows has to be different
            from scapy.arch.windows import IFACES
            iface_addr = get_if_addr(IFACES.dev_from_name(iface_name))
        else:
            iface_addr = get_if_addr(iface_name)
    
    logging.info(f"Selected {iface_name} with address {iface_addr} to send DHCP request")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(10)
        sock.bind((iface_addr, 68))

        for _ in range(5):
            # if the receive fails 5 times, try sending again
            trans_id = random.randint(1, 4294967295)
            inform_packet = BOOTP(xid=trans_id) / DHCP(options=[('message-type', 'inform'), ('param_req_list', 15, 6), 'end'])
            sock.sendto(bytes(inform_packet), (dst_addr.exploded, 67))
            logging.debug(f"Sent DHCPINFORM to {dst_addr.exploded}")

            for _ in range(5):
                # try to receive from the socket 5 times
                try:
                    reply_raw, relay_agent = sock.recvfrom(512)
                    reply_packet = BOOTP(reply_raw)

                    if reply_packet[BOOTP].xid == trans_id:
                        # make sure that we're talking to the correct DHCP server
                        # by checking the transaction id
                        logging.debug(f"{reply_packet.show(dump=True)} received from {relay_agent}")
                        break
                except socket.timeout:
                    continue
            else:
                continue
            break
        else:
            # if sending fails to get any response 5 times, then raise this exception
            raise Exception("Failed to get DHCP options!")
        
        reply_options = dict(map(lambda each: each if len(each) == 2 else (each[0], each[1:]), itertools.takewhile(lambda x: x != 'end', reply_packet[DHCP].options)))

        dhcp_server_temp = IPv4Address(reply_options['server_id'])
        logging.info("Received DHCPACK from " + dhcp_server_temp.exploded)

        local_domain = reply_options['domain']    # retrieve the local domain name
        local_dns = list(map(IPv4Address, reply_options['name_server'])) # retrieve the network's dns servers

        logging.info(f"Options retrieved from {dhcp_server_temp.exploded}:\n\tLocal Domain: {local_domain.decode()}\n\tLocal DNS Servers: [{', '.join(map(attrgetter('exploded'), local_dns))}]")

        return {
            "local_domain": local_domain, 
            "local_dns": local_dns,
            "local_dhcp": dhcp_server_temp
        }