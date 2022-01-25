import dhcp as dhcp
from ipaddress import IPv4Address
import random
import socket
from typing import *
        
    
def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("172.31.134.165", 68))

        transaction_id = random.randbytes(4)
        inform_msg = dhcp.format_dhcp(
            transaction_id=transaction_id,
            options={
            53: b'\x08',    # code for DHCPINFORM message
            55: b'\x0F\x06' # request for domain and dns server
        })

        sock.sendto(inform_msg, ("255.255.255.255", 67))

        reply_data, addr = sock.recvfrom(512)
        print(dhcp.parse_dhcp(reply_data))
        


if __name__ == "__main__":
    main()
        