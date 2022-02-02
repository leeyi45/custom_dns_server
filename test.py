import socket

from scapy.all import *
from dns import DNSParser, format_dns, QuestionRecord


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        #  sock.bind(('127.0.0.1', 0))

        addr = '8.8.8.8'
        iface_name, iface_addr, gateway = conf.route.route(addr)

        print(f"Sending via {iface_name}")

        sock.bind((iface_addr, 0))
    
        questions = [ 
           QuestionRecord("nus.edu.sg", 0x0002, 1) 
        ]
        dns_send = format_dns(questions=questions)

        sock.sendto(dns_send, (addr, 53))
        data, addr = sock.recvfrom(512)

        packet = DNSParser(data).parse()

        print(packet["qnlen"])
        print(packet["anlen"])

        return 
        for record in packet['sections']['ad']:
            print(record)


if __name__ == "__main__":
    main()
