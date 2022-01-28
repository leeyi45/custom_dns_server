import socket

from dns import DNSParser, format_dns, QuestionRecord


def main():
    # with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    #     #  sock.bind(('127.0.0.1', 0))

    #     questions= [ 
    #        QuestionRecord("nus.edu.sg", 0x000F, 1) 
    #     ]
    #     dns_send = format_dns(questions=questions)

    with open('dns_reply.bin', 'rb') as file:
        data = file.read()
        packet = DNSParser(data).parse()

        print(packet)
        print(packet['ad'])


if __name__ == "__main__":
    main()
