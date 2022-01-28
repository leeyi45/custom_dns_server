from ipaddress import IPV4LENGTH, IPV6LENGTH, IPv4Address, IPv6Address
import random
from tracemalloc import start
from typing import *

NOERROR = 0
FORMERROR = 1
SERVFAIL = 2
NXDOMAIN = 3
NOTIMP = 4
REFUSED = 5

QUERY = 0
IQUERY = 1
STATUS = 2

A = 1
NS = 2
CNAME = 5
SOA = 6
PTR = 12
MX = 15
AAAA = 28


class QuestionRecord:
    """
    size field refers to the number of bytes it would take up stored in the regular DNS format
    """
    def __init__(self, qname: Union[str, bytes], qtype: bytes, qclass: bytes):
        if isinstance(qname, str):
            qname = qname.encode()

        self.qname = qname.strip()
        
        self.qtype = qtype
        self.qclass = qclass

    def __repr__(self):
        return f'<QuestionRecord: qname={self.qname.decode()}, qtype={self.qtype}, qclass={self.qclass}>'
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Tuple[Any, int]:
        """
        Parses the provided bytes into a QuestionRecord
        
        Returns a tuple including the record and the number of bytes read
        """
        domain_data = []

        index = 0
        while index < len(data):
            domain_len = data[index]

            if domain_len == 0:
                break

            index += 1
            domain_data.append(data[index:index + domain_len])
            index += domain_len

        qtype = int.from_bytes(data[index:index + 2], "big")
        index += 2
        qclass = int.from_bytes(data[index:index + 2], "big")
        index += 2

        return cls(b'.'.join(domain_data), qtype, qclass, index), index            

    def to_bytes(self) -> bytes:
        """
        Convert the question record into byte format
        """
        def yielder():
            for domain in self.qname.split(b'.'):
                yield len(domain).to_bytes(1, "big")
                yield domain
            yield b'\x00'
            yield self.qtype
            yield self.qclass
        
        return b''.join(yielder())

    
class AnswerRecord:
    def __init__(self, rname: Union[str, bytes], rtype: int, rclass: int, ttl: int, rdata: bytes = b''):
        if isinstance(rname, str):
            rname = rname.encode()

        self.rname = rname.strip()
        
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata
    
    def __repr__(self):
        return f'<AnswerRecord: rname={self.rname}, rtype={self.rtype},' +\
        f'rclass={self.rclass}, ttl={self.ttl}, rdata={self.rdata}>'

    @classmethod
    def from_bytes(cls, data: bytes) -> Tuple[Any, int]:
        """
        Parses the provided bytes into a QuestionRecord
        
        Returns a tuple including the record and the number of bytes read
        """
        domain_data = []

        index = 0
        while index < len(data):
            domain_len = data[index]
            index += 1

            if domain_len == 0:
                break

            domain_data.append(data[index:index + domain_len])
            index += domain_len

        def read_field(length: int) -> int:
            nonlocal index

            value = data[index:index + length]
            index += length
            return int.from_bytes(value, "big")

        rtype = read_field(2)
        rclass = read_field(2)
        ttl = read_field(2)
        rdlength = read_field(2)
        rdata = data[index:index + rdlength]
        index += rdlength

        return AnswerRecord(b'.'.join(domain_data), rtype, rclass, ttl, rdata), index

    def to_bytes(self) -> bytes:
        def yielder():
            for domain in self.rname.split(b'.'):
                yield len(domain).to_bytes(1, "big")
                yield domain
            yield b'\x00'
            yield self.rtype
            yield self.rclass
            yield self.ttl.to_bytes(4, "big")
            yield len(self.rdata).to_bytes(2, "big")
            yield self.rdata
        
        return b''.join(yielder())

def format_dns(
        trans_id: bytes = None,
        qr:       bool = False,
        opcode:   int =  QUERY,
        aa:       bool = False,
        tc:       bool = False,
        rd:       bool = False,
        ra:       bool = False,
        rcode:    int  = NOERROR,
        questions: List[QuestionRecord] = None,
        answers:   List[AnswerRecord] = None,
        authority: List[AnswerRecord] = None,
        additional: List[AnswerRecord] = None
    ) -> bytes:

    def flag_val(val: bytes, flag: bool) -> int:
        return val if flag else 0

    if not trans_id:
        trans_id = random.randbytes(2)

    header_0 = flag_val(0x80, qr)
    header_0 |= (opcode << 3)
    header_0 |= flag_val(0x04, aa)
    header_0 |= flag_val(0x02, tc)
    header_0 |= flag_val(0x01, rd)

    header_1 = flag_val(0x80, ra)
    header_1 |= rcode

    data = [trans_id, header_0.to_bytes(1, "big"), header_1.to_bytes(1, "big")]
    sections = [answers, authority, additional]

    # append section lengths
    if questions:
        data.append(len(questions).to_bytes(2, "big"))
    else:
        data.append(b'\x00\x00')

    for section in sections:
        if section:
            data.append(len(section).to_bytes(2, "big"))
        else:
            data.append(b'\x00\x00')
    
    index = 12
    domain_names = {}

    if questions:
        for question in questions:
            qname = question.qname
            
            if qname not in domain_names:
                for each in qname.split(b'.'):
                    data.append(len(each).to_bytes(1, "big"))
                    data.append(each)
                    index += 1 + len(each)
                
                data.append(b'\x00')
                index += 1

                # domain_names[qname] = index
            
            data.append(int.to_bytes(question.qtype, 2, "big"))
            data.append(int.to_bytes(question.qclass, 2, "big"))

    # then append sections
    for section in sections:
        if not section:
            continue
        
        for record in section:
            rname = record.rname


            data.append(rdata)
    return b''.join(data)


class DNSParser:
    data: bytes
    domain_names: Dict[int, bytes]
    index: int

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.domain_names = {}
        self.index = 0

    def _get_bytes(self, count: int, increment: bool = True) -> bytes:
        value = self.data[self.index:self.index + count]

        if increment:
            self.index += count
        return value

    def _get_int(self, count: int, increment: bool = True) -> int:
        return int.from_bytes(self._get_bytes(count, increment), "big")

    def _get_domain(self, start_index: int, ptr_mode: bool) -> bytes:
        if start_index in self.domain_names:
            return self.domain_names[start_index]

        domain_data = []
        index = start_index
        consumed = 0

        while index < len(self.data):
            length = self.data[index]
            index += 1
            consumed += 1

            if (length & 0xC0):
                # is a pointer
                pointed_index = self.data[index]
                consumed += 1
                domain_data.append(self._get_domain(pointed_index, True))
                break
            elif length == 0:
                break
            else:
                domain_data.append(self.data[index:index + length])
                index += length
                consumed += length
                continue
        
        if not ptr_mode:
            self.index += consumed

        full_domain = b'.'.join(domain_data)
        self.domain_names[start_index] = full_domain
        return full_domain

    def _get_rdata(self, rtype: int, rdata: bytes) -> Any:
        def parser(data: bytes) -> bytes:
            return self._get_domain(self.index, True)

        parsers = {
            A: IPv4Address,
            AAAA: IPv6Address,
            MX: parser,
            NS: parser,
            CNAME: parser
        }

        return parsers.get(rtype, lambda x: x)(rdata)

    def parse_header(self) -> Dict[str, int]:
        header = {
            'trans_id': self._get_int(2),
            'qr': (self.data[self.index] & 0x80)     >> 7, # 0b1000_1000
            'opcode': (self.data[self.index] & 0x78) >> 3, # 0b0111_1000
            'aa': (self.data[self.index] & 0x04)     >> 2, # 0b0000_0100
            'tc': self.data[self.index] & 0x02       >> 1, # 0b0000_0010
            'rd': self.data[self.index] & 0x01,            # 0b0000_0001
            'ra': self.data[self.index + 1] & 0x80   >> 7, # 0b1000_0000
            'rcode': self.data[self.index + 1] & 0x0F      # 0b0000_1111
        }

        self.index += 2
        return header

    def parse(self) -> Dict[str, Any]:
        # question, answer, authoritative, additional
        sections = ["an", "aa_sec", "ad"]
        
        packet = self.parse_header()
        packet['qnlen'] = self._get_int(2)

        for section in sections:
            packet[section + "len"] = self._get_int(2)

        # parse questions
        packet['qn'] = []

        for _ in range(packet['qnlen']):
            # print(f'{self.index}, {self.data[self.index:self.index + 2]}')
            domain_name = self._get_domain(self.index, False)
            # print(self.index)

            qtype = self._get_int(2)
            qclass = self._get_int(2)

            record = QuestionRecord(domain_name, qtype, qclass)
            packet['qn'].append(record)

        # parse other sections
        for section in sections:
            packet[section] = []

            for _ in range(packet[section + "len"]):

                # print(f'{self.index}, {self.data[self.index:self.index + 2]}')
                domain_name = self._get_domain(self.index, False)
                # print(self.index)

                rtype = self._get_int(2)
                rclass = self._get_int(2)
                ttl = self._get_int(4)
                rlength = self._get_int(2)
                rdata = self._get_rdata(rtype, self._get_bytes(rlength))

                record = AnswerRecord(domain_name, rtype, rclass, ttl, rdata)
                packet[section].append(record)

        return packet


def parse_dns(data: bytes) -> Dict[str, Any]:
    """
    Parse a DNS message
    """
    # question, answer, authoritative, additional
    sections = ["an", "aa", "ad"]
    
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

    packet['qnlen'] = int.from_bytes(data[4:6], "big")

    index = 6
    for section in sections:
        packet[section + "len"] = int.from_bytes(data[index:index + 2], "big")
        index += 2

    # parse questions
    packet['qn'] = []

    for _ in range(packet['qnlen']):
        record, size = QuestionRecord.from_bytes(data[index:])
        index += size
        packet['qn'].append(record)

    # parse other sections
    for section in sections:
        packet[section] = []

        for _ in range(packet[section + "len"]):
            record, size = AnswerRecord.from_bytes(data[index:])
            index += size
            packet[section].append(record)
    
    return packet