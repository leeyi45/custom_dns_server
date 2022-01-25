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


class QuestionRecord:
    """
    size field refers to the number of bytes it would take up stored in the regular DNS format
    """
    def __init__(self, qname: Union[str, bytes], qtype: bytes, qclass: bytes, size: int):
        if isinstance(qname, str):
            qname = qname.encode()

        self.qname = qname.strip()
        
        self.qtype = qtype
        self.qclass = qclass
        self.size = size

    def __len__(self) -> int:
        return self.size
    
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
            yield self.ttl.to_bytes(2, "big")
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

    def flag_val(val: bytes, flag: bool):
        return val if flag else 0

    header_0 = flag_val(0x80, qr)
    header_0 |= opcode << 3
    header_0 |= flag_val(0x04, aa)
    header_0 |= flag_val(0x02, tc)
    header_0 |= flag_val(0x01, rd)

    header_1 = flag_val(0x80, ra)
    header_1 |= rcode

    data = [trans_id, header_0, header_1]
    sections = [questions, answers, authority, additional]

    # append section lengths
    for section in sections:
        data.append(len(section).to_bytes(2, "big"))

    # then append sections
    for section in section:
        if not section:
            continue
        
        # dns has a weird compression thing that idk how to do yet
        # so uh
        for record in section:
            rdata = record.to_bytes()
            data.append(rdata)

    return b''.join(data)


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