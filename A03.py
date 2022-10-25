import socket

from typing import Tuple

BUFFER_SIZE = 4096
SERVER_IP = "0.0.0.0"
SERVER_PORT = 5803

DEST_IP = "34.101.92.60"
DEST_PORT = 5353

class DNSHeader():
    def __init__(self, request_message: bytearray):
        self.id = int.from_bytes(request_message[0:2], "big")

        second_message_section = request_message[2:4]  # Get bits 16-31
        self.qr = (second_message_section[0] & 0x80) >> 7
        self.opcode = (second_message_section[0] & 0x78) >> 3
        self.aa = (second_message_section[0] & 0x4) >> 2
        self.tc = (second_message_section[0] & 0x2) >> 1
        self.rd = second_message_section[0] & 0x1
        self.ra = (second_message_section[1] & 0x80) >> 7
        self.z = (second_message_section[1] & 0x40) >> 6
        self.ad = (second_message_section[1] & 0x20) >> 5
        self.cd = (second_message_section[1] & 0x10) >> 4
        self.rcode = second_message_section[1] & 0x0F

        # Get counts (all counts have size of 2 bytes and are aligned to 2^n byte indexes)
        self.qdcount = int.from_bytes(request_message[4:6], "big")
        self.ancount = int.from_bytes(request_message[6:8], "big")
        self.nscount = int.from_bytes(request_message[8:10], "big")
        self.arcount = int.from_bytes(request_message[10:12], "big")

class DNSQuestion():
    def __init__(self, request_message: bytearray):
        self.qname = []
        self.pointer = 12  # DNS Question starts at Byte 12

        # Call QNAME decode function
        self.decode_qname(request_message)

        # Get QTYPE (size of QTYPE is 2 bytes). We use pointer because size of QNAME is not guaranteed/is variable
        self.qtype = int.from_bytes(request_message[self.pointer:self.pointer + 2], "big")
        self.pointer += 2

        # Get QCLASS (Size of QCLASS is 2 bytes, but it's value is usually 0x01)
        self.qclass = int.from_bytes(request_message[self.pointer: self.pointer + 2], "big")
        self.pointer += 2


    def decode_qname(self, request_message: bytearray):
        groups = []
        # Iterate through packet until null terminator (denotes end of QNAME section)
        while request_message[self.pointer] != 0:
            length = request_message[self.pointer] # QNAME group length
            self.pointer += 1

            groups.append(request_message[self.pointer:self.pointer + length].decode("ascii"))  # Group name string is encoded as ASCII
            self.pointer += length

        self.pointer += 1  # Increment pointer by 1 after null terminator
        self.qname = ".".join(groups)  # Join groups with "." to get DNS name

    # Function to access last pointer value from outside of object.
    # This is required since size of Question is not constant.
    def get_pointer(self):
        return self.pointer


class DNSResponse():
    # Same logic as QNAME decoding
    def decode_name(self, request_message: bytearray, offset: int):
        groups = []
        while request_message[offset] != 0:
            length = request_message[offset]
            offset += 1
            groups.append(request_message[offset:offset + length].decode("ascii"))
            offset += length
        offset += 1  # Increment pointer after null terminator
        return ".".join(groups)

    def __init__(self, request_message: bytearray, pointer: int):
        self.answers = []

        while request_message[pointer] != 0:
            answer = DNSAnswer()

            offset = request_message[pointer:pointer + 2]

            answer.name = self.decode_name(request_message, offset[1])
            pointer += 2

            answer.type = int.from_bytes(request_message[pointer:pointer + 2], "big")
            pointer += 2

            answer.class_ = int.from_bytes(request_message[pointer:pointer + 2], "big")
            pointer += 2

            answer.ttl = int.from_bytes(request_message[pointer:pointer + 4], "big")
            pointer += 4

            answer.dlength = int.from_bytes(request_message[pointer:pointer + 2], "big")
            pointer += 2

            answer.address = ".".join([str(octet) for octet in list(request_message[pointer:pointer + answer.dlength])])
            pointer += answer.dlength

            self.answers.append(answer)

class DNSAnswer():
    def __init__(self):
        self.name = ""
        self.type = 0
        self.class_ = 0
        self.ttl = 0
        self.dlength = 0
        self.address = ""

def request_parser(request_message_raw: bytearray, source_address: Tuple[str, int]) -> str:
    output_string = "=========================================================================\n"
    output_string += f"[Request from {source_address}]\n"
    output_string += "-------------------------------------------------------------------------\n"

    header = DNSHeader(request_message_raw)
    output_string += "HEADERS\n"
    output_string += f"Request ID: {header.id}\n"
    output_string += f"QR: {header.qr} | OPCODE: {header.opcode} | AA: {header.aa} | TC: {header.tc} | RD: {header.rd} | RA: {header.ra} | AD: {header.ad} | CD: {header.cd} | RCODE: {header.rcode}\n"
    output_string += f"Question Count: {header.qdcount} | Answer Count: {header.ancount} | Authority Count: {header.nscount} | Additional Count: {header.arcount}\n"

    question = DNSQuestion(request_message_raw)
    output_string += "-------------------------------------------------------------------------\n"
    output_string += "QUESTION\n"
    output_string += f"Domain Name: {question.qname} | QTYPE: {question.qtype} | QCLASS: {question.qclass}\n"
    output_string += "-------------------------------------------------------------------------\n"

    return output_string

def response_parser(response_mesage_raw: bytearray) -> str:
    output_string = ""
    output_string += f"[Response from DNS Server]\n"
    output_string += "-------------------------------------------------------------------------\n"

    # Reuse DNS Header logic
    header = DNSHeader(response_mesage_raw)
    output_string += "HEADERS\n"
    output_string += f"Request ID: {header.id}\n"
    output_string += f"QR: {header.qr} | OPCODE: {header.opcode} | AA: {header.aa} | TC: {header.tc} | RD: {header.rd} | RA: {header.ra} | AD: {header.ad} | CD: {header.cd} | RCODE: {header.rcode}\n"
    output_string += f"Question Count: {header.qdcount} | Answer Count: {header.ancount} | Authority Count: {header.nscount} | Additional Count: {header.arcount}\n"

    # Reuse DNS Question logic
    question = DNSQuestion(response_mesage_raw)
    output_string += "-------------------------------------------------------------------------\n"
    output_string += "QUESTION\n"
    output_string += f"Domain Name: {question.qname} | QTYPE: {question.qtype} | QCLASS: {question.qclass}\n"
    output_string += "-------------------------------------------------------------------------\n"

    # Decode DNS Answer (supports multiple answers, but not required for this assignment.)
    dns_answer = DNSResponse(response_mesage_raw, question.get_pointer())
    output_string += "ANSWER\n"
    for answer in dns_answer.answers:
        output_string += f"TYPE: {answer.type} | CLASS: {answer.class_} | TTL: {answer.ttl} | RDLENGTH: {answer.dlength}\n"
        output_string += f"IP Address: {answer.address}\n"

    output_string += "=========================================================================\n"

    return output_string

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sc:
        sc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sc.bind((SERVER_IP, SERVER_PORT))

        while True:
            inbound_message_raw, source_addr = sc.recvfrom(BUFFER_SIZE)
            print(request_parser(bytearray(inbound_message_raw), source_addr))

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forward_sc:
                forward_sc.sendto(inbound_message_raw, (DEST_IP, DEST_PORT))
                dns_response, _ = forward_sc.recvfrom(BUFFER_SIZE)

                print(response_parser(bytearray(dns_response)))

                sc.sendto(dns_response, source_addr)

# DO NOT ERASE THIS PART!
if __name__ == "__main__":
    main()
