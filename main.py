import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import socket
import copy

sock = socket.socket(type=socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 53))
cache = dict()


def resolve(query):
    if query in cache:
        return cache[query]
    message = dns.message.make_query(qname=query, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN)
    for root in roots:
        response = resolve_recursive(message, str(root))
        if response is not None:
            cache[query] = response
            return response
    return None


def resolve_recursive(query, parent):
    response = dns.query.udp(q=query, where=parent, raise_on_truncation=False)
    if response:
        if response.answer:
            return response
        for additional in response.additional:
            if additional.rdtype == 1:
                for data in additional:
                    new_response = resolve_recursive(query, str(data))
                    if new_response:
                        return new_response
    return response


if __name__ == "__main__":
    with open('./root_hints.txt') as f:
        roots = f.read().splitlines()
    try:
        while True:
            message, _, domain = dns.query.receive_udp(sock)
            query = str(message.question[0]).split()[0]
            response = copy.copy(message)
            result = resolve(dns.name.from_text(query))
            if result is not None:
                response.answer = result.answer
                response.flags |= dns.flags.QR | dns.flags.RA
                if response.flags & dns.flags.AD:
                    response.flags ^= dns.flags.AD
            dns.query.send_udp(sock, message, domain)
    except KeyboardInterrupt:
        sock.close()
        exit(0)
