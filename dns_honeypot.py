import os
from twisted.internet import reactor, protocol
from twisted.names import dns, server
from twisted.python import log
import argparse

# Constants
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5353

class SimpleDNSProtocol(protocol.DatagramProtocol):
    def datagramReceived(self, datagram, address):
        message = dns.Message()
        try:
            message.fromStr(datagram)
        except (EOFError, dns.UnknownOpcode):
            return
        for query in message.queries:
            self.logQuery(query, address)
            response = self.createResponse(message, query)
            self.transport.write(response.toStr(), address)

    def logQuery(self, query, address):
        query_name_str = (
            query.name.name.decode() if isinstance(query.name.name, bytes) else query.name.name
        )
        log_message = (
            f"DNS Query Received - Query Name: {query_name_str}, Type: {dns.QUERY_TYPES.get(query.type, 'UNKNOWN')}, "
            f"Class: {dns.QUERY_CLASSES.get(query.cls, 'UNKNOWN')}, From: {address}"
        )
        log.msg(log_message)

    def createResponse(self, message, query):
        response = dns.Message(id=message.id, answer=1)
        response.queries = [query]
        query_name_str = (
            query.name.name.decode() if isinstance(query.name.name, bytes) else query.name.name
        )
        if query.type == dns.A:
            answer = dns.RRHeader(
                name=query_name_str,
                type=dns.A,
                cls=query.cls,
                ttl=60,
                payload=dns.Record_A(address="127.0.0.1"),
            )
            response.answers.append(answer)
        elif query.type == dns.AAAA:
            answer = dns.RRHeader(
                name=query_name_str,
                type=dns.AAAA,
                cls=query.cls,
                ttl=60,
                payload=dns.Record_AAAA(address="::1"),
            )
            response.answers.append(answer)
        elif query.type == dns.TXT:
            answer = dns.RRHeader(
                name=query_name_str,
                type=dns.TXT,
                cls=query.cls,
                ttl=60,
                payload=dns.Record_TXT(data=["dummy response"]),
            )
            response.answers.append(answer)
        elif query.type == dns.MX:
            answer = dns.RRHeader(
                name=query_name_str,
                type=dns.MX,
                cls=query.cls,
                ttl=60,
                payload=dns.Record_MX(preference=10, exchange="mail.example.com"),
            )
            response.answers.append(answer)
        elif query.type == dns.CNAME:
            answer = dns.RRHeader(
                name=query_name_str,
                type=dns.CNAME,
                cls=query.cls,
                ttl=60,
                payload=dns.Record_CNAME(name="cname.example.com"),
            )
            response.answers.append(answer)
        elif query.type == dns.NS:
            answer = dns.RRHeader(
                name=query_name_str,
                type=dns.NS,
                cls=query.cls,
                ttl=60,
                payload=dns.Record_NS(name="ns.example.com"),
            )
            response.answers.append(answer)
        elif query.type == dns.SOA:
            answer = dns.RRHeader(
                name=query_name_str,
                type=dns.SOA,
                cls=query.cls,
                ttl=60,
                payload=dns.Record_SOA(
                    mname="ns.example.com",
                    rname="hostmaster.example.com",
                    serial=12345,
                    refresh=3600,
                    retry=600,
                    expire=86400,
                    minimum=3600,
                ),
            )
            response.answers.append(answer)
        elif query.type == dns.PTR:
            answer = dns.RRHeader(
                name=query_name_str,
                type=dns.PTR,
                cls=query.cls,
                ttl=60,
                payload=dns.Record_PTR(name="ptr.example.com"),
            )
            response.answers.append(answer)
        else:
            log.msg(f"Received unsupported DNS query type: {query.type}")
        return response

class SimpleDNSServerFactory(server.DNSServerFactory):
    def __init__(self, protocol):
        clients = [protocol]
        super(SimpleDNSServerFactory, self).__init__(clients=clients)

def start_honeypot(host, port, _):
    dns_protocol = SimpleDNSProtocol()
    dns_factory = SimpleDNSServerFactory(dns_protocol)
    reactor.listenUDP(port, dns_protocol, interface=host)
    reactor.listenTCP(port, dns_factory, interface=host)
    print(f"DNS Honeypot started on {host}:{port}")

def stop_honeypot():
    try:
        reactor.callFromThread(reactor.stop)
    except Exception as e:
        print(f"Error stopping DNS honeypot: {e}")

if __name__ == "__main__":
    # Example usage (for standalone execution)
    parser = argparse.ArgumentParser(description="Run a simple DNS honeypot server.")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST, help="Host to bind the DNS server to.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind the DNS server to.")
    args = parser.parse_args()

    start_honeypot(args.host, args.port, {})