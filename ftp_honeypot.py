import os
from twisted.internet import reactor, protocol, endpoints
from twisted.protocols import basic
from twisted.python import log
import argparse

# Constants
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 2121

class SimpleFTPProtocol(basic.LineReceiver):
    delimiter = b"\r\n"
    maxAttempts = 3

    def connectionMade(self):
        client_ip = self.transport.getPeer().host
        client_port = self.transport.getPeer().port
        log_message = f"FTP NEW Connection - Client IP: {client_ip}, Port: {client_port}"
        log.msg(log_message)

    def lineReceived(self, line):
        log_message = f"Received data: {line.decode('utf-8')}"
        log.msg(log_message)

        line_str = line.decode("utf-8")
        command = line_str.split(" ")[0].upper()

        if command == "USER":
            self.userReceived = True
            self.sendLine(b"331 Username okay, need password")
        elif command == "PASS" and hasattr(self, "userReceived") and self.userReceived:
            self.attempts = getattr(self, "attempts", 0) + 1
            if self.attempts < self.maxAttempts:
                self.sendLine(b"530 Login incorrect")
                self.userReceived = False
            else:
                log_message = "Maximum attempts reached. Disconnecting client."
                log.msg(log_message)
                self.sendLine(b"530 Too many wrong attempts. Disconnecting.")
                self.transport.loseConnection()
        else:
            self.sendLine(b"500 Syntax error, command unrecognized")

    def sendLine(self, line):
        self.transport.write(line + self.delimiter)

    def connectionLost(self, reason):
        log_message = "Connection lost"
        log.msg(log_message)


class SimpleFTPFactory(protocol.ServerFactory):
    protocol = SimpleFTPProtocol


def start_honeypot(host, port, _):
    ftp_factory = SimpleFTPFactory()
    endpoint = endpoints.TCP4ServerEndpoint(reactor, port, interface=host)
    endpoint.listen(ftp_factory)
    print(f"FTP Honeypot started on {host}:{port}")


def stop_honeypot():
    try:
        reactor.callFromThread(reactor.stop)
    except Exception as e:
        print(f"Error stopping FTP honeypot: {e}")


if __name__ == "__main__":
    # Example usage (for standalone execution)
    parser = argparse.ArgumentParser(description="Run a simple FTP honeypot server.")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST, help="Host to bind the FTP server to.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind the FTP server to.")
    args = parser.parse_args()

    start_honeypot(args.host, args.port, {})