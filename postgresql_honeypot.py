import os
from twisted.internet import reactor, protocol, endpoints
from twisted.python import log
import argparse
from struct import unpack

# Constants
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5432

class SimplePostgreSQLProtocol(protocol.Protocol):
    def connectionMade(self):
        self.state = "startup"
        client_ip = self.transport.getPeer().host
        client_port = self.transport.getPeer().port
        log_message = f"PostgreSQL NEW Connection - Client IP: {client_ip}, Port: {client_port}"
        log.msg(log_message)

    def dataReceived(self, data):
        if self.state == "startup":
            self.handleStartupMessage(data)
        elif self.state == "authentication":
            self.handleAuthenticationMessage(data)

    def handleStartupMessage(self, data):
        if len(data) < 8:
            return
        (length,) = unpack("!I", data[:4])
        if length > len(data):
            return
        message_items = data[4:length].decode("utf-8", "replace").split("\x00")
        startup_message = {}
        it = iter(message_items)
        for item in it:
            if item:
                key = item
                value = next(it, "")
                startup_message[key] = value
        self.username = startup_message.get("user")
        self.database = startup_message.get("database")
        if self.username:
            log_message = f"PostgreSQL Connection Startup - Username: {self.username}, Database: {self.database or 'Not provided'}"
            log.msg(log_message)
            self.state = "authentication"
            self.sendAuthenticationRequest()

    def handleAuthenticationMessage(self, data):
        if len(data) > 5 and data[0:1] == b"p":
            password = data[5:].decode("utf-8", "replace").split("\x00")[0]
            log_message = f"PostgreSQL Authentication - Password: {password}"
            log.msg(log_message)
            self.sendAuthenticationFailure()

    def sendAuthenticationRequest(self):
        self.transport.write(b"R\x00\x00\x00\x08\x00\x00\x00\x03")

    def sendAuthenticationFailure(self):
        username_display = self.username if self.username else "unknown"
        message_type = b"E"
        fields = [
            (b"S", b"FATAL"),
            (b"C", b"28P01"),
            (
                b"M",
                f'password authentication failed for user "{username_display}"'.encode("utf-8"),
            ),
            (b"\x00", b""),
        ]
        message_content = b"".join([code + value + b"\x00" for code, value in fields])
        message_length = 4 + len(message_content)
        message = message_type + message_length.to_bytes(4, "big") + message_content
        self.transport.write(message)
        self.transport.loseConnection()


class SimplePostgreSQLFactory(protocol.ServerFactory):
    protocol = SimplePostgreSQLProtocol


def start_honeypot(host, port, _):
    postgresql_factory = SimplePostgreSQLFactory()
    endpoint = endpoints.TCP4ServerEndpoint(reactor, port, interface=host)
    endpoint.listen(postgresql_factory)
    print(f"PostgreSQL Honeypot started on {host}:{port}")


def stop_honeypot():
    try:
        reactor.callFromThread(reactor.stop)
    except Exception as e:
        print(f"Error stopping PostgreSQL honeypot: {e}")


if __name__ == "__main__":
    # Example usage (for standalone execution)
    parser = argparse.ArgumentParser(description="Run a simple PostgreSQL honeypot server.")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST, help="Host to bind the PostgreSQL server to.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind the PostgreSQL server to.")
    args = parser.parse_args()

    start_honeypot(args.host, args.port, {})