import os
from twisted.internet import reactor, endpoints, defer
from twisted.conch.ssh import factory, keys, userauth, connection, transport
from twisted.cred import portal, credentials, error
from twisted.logger import textFileLogObserver
from twisted.python import log
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from zope.interface import implementer
import argparse

# Constants
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 2222

ADDITIONAL_CONFIGS = {
    "version": {"label": "SSH Version", "default": "SSH-2.0-OpenSSH_7.4"},
}

@implementer(portal.IRealm)
class SimpleSSHRealm:
    def requestAvatar(self, avatar_id, mind, *interfaces):
        if b"conch.interfaces.IConchUser" in interfaces:
            return interfaces[0], None, lambda: None
        else:
            raise Exception("No supported interfaces found.")

def getRSAKeys():
    public_key_path = os.path.join(script_dir, "id_rsa.pub")
    private_key_path = os.path.join(script_dir, "id_rsa")
    if not (os.path.exists(public_key_path) and os.path.exists(private_key_path)):
        ssh_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = ssh_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )
        private_key = ssh_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        with open(public_key_path, "wb") as key_file:
            key_file.write(public_key)
        with open(private_key_path, "wb") as key_file:
            key_file.write(private_key)
    else:
        with open(public_key_path, "rb") as key_file:
            public_key = key_file.read()
        with open(private_key_path, "rb") as key_file:
            private_key = key_file.read()
    return public_key, private_key

class CustomSSHServerTransport(transport.SSHServerTransport):
    def __init__(self, our_version_string):
        self.ourVersionString = our_version_string.encode()
        transport.SSHServerTransport.__init__(self)

    def dispatchMessage(self, messageNum, payload):
        super().dispatchMessage(messageNum, payload)
        if messageNum == 50:  # SSH_MSG_USERAUTH_REQUEST
            username = payload.split(b'\x00')[1].decode('utf-8', errors='ignore')
            password_start = payload.find(b'\x00password\x00') + len(b'\x00password\x00')
            password = payload[password_start:].split(b'\x00')[0].decode('utf-8', errors='ignore')
            log.msg(f"Login attempt - Username: {username}, Password: {password}")

class SimpleSSHFactory(factory.SSHFactory):
    def __init__(self, version):
        self.ourVersionString = version
        self.publicKeys = {b"ssh-rsa": keys.Key.fromString(data=getRSAKeys()[0])}
        self.privateKeys = {b"ssh-rsa": keys.Key.fromString(data=getRSAKeys()[1])}
        self.services = {
            b"ssh-userauth": userauth.SSHUserAuthServer,
            b"ssh-connection": connection.SSHConnection,
        }

class LoggingPasswordChecker:
    credentialInterfaces = [credentials.IUsernamePassword]
    def requestAvatarId(self, creds):
        return defer.fail(error.UnauthorizedLogin())

def start_honeypot(host, port, additional_config):
    version = additional_config.get("version", "SSH-2.0-OpenSSH_7.4")
    ssh_factory = SimpleSSHFactory(version)
    ssh_realm = SimpleSSHRealm()
    ssh_portal = portal.Portal(ssh_realm)
    ssh_portal.registerChecker(LoggingPasswordChecker())
    ssh_factory.portal = ssh_portal
    endpoint = endpoints.TCP4ServerEndpoint(reactor, port, interface=host)
    endpoint.listen(ssh_factory)
    print(f"SSH Honeypot started on {host}:{port} with version {version}")

def stop_honeypot():
    try:
        reactor.callFromThread(reactor.stop)
    except Exception as e:
        print(f"Error stopping SSH honeypot: {e}")

# Script directory
script_dir = os.path.dirname(os.path.abspath(__file__))

if __name__ == "__main__":
    # Example usage (for standalone execution)
    parser = argparse.ArgumentParser(description="Run a simple SSH honeypot server.")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST, help="Host to bind the SSH server to.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind the SSH server to.")
    parser.add_argument("--version", type=str, default="SSH-2.0-OpenSSH_7.4", help="Custom SSH version string to display.")
    args = parser.parse_args()

    additional_config = {
        "version": args.version,
    }

    start_honeypot(args.host, args.port, additional_config)