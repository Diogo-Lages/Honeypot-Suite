import os
import argparse
from twisted.internet import reactor
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from twisted.web import server, resource
from twisted.python import log
from datetime import datetime, timedelta
import requests
import urllib
from urllib.parse import urljoin
from mimetypes import guess_type
import base64
from bs4 import BeautifulSoup
import ssl


# Constants
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 443

ADDITIONAL_CONFIGS = {
    "ssl_country": {"label": "SSL Country", "default": "GB"},
    "ssl_state": {"label": "SSL State", "default": "London"},
    "ssl_locality": {"label": "SSL Locality", "default": "City of London"},
    "ssl_org": {"label": "SSL Organization", "default": "MyTestOrg"},
    "domain_name": {"label": "Domain Name", "default": "test.local"},
}

class SimpleHTTPResource(resource.Resource):
    isLeaf = True

    def __init__(self, server):
        self.server = server

    def render_GET(self, request):
        request.setHeader(b"Server", self.server.server_banner.encode())
        return self.serve_page(request)

    def render_POST(self, request):
        post_content = self.extract_post_content(request)
        self.log_request(request, post_content)
        return self.serve_page(request)

    def serve_page(self, request):
        requested_url = urllib.parse.urljoin(self.server.current_url, request.path.decode())
        try:
            self.server.download_and_modify_html(requested_url)
            with open(os.path.join(script_dir, "index.html"), "rb") as file:
                return file.read()
        except Exception as e:
            log.msg(f"Error processing requested URL {requested_url}: {e}")
            with open(os.path.join(script_dir, "index.html"), "rb") as file:
                return file.read()

    def extract_post_content(self, request):
        request.content.seek(0)
        content = request.content.read()
        try:
            return urllib.parse.parse_qs(content.decode())
        except Exception as e:
            log.msg(f"Error parsing POST content: {e}")
            return {}

    def log_request(self, request, post_data=None):
        src_ip = request.getClientAddress().host
        src_port = request.getClientAddress().port
        user_agent = request.getHeader("user-agent") or "Unknown"
        language = request.getHeader("accept-language") or "Unknown"
        referer = request.getHeader("referer") or "Unknown"
        protocol_version = (
            request.transport.negotiatedProtocol.decode("utf-8")
            if hasattr(request.transport, "negotiatedProtocol")
            else "Unknown"
        )
        request_path = request.uri.decode()
        log_message = (
            f"[{datetime.now()}] src_ip={src_ip}, "
            f"src_port={src_port}, "
            f"user_agent='{user_agent}', "
            f"language='{language}', "
            f"referer='{referer}', "
            f"protocol_version='{protocol_version}', "
            f"path='{request_path}'"
        )
        if post_data:
            log_message += f", post_data={post_data}"
        log.msg(log_message)


class SimpleHTTPServer:
    def __init__(self, host, port, url):
        self.host = host
        self.port = port
        self.url = url
        self.current_url = url

    def start(self, ssl_country, ssl_state, ssl_locality, ssl_org, domain_name):
        self.setup_logging()
        print(f"Please wait, downloading resources from {self.url} ...")
        if self.download_and_modify_html(self.url):
            root = resource.Resource()
            root.putChild(b"", SimpleHTTPResource(self))
            site = server.Site(root)
            key_path, cert_path = self.load_certificates(
                ssl_country=ssl_country,
                ssl_state=ssl_state,
                ssl_locality=ssl_locality,
                ssl_org=ssl_org,
                domain_name=domain_name,
            )
            context_factory = ssl.DefaultOpenSSLContextFactory(str(key_path), str(cert_path))
            reactor.listenSSL(self.port, site, context_factory, interface=self.host)
            print(f"HTTPS Honeypot started on {self.host}:{self.port}")
        else:
            print("Failed to download all resources. Server not started.")

    def setup_logging(self):
        log_file_path = os.path.join(script_dir, "https_honeypot.log")
        print(f"All HTTP requests will be logged in: {log_file_path}")
        log_observer = log.FileLogObserver(open(log_file_path, "a"))
        log.startLoggingWithObserver(log_observer.emit, setStdout=False)

    def download_and_modify_html(self, url):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        try:
            response = requests.get(url, headers=headers)
            self.server_banner = response.headers.get("Server", "Apache/2.2.49")
            soup = BeautifulSoup(response.content, "html.parser")

            # Inline CSS
            for css in soup.find_all("link", rel="stylesheet"):
                if "href" in css.attrs:
                    css_url = urllib.parse.urljoin(url, css["href"])
                    css_response = requests.get(css_url, headers=headers)
                    new_style_tag = soup.new_tag("style")
                    new_style_tag.string = css_response.text
                    css.replace_with(new_style_tag)

            # Inline JavaScript
            for js in soup.find_all("script", src=True):
                js_url = urllib.parse.urljoin(url, js["src"])
                js_response = requests.get(js_url, headers=headers)
                new_script_tag = soup.new_tag("script")
                new_script_tag.string = js_response.text
                js.replace_with(new_script_tag)

            # Inline Images
            for img in soup.find_all("img", src=True):
                img_url = urllib.parse.urljoin(url, img["src"])
                img_response = requests.get(img_url, headers=headers)
                mime_type, _ = guess_type(img_url)
                data_url = (
                    f"data:{mime_type};base64,"
                    + base64.b64encode(img_response.content).decode()
                )
                img["src"] = data_url

            # Save modified HTML
            with open(os.path.join(script_dir, "index.html"), "w", encoding="utf-8") as file:
                file.write(str(soup))
            return True
        except Exception as e:
            log.msg(f"Error processing HTML from {url}: {e}")
            return False

    def load_certificates(self, ssl_country, ssl_state, ssl_locality, ssl_org, domain_name):
        key_path = os.path.join(script_dir, "server.key")
        cert_path = os.path.join(script_dir, "server.crt")

        # Generate private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_path, "wb") as key_file:
            key_file.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Create certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, ssl_country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ssl_state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, ssl_locality),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, ssl_org),
                x509.NameAttribute(NameOID.COMMON_NAME, domain_name),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        with open(cert_path, "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

        return key_path, cert_path


def start_honeypot(host, port, additional_config):
    server = SimpleHTTPServer(host, port, additional_config.get("url", "https://example.com"))
    server.start(
        ssl_country=additional_config.get("ssl_country", "GB"),
        ssl_state=additional_config.get("ssl_state", "London"),
        ssl_locality=additional_config.get("ssl_locality", "City of London"),
        ssl_org=additional_config.get("ssl_org", "MyTestOrg"),
        domain_name=additional_config.get("domain_name", "test.local"),
    )


def stop_honeypot():
    try:
        reactor.callFromThread(reactor.stop)
    except Exception as e:
        print(f"Error stopping HTTPS honeypot: {e}")


# Script directory
script_dir = os.path.dirname(os.path.abspath(__file__))

if __name__ == "__main__":
    # Example usage (for standalone execution)
    parser = argparse.ArgumentParser(description="Run a simple HTTPS honeypot.")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST, help="Host to bind the server to.")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="Port to bind the server to.")
    parser.add_argument("--url", type=str, required=True, help="URL to download and serve HTML from.")
    args = parser.parse_args()

    additional_config = {
        "url": args.url,
        "ssl_country": ADDITIONAL_CONFIGS["ssl_country"]["default"],
        "ssl_state": ADDITIONAL_CONFIGS["ssl_state"]["default"],
        "ssl_locality": ADDITIONAL_CONFIGS["ssl_locality"]["default"],
        "ssl_org": ADDITIONAL_CONFIGS["ssl_org"]["default"],
        "domain_name": ADDITIONAL_CONFIGS["domain_name"]["default"],
    }

    start_honeypot(args.host, args.port, additional_config)