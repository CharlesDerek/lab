"""Private TLS termination and certificate faults for the native fleet fixture.

The product's HTTP server stays on loopback, as with its documented reverse
proxy deployment. This helper never installs a CA or records request contents.
"""
import collections
import hashlib
import json
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import threading
import time


def certificates(root):
    root.mkdir(mode=0o700)

    def openssl(*arguments):
        subprocess.run(['openssl', *map(str, arguments)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)

    for name in ('trusted', 'untrusted'):
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', f'/CN=Athernex isolated {name} fixture CA',
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                '-keyout', root/f'{name}.key', '-out', root/f'{name}.pem')
    contexts, fingerprints = {}, {}
    for name, ca, san in (
        ('trusted_original', 'trusted', 'IP:127.0.0.1,DNS:localhost'),
        ('untrusted_ca', 'untrusted', 'IP:127.0.0.1,DNS:localhost'),
        ('wrong_name', 'trusted', 'DNS:wrong.invalid'),
        ('trusted_rotated', 'trusted', 'IP:127.0.0.1,DNS:localhost'),
    ):
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', f'/CN={name}',
                '-keyout', root/f'{name}.key', '-out', root/f'{name}.csr')
        (root/f'{name}.ext').write_text('basicConstraints=critical,CA:FALSE\n'
            'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
            f'subjectAltName={san}\n')
        openssl('x509', '-req', '-in', root/f'{name}.csr', '-CA', root/f'{ca}.pem',
                '-CAkey', root/f'{ca}.key', '-CAcreateserial', '-days', '1',
                '-extfile', root/f'{name}.ext', '-out', root/f'{name}.pem')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        context.load_cert_chain(root/f'{name}.pem', root/f'{name}.key')
        contexts[name] = context
        fingerprints[name] = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
            (root/f'{name}.pem').read_text())).hexdigest()
    assert len(set(fingerprints.values())) == 4
    for key in root.glob('*.key'):
        key.chmod(0o600)
    return contexts, fingerprints


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        owner = self.server
        if not owner.slots.acquire(blocking=False):
            return
        client = None
        try:
            with owner.lock:
                label, generation = owner.label, owner.generation
                client = owner.contexts[label].wrap_socket(
                    self.request, server_side=True, do_handshake_on_connect=False)
                owner.connections[client] = generation
            client.settimeout(10)
            try:
                client.do_handshake()
            except ssl.SSLError as error:
                with owner.lock:
                    owner.stats[label]['handshake_errors'][error.reason or type(error).__name__] += 1
                return
            with owner.lock:
                if generation != owner.generation:
                    return
                owner.stats[label]['handshakes'] += 1
                owner.stats[label]['versions'][client.version()] += 1
            with socket.create_connection(owner.destination, timeout=10) as peer:
                with owner.lock:
                    owner.stats[label]['upstream_connections'] += 1
                pairs = {client: peer, peer: client}
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    # OpenSSL may already hold decrypted bytes without another
                    # readable TCP notification; always drain those first.
                    ready = [client] if client.pending() else select.select(list(pairs), [], [], 1)[0]
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        if source is client:
                            with owner.lock:
                                owner.stats[label]['plaintext_client_bytes'] += len(data)
                        pairs[source].sendall(data)
                        deadline = time.monotonic() + 40
        except OSError:
            # Certificate changes and actual server outages deliberately close
            # connections. No failed exchange is counted as delivered evidence.
            pass
        finally:
            if client is not None:
                client.close()
                with owner.lock:
                    owner.connections.pop(client, None)
            owner.slots.release()


class Terminator(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, destination, contexts):
        self.destination, self.contexts = destination, contexts
        self.label, self.generation = 'trusted_original', 0
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(64)
        self.connections = {}
        self.stats = {name: dict(handshakes=0, upstream_connections=0, plaintext_client_bytes=0,
                                versions=collections.Counter(), handshake_errors=collections.Counter())
                      for name in contexts}
        super().__init__(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def disconnect(self, label=None):
        with self.lock:
            if label is not None:
                assert label in self.contexts
                self.label = label
            self.generation += 1
            generation = self.generation
            for client in self.connections:
                try:
                    # Interrupt underlying I/O. The owning handler alone closes
                    # its SSL object; do not mutate it from this thread.
                    socket.socket.shutdown(client, socket.SHUT_RDWR)
                except OSError:
                    pass
        deadline = time.monotonic() + 15
        while True:
            with self.lock:
                if all(g >= generation for g in self.connections.values()):
                    return
            if time.monotonic() > deadline:
                raise RuntimeError('Previous TLS connections did not retire')
            time.sleep(.05)

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.stats))

    def close(self):
        self.shutdown()
        self.server_close()
        self.disconnect()
        self.thread.join(timeout=5)
