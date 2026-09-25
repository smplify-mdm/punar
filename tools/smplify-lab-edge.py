#!/usr/bin/env python3
"""The Smplify lab edge: TLS termination on the Mac's loopback in front of the
local Smplify port-forward (plain HTTP on 127.0.0.1:9003).

A Punar VM under QEMU user-mode networking reaches the host's loopback as
10.0.2.2, so listening on 127.0.0.1 is enough for the guest and keeps the lab
off every other interface. A Docker-published proxy cannot do this job: a
container reaches the Mac through host.docker.internal, which never sees a
loopback-only listener. Standard library only; nothing to install.

Honest limit: this edge does not request the device certificate, so the
device presents none. Server-side device identity (backend B1/B2 in
docs/development/smplify-enrollment.md) is what makes that real.
"""
import argparse
import selectors
import socket
import ssl
import sys
import threading


def relay(client, backend):
    """Shovel bytes both ways until either side closes."""
    sel = selectors.DefaultSelector()
    sel.register(client, selectors.EVENT_READ, backend)
    sel.register(backend, selectors.EVENT_READ, client)
    try:
        while True:
            for key, _ in sel.select(timeout=60):
                try:
                    data = key.fileobj.recv(65536)
                except (ssl.SSLWantReadError, BlockingIOError):
                    continue
                if not data:
                    return
                key.data.sendall(data)
    finally:
        sel.close()
        for sock in (client, backend):
            try:
                sock.close()
            except OSError:
                pass


def serve(listen, backend_addr, context):
    server = socket.create_server(listen, reuse_port=False)
    print(f"smplify-lab-edge: https://{listen[0]}:{listen[1]} -> http://{backend_addr[0]}:{backend_addr[1]}", flush=True)
    while True:
        conn, peer = server.accept()
        threading.Thread(target=handle, args=(conn, peer, backend_addr, context), daemon=True).start()


def handle(conn, peer, backend_addr, context):
    try:
        tls = context.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError) as error:
        print(f"smplify-lab-edge: handshake with {peer[0]} failed: {error}", flush=True)
        conn.close()
        return
    try:
        backend = socket.create_connection(backend_addr, timeout=10)
    except OSError as error:
        print(f"smplify-lab-edge: backend unreachable: {error}", flush=True)
        tls.close()
        return
    backend.settimeout(None)
    tls.settimeout(None)
    relay(tls, backend)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--listen", default="127.0.0.1:8443")
    parser.add_argument("--backend", default="127.0.0.1:9003")
    args = parser.parse_args()
    listen_host, listen_port = args.listen.rsplit(":", 1)
    backend_host, backend_port = args.backend.rsplit(":", 1)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.certificate, args.private_key)
    try:
        serve((listen_host, int(listen_port)), (backend_host, int(backend_port)), context)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
