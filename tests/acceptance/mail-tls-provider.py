#!/usr/bin/env python3
"""Disposable TLS IMAP/SMTP provider for installed-image Mail acceptance.

This is deliberately a test-side server, not product code or image content.
It implements only the protocol surface Punar's bounded open-protocol adapter
uses during connect and INBOX receive.  Credentials come from the environment,
the certificate is supplied by the caller, and all state disappears with the
process.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import signal
import socketserver
import ssl
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage


MAX_LINE = 16 * 1024
MAX_DATA = 2 * 1024 * 1024


@dataclass(frozen=True)
class Account:
    username: str
    password: str


def build_message(recipient: str) -> bytes:
    message = EmailMessage()
    message["From"] = "Punar Mail Acceptance <sender@acceptance.punar.invalid>"
    message["To"] = recipient
    message["Subject"] = "Encrypted Mail sync is working"
    message["Date"] = datetime.now(timezone.utc)
    message["Message-ID"] = "<punar-mail-acceptance-1@acceptance.punar.invalid>"
    message.set_content(
        "This message came through the disposable TLS acceptance provider.\n"
        "It is not included in the Punar product image.\n"
    )
    return message.as_bytes().replace(b"\n", b"\r\n")


class BoundedLineHandler(socketserver.StreamRequestHandler):
    def line(self) -> bytes | None:
        value = self.rfile.readline(MAX_LINE + 1)
        if not value:
            return None
        if len(value) > MAX_LINE or not value.endswith(b"\n"):
            raise ValueError("line limit exceeded")
        return value.rstrip(b"\r\n")

    def send_line(self, value: bytes) -> None:
        self.wfile.write(value + b"\r\n")
        self.wfile.flush()


class ImapHandler(BoundedLineHandler):
    account: Account
    message: bytes

    def handle(self) -> None:
        self.send_line(b"* OK Punar acceptance IMAP ready")
        authenticated = False
        while True:
            line = self.line()
            if line is None:
                return
            match = re.match(br"([^ ]+) +([^ ]+)(?: +(.*))?$", line)
            if match is None:
                return
            tag, raw_command, raw_args = match.groups()
            command = raw_command.upper()
            args = raw_args or b""
            if command == b"CAPABILITY":
                self.send_line(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN")
                self.send_line(tag + b" OK CAPABILITY completed")
            elif command == b"LOGIN":
                credentials = re.findall(br'"((?:[^"\\]|\\.)*)"|([^ ]+)', args)
                values = [left or right for left, right in credentials]
                authenticated = (
                    len(values) == 2
                    and values[0].decode("utf-8", "strict") == self.account.username
                    and values[1].decode("utf-8", "strict") == self.account.password
                )
                if authenticated:
                    self.send_line(tag + b" OK LOGIN completed")
                else:
                    self.send_line(tag + b" NO authentication failed")
            elif command == b"EXAMINE" and authenticated:
                self.send_line(b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
                self.send_line(b"* 1 EXISTS")
                self.send_line(b"* 0 RECENT")
                self.send_line(b"* OK [UNSEEN 1] first unseen message")
                self.send_line(b"* OK [UIDVALIDITY 4242] stable test mailbox")
                self.send_line(b"* OK [UIDNEXT 2] next UID")
                self.send_line(tag + b" OK [READ-ONLY] EXAMINE completed")
            elif command == b"UID" and authenticated and args.upper().startswith(b"FETCH "):
                internal_date = datetime.now(timezone.utc).strftime("%d-%b-%Y %H:%M:%S +0000")
                prefix = (
                    b"* 1 FETCH (UID 1 FLAGS () INTERNALDATE \""
                    + internal_date.encode("ascii")
                    + b"\" RFC822.SIZE "
                    + str(len(self.message)).encode("ascii")
                    + b" BODY[] {"
                    + str(len(self.message)).encode("ascii")
                    + b"}\r\n"
                )
                self.wfile.write(prefix + self.message + b"\r\n)\r\n")
                self.send_line(tag + b" OK FETCH completed")
            elif command == b"LOGOUT":
                self.send_line(b"* BYE Punar acceptance IMAP closing")
                self.send_line(tag + b" OK LOGOUT completed")
                return
            else:
                self.send_line(tag + b" BAD unsupported acceptance command")


class SmtpHandler(BoundedLineHandler):
    account: Account

    def authenticate_plain(self, encoded: bytes) -> bool:
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except ValueError:
            return False
        values = decoded.split(b"\0")
        return (
            len(values) == 3
            and values[1].decode("utf-8", "strict") == self.account.username
            and values[2].decode("utf-8", "strict") == self.account.password
        )

    def handle(self) -> None:
        self.send_line(b"220 mail.acceptance.punar.invalid ESMTP ready")
        authenticated = False
        login_user: str | None = None
        while True:
            line = self.line()
            if line is None:
                return
            command, _, args = line.partition(b" ")
            command = command.upper()
            if command in (b"EHLO", b"HELO"):
                self.wfile.write(
                    b"250-mail.acceptance.punar.invalid\r\n"
                    b"250-AUTH PLAIN LOGIN\r\n"
                    b"250 SIZE 2097152\r\n"
                )
                self.wfile.flush()
            elif command == b"AUTH" and args.upper().startswith(b"PLAIN"):
                _, _, encoded = args.partition(b" ")
                if not encoded:
                    self.send_line(b"334 ")
                    encoded = self.line() or b""
                authenticated = self.authenticate_plain(encoded)
                self.send_line(b"235 2.7.0 authenticated" if authenticated else b"535 5.7.8 authentication failed")
            elif command == b"AUTH" and args.upper() == b"LOGIN":
                self.send_line(b"334 VXNlcm5hbWU6")
                encoded_user = self.line() or b""
                try:
                    login_user = base64.b64decode(encoded_user, validate=True).decode("utf-8", "strict")
                except (ValueError, UnicodeDecodeError):
                    login_user = None
                self.send_line(b"334 UGFzc3dvcmQ6")
                encoded_password = self.line() or b""
                try:
                    password = base64.b64decode(encoded_password, validate=True).decode("utf-8", "strict")
                except (ValueError, UnicodeDecodeError):
                    password = ""
                authenticated = login_user == self.account.username and password == self.account.password
                self.send_line(b"235 2.7.0 authenticated" if authenticated else b"535 5.7.8 authentication failed")
            elif command == b"NOOP":
                self.send_line(b"250 2.0.0 ok")
            elif command == b"QUIT":
                self.send_line(b"221 2.0.0 closing")
                return
            elif authenticated and command in (b"MAIL", b"RCPT", b"RSET"):
                self.send_line(b"250 2.1.0 accepted")
            elif authenticated and command == b"DATA":
                self.send_line(b"354 end with <CRLF>.<CRLF>")
                total = 0
                while True:
                    data_line = self.line()
                    if data_line is None:
                        return
                    if data_line == b".":
                        break
                    total += len(data_line) + 2
                    if total > MAX_DATA:
                        self.send_line(b"552 5.3.4 message too large")
                        return
                self.send_line(b"250 2.0.0 queued for acceptance")
            else:
                self.send_line(b"530 5.7.0 authentication required")


class ThreadingTlsServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler: type[BoundedLineHandler], context: ssl.SSLContext):
        super().__init__(address, handler)
        self.socket = context.wrap_socket(self.socket, server_side=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--imap-port", type=int, default=1993)
    parser.add_argument("--smtp-port", type=int, default=1465)
    args = parser.parse_args()

    username = os.environ.get("PUNAR_MAIL_LAB_USERNAME", "mail@acceptance.punar.invalid")
    password = os.environ.get("PUNAR_MAIL_LAB_PASSWORD")
    if not password:
        print("PUNAR_MAIL_LAB_PASSWORD is required", file=sys.stderr)
        return 2
    account = Account(username=username, password=password)
    message = build_message(username)
    ImapHandler.account = account
    ImapHandler.message = message
    SmtpHandler.account = account

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.certificate, args.private_key)

    servers = [
        ThreadingTlsServer(("0.0.0.0", args.imap_port), ImapHandler, context),
        ThreadingTlsServer(("0.0.0.0", args.smtp_port), SmtpHandler, context),
    ]
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()

    stopped = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print(
        f"PUNAR_MAIL_TLS_LAB_READY imap={args.imap_port} smtp={args.smtp_port} user={username}",
        flush=True,
    )
    stopped.wait()
    for server in servers:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
