#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER="${REPO_ROOT}/tests/acceptance/mail-tls-provider.py"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/punar-mail-tls-provider.XXXXXX")"
PASSWORD="$(openssl rand -hex 16)"
PID=''

cleanup() {
    if [ -n "${PID}" ]; then
        kill "${PID}" 2>/dev/null || true
        wait "${PID}" 2>/dev/null || true
    fi
    rm -rf -- "${WORK}"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=mail.acceptance.punar.invalid' \
    -addext 'subjectAltName=DNS:mail.acceptance.punar.invalid' \
    -keyout "${WORK}/server.key" -out "${WORK}/server.crt" >/dev/null 2>&1

PUNAR_MAIL_LAB_PASSWORD="${PASSWORD}" \
    python3 "${SERVER}" \
        --certificate "${WORK}/server.crt" \
        --private-key "${WORK}/server.key" \
        --imap-port 21993 --smtp-port 21465 >"${WORK}/server.log" 2>&1 &
PID=$!

for _ in $(seq 1 50); do
    grep -q '^PUNAR_MAIL_TLS_LAB_READY ' "${WORK}/server.log" 2>/dev/null && break
    kill -0 "${PID}" 2>/dev/null || {
        cat "${WORK}/server.log" >&2
        exit 1
    }
    sleep 0.1
done
grep -q '^PUNAR_MAIL_TLS_LAB_READY ' "${WORK}/server.log"

imap_reply="$({
    printf 'a1 LOGIN "mail@acceptance.punar.invalid" "%s"\r\n' "${PASSWORD}"
    printf 'a2 EXAMINE INBOX\r\n'
    printf 'a3 UID FETCH 1:1 (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[])\r\n'
    printf 'a4 LOGOUT\r\n'
} | openssl s_client -quiet -connect 127.0.0.1:21993 \
    -CAfile "${WORK}/server.crt" -verify_return_error 2>/dev/null || true)"
grep -q 'a1 OK LOGIN completed' <<<"${imap_reply}"
grep -q '\[UIDVALIDITY 4242\]' <<<"${imap_reply}"
grep -q 'Subject: Encrypted Mail sync is working' <<<"${imap_reply}"
grep -q 'a4 OK LOGOUT completed' <<<"${imap_reply}"

smtp_reply="$({
    encoded="$(printf '\0%s\0%s' 'mail@acceptance.punar.invalid' "${PASSWORD}" | openssl base64 -A)"
    printf 'EHLO acceptance.punar.invalid\r\n'
    printf 'AUTH PLAIN %s\r\n' "${encoded}"
    printf 'QUIT\r\n'
} | openssl s_client -quiet -connect 127.0.0.1:21465 \
    -CAfile "${WORK}/server.crt" -verify_return_error 2>/dev/null || true)"
grep -q '^235 2.7.0 authenticated' <<<"${smtp_reply}"
grep -q '^221 2.0.0 closing' <<<"${smtp_reply}"

echo 'PUNAR_MAIL_TLS_PROVIDER_OK imap=tls smtp=tls fixture_scope=test_only'
