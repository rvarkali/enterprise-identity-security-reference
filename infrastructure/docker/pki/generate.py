#!/usr/bin/env python3
"""Development-only PKI. Refuses any existing output directory; never prints secrets."""
import argparse
from datetime import datetime, timedelta, timezone
import ssl
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[3]


def run(*args, env=None):
    result = subprocess.run(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError("Local PKI command failed: " + Path(args[0]).name)
    return result.stdout


def validity_days(ca, server, client):
    if any(type(days) is not int or days <= 0 for days in (ca, server, client)):
        raise ValueError("Validity days must be positive integers")
    # Leaves are issued after the CA; equal durations could outlive it by seconds.
    if server >= ca or client >= ca:
        raise ValueError("Server and client validity must each be shorter than CA validity")
    try:
        datetime.now(timezone.utc) + timedelta(days=ca)
    except (OverflowError, ValueError):
        raise ValueError("CA validity exceeds the supported date range") from None
    return ca, server, client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", required=True, help="Exact machine client URI SAN")
    parser.add_argument("--subject", required=True, help="Existing Keycloak service-account UUID")
    parser.add_argument("--output", default=str(ROOT / ".local-pki"))
    parser.add_argument("--ca-days", type=int, default=365, help="CA validity in days (default: 365)")
    parser.add_argument("--server-days", type=int, default=90, help="Server validity in days (default: 90)")
    parser.add_argument("--client-days", type=int, default=30, help="Client validity in days (default: 30)")
    args = parser.parse_args()
    try:
        validity_days(args.ca_days, args.server_days, args.client_days)
    except ValueError as error:
        parser.error(str(error))
    # Prevent OpenSSL config injection and SAN-list expansion.
    if (not urlsplit(args.uri).scheme or any(c.isspace() or c in ',#;\\' for c in args.uri)
            or not args.uri.isascii() or '$' in args.uri or '[' in args.uri or ']' in args.uri):
        parser.error("Use a single absolute ASCII URI without config metacharacters")
    import uuid
    try:
        uuid.UUID(args.subject)
    except ValueError:
        parser.error("subject must be the existing service-account UUID")
    out = Path(args.output).absolute()
    if out.exists() or out.is_symlink():
        parser.error("Output already exists; inspect or explicitly rotate it before generating")
    if not shutil.which("openssl") or not shutil.which("keytool"):
        parser.error("OpenSSL and Java keytool are required")
    if out.is_relative_to(ROOT):
        ignored = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "--quiet", str(out / "probe")])
        if ignored.returncode:
            parser.error("Output inside repository must be Git-ignored")
    os.umask(0o077)
    out.mkdir(parents=True, mode=0o700)
    # An incomplete directory is deliberately retained and will be refused on rerun.
    password = secrets.token_urlsafe(32)
    env = dict(os.environ, DEV_PKI_PASSWORD=password)
    def openssl(*values):
        return run("openssl", *values, env=env)
    try:
        ca = out / "ca"
        openssl("req", "-x509", "-newkey", "rsa:3072", "-noenc", "-sha256", "-days", str(args.ca_days),
                "-subj", "/CN=DEVELOPMENT ONLY Machine Test CA",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", str(ca)+".key", "-out", str(ca)+".crt")
        def expires(cert):
            value = openssl("x509", "-in", str(cert), "-noout", "-enddate").decode().strip()
            return ssl.cert_time_to_seconds(value.removeprefix("notAfter="))
        ca_expiry = expires(out / "ca.crt")
        for name, san, usage, days in [
            ("server", "DNS:localhost,IP:127.0.0.1", "serverAuth", args.server_days),
            ("client", "URI:"+args.uri, "clientAuth", args.client_days),
        ]:
            ext = out / (name+".ext")
            ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                           "extendedKeyUsage="+usage+"\nsubjectAltName="+san+"\n")
            openssl("req", "-new", "-newkey", "rsa:3072", "-noenc", "-sha256",
                    "-subj", "/CN=DEVELOPMENT ONLY "+name, "-keyout", str(out/(name+".key")),
                    "-out", str(out/(name+".csr")))
            openssl("x509", "-req", "-in", str(out/(name+".csr")), "-CA", str(ca)+".crt",
                    "-CAkey", str(ca)+".key", "-set_serial", "0x"+secrets.token_hex(16),
                    "-days", str(days), "-sha256", "-extfile", str(ext), "-out", str(out/(name+".crt")))
            if expires(out / (name+".crt")) > ca_expiry:
                raise RuntimeError("Leaf expiration exceeds CA expiration; do not deploy")
            openssl("verify", "-CAfile", str(ca)+".crt", "-purpose",
                    "sslserver" if name == "server" else "sslclient", str(out/(name+".crt")))
        openssl("verify", "-CAfile", str(ca)+".crt", "-verify_hostname", "localhost", str(out/"server.crt"))
        openssl("verify", "-CAfile", str(ca)+".crt", "-verify_ip", "127.0.0.1", str(out/"server.crt"))
        openssl("pkcs12", "-export", "-name", "development-server", "-inkey", str(out/"server.key"),
                "-in", str(out/"server.crt"), "-certfile", str(ca)+".crt",
                "-out", str(out/"server.p12"), "-passout", "env:DEV_PKI_PASSWORD")
        run("keytool", "-importcert", "-noprompt", "-alias", "development-client-ca",
            "-file", str(ca)+".crt", "-keystore", str(out/"client-ca.p12"), "-storetype", "PKCS12",
            "-storepass:env", "DEV_PKI_PASSWORD", env=env)
        for store in ("server.p12", "client-ca.p12"):
            run("keytool", "-list", "-keystore", str(out/store), "-storetype", "PKCS12",
                "-storepass:env", "DEV_PKI_PASSWORD", env=env)
        (out/"client-bundle.pem").write_bytes((out/"client.crt").read_bytes()+(out/"ca.crt").read_bytes())
        # Compose env file; password and private keys never go to stdout or command arguments.
        import shlex
        settings = dict(MACHINE_TLS_KEY_STORE_FILE=str(out/"server.p12"),
                        MACHINE_TLS_TRUST_STORE_FILE=str(out/"client-ca.p12"),
                        MACHINE_TLS_KEY_STORE_PASSWORD=password, MACHINE_TLS_TRUST_STORE_PASSWORD=password,
                        MACHINE_SERVICE_ACCOUNT_SUBJECT=args.subject, MACHINE_CERTIFICATE_URI=args.uri)
        (out/"machine.env").write_text("".join(k+"="+shlex.quote(v)+"\n" for k,v in settings.items()))
        for file in out.iterdir():
            file.chmod(0o600)
        (out/"COMPLETE").write_text(f"DEVELOPMENT ONLY: CA {args.ca_days} days; server {args.server_days} days; client {args.client_days} days. Do not reuse after expiry.\n")
        print("PASS: development PKI generated and locally verified.")
        print("Before deployment, grant API UID 10001 read access to the two stores; see PKI README.")
    except Exception:
        print("ERROR: incomplete PKI output retained; do not deploy it. Inspect then explicitly remove it.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
