"""Local TLS lab for the eMudhra intermediate CA compromise.

Why this exists
---------------
The disclosure ships certificate *chains* for twelve test hosts, but no leaf
private keys, so the only way to ask an installed TLS client "do you still
trust this CA?" is to talk to one of those hosts over the internet.

We do have the eight compromised intermediate CA private keys (recovered from
the certificates themselves, see keys/emudhra-intermediate-ca-keys.zip).  With
those we can mint our own leaf certificate for localhost / 127.0.0.1 under each
intermediate, serve it from a loopback port, and let every client connect to
it.  No DNS, no third-party host, no internet.

Each chain mirrors one of the twelve published chains: the minted leaf replaces
the original leaf, and the intermediate (plus the emSign cross-sign, where the
published chain includes it) is served exactly as captured.
"""

from __future__ import annotations

import errno
import hashlib
import http.server
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path

CERT_RE = r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"

CHAINS_DIR = Path("disclosure") / "chains"
CHAINS_ARCHIVE = Path("disclosure") / "emudhra-test-host-chains.zip"

KEY_ARCHIVE = "emudhra-intermediate-ca-keys.zip"
KEY_DIR = "emudhra-intermediate-ca-keys"

EXT_CONF = """\
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = serverAuth
subjectAltName         = DNS:localhost, IP:127.0.0.1, IP:::1
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer
"""


class LabError(RuntimeError):
    pass


@dataclass
class Chain:
    """One served chain: a minted leaf plus the captured intermediates."""

    name: str          # e.g. dv-g3b-aaa
    ca_cn: str         # e.g. EM DV TLS CA - G3B
    path: Path         # PEM file with leaf first
    port: int = 0

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}/"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib naming
        body = b"eMudhra local trust lab\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the run output clean
        pass


class _HTTPS(http.server.ThreadingHTTPServer):
    """Accept plain TCP and run the TLS handshake in the request thread, so a
    client that stalls mid-handshake cannot block the others."""

    daemon_threads = True

    def __init__(self, host: str, port: int, ctx: ssl.SSLContext):
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.tls = ctx
        super().__init__((host, port), _Handler)

    def finish_request(self, request, client_address):
        request.settimeout(10)
        try:
            tls = self.tls.wrap_socket(request, server_side=True)
        except OSError:  # the client refused our chain; that is its answer
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            tls.close()

    def handle_error(self, request, client_address):
        pass


class _Server(threading.Thread):
    def __init__(self, httpd: _HTTPS):
        super().__init__(daemon=True)
        self.httpd = httpd
        self.port = httpd.server_address[1]
        self.ready = threading.Event()

    def run(self):
        self.ready.set()
        self.httpd.serve_forever(poll_interval=0.05)

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _bind_pair(ctx: ssl.SSLContext) -> list[_HTTPS]:
    """Bind 127.0.0.1 and ::1 on the same port, since clients resolve
    `localhost` to either.  Without an IPv6 loopback, serve IPv4 only."""
    for _ in range(20):
        v4 = _HTTPS("127.0.0.1", 0, ctx)
        try:
            v6 = _HTTPS("::1", v4.server_address[1], ctx)
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                v4.server_close()
                continue
            return [v4]
        return [v4, v6]
    raise LabError("could not bind a port on both 127.0.0.1 and ::1")


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def sweep_stale(cache: Path) -> None:
    """Remove lab directories left by runs that were killed before cleanup."""
    for workdir in cache.glob("lab-*"):
        try:
            pid = int((workdir / "owner.pid").read_text())
        except (OSError, ValueError):
            pid = 0
        if not pid or not _pid_alive(pid):
            shutil.rmtree(workdir, ignore_errors=True)


def resolve_chains(root: Path, cache: Path, chains: str | Path | None = None) -> Path:
    """Directory holding the twelve chain PEMs.

    `chains` may be a directory or a zip.  By default use disclosure/chains/
    when it has PEMs, else the tracked disclosure zip.  A zip is extracted
    once into cache/chains-<hash>/, so concurrent runs share it safely.
    """
    if chains:
        source = Path(chains).expanduser().resolve()
    elif any((root / CHAINS_DIR).glob("*.pem")):
        source = root / CHAINS_DIR
    else:
        source = root / CHAINS_ARCHIVE
    if source.is_dir():
        return source
    if not source.is_file():
        raise LabError(f"no chains: {source} not found; pass --chains DIR or ZIP")

    digest = hashlib.sha256(source.read_bytes()).hexdigest()[:12]
    target = cache / f"chains-{digest}"
    if not target.is_dir():
        cache.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix="chains-tmp-", dir=cache))
        with zipfile.ZipFile(source) as zf:
            for member in zf.namelist():
                if member.endswith(".pem") and not member.startswith(("/", "..")):
                    (staging / Path(member).name).write_bytes(zf.read(member))
        try:
            staging.rename(target)
        except OSError:  # another run got there first
            shutil.rmtree(staging, ignore_errors=True)
    if not any(target.glob("*.pem")):
        raise LabError(f"{source} contains no .pem chains")
    return target


def split_pem(text: str) -> list[str]:
    return re.findall(CERT_RE, text, re.S)


def _run(cmd: list[str], *, timeout: int = 30, input_text: str | None = None):
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise LabError(f"{cmd[0]} not found") from exc
    if proc.returncode != 0:
        raise LabError(f"{' '.join(cmd[:3])} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


class Lab:
    """Mint leaves under the recovered CA keys and serve them on loopback."""

    def __init__(self, root: Path, cache: Path, openssl: str = "openssl",
                 keys: Path | str | None = None):
        self.root = root
        self.cache = cache
        self.keys = Path(keys) if keys else None
        self.openssl = openssl or "openssl"
        self.workdir: Path | None = None
        self.chains: list[Chain] = []
        self._servers: list[_Server] = []
        self._leaf_keys: dict[str, Path] = {}
        self.skip: list[str] = []

    # -- material ---------------------------------------------------------

    def _extract_zip(self, archive: Path) -> Path:
        target = self.workdir / "keys"
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(target)
        dirs = [p for p in target.iterdir() if p.is_dir()]
        return dirs[0] if len(dirs) == 1 else target

    def _key_material(self) -> dict[str, tuple[Path, Path]]:
        """Map CA common name -> (certificate, private key) on disk.

        `keys` may point at the extracted directory or the zip; by default we
        look for it under keys/ at the repo root.
        """
        if self.keys is not None:
            if self.keys.is_dir():
                keys_dir = self.keys
            elif self.keys.is_file():
                keys_dir = self._extract_zip(self.keys)
            else:
                raise LabError(f"keys path not found: {self.keys}")
        else:
            keys_dir = self.root / "keys" / KEY_DIR
            if not keys_dir.is_dir():
                archive = self.root / "keys" / KEY_ARCHIVE
                if not archive.is_file():
                    raise LabError(
                        f"no recovered CA keys: expected {keys_dir} or {archive}; "
                        "pass --keys"
                    )
                keys_dir = self._extract_zip(archive)

        material: dict[str, tuple[Path, Path]] = {}
        for pem in sorted(keys_dir.glob("*.pem")):
            key = pem.with_suffix(".key")
            if not key.is_file():
                continue
            cn = pem.stem.split("CN=")[1].split(",")[0].strip() if "CN=" in pem.stem else pem.stem
            # A cross-signed cert and its key must belong together.
            cert_pub = _run([self.openssl, "x509", "-in", str(pem), "-noout", "-pubkey"]).strip()
            key_pub = _run([self.openssl, "pkey", "-in", str(key), "-pubout"]).strip()
            if cert_pub != key_pub:
                self.skip.append(f"{cn}: private key does not match certificate")
                continue
            material[cn] = (pem, key)
        if not material:
            raise LabError("no usable CA key/certificate pairs found")
        return material

    def _mint_leaf(self, ca_cert: Path, ca_key: Path, cn: str) -> tuple[Path, Path]:
        """Issue a localhost leaf under `ca_cert`; reuse it for both cross-signs."""
        assert self.workdir is not None
        safe = "".join(c if c.isalnum() else "_" for c in cn)
        out = self.workdir / "leaves"
        out.mkdir(exist_ok=True)
        leaf_key = out / f"{safe}.key"
        leaf_csr = out / f"{safe}.csr"
        leaf_pem = out / f"{safe}.pem"
        ext = out / "leaf.ext"
        if not ext.exists():
            ext.write_text(EXT_CONF)

        if not leaf_pem.is_file():
            _run([self.openssl, "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", str(leaf_key)])
            _run([self.openssl, "req", "-new", "-key", str(leaf_key), "-subj", "/CN=localhost", "-out", str(leaf_csr)])
            _run(
                [
                    self.openssl, "x509", "-req",
                    "-in", str(leaf_csr),
                    "-CA", str(ca_cert),
                    "-CAkey", str(ca_key),
                    "-set_serial", str(int(secrets.token_hex(8), 16)),
                    "-days", "30",
                    "-sha384",
                    "-extfile", str(ext),
                    "-out", str(leaf_pem),
                ]
            )
        return leaf_pem, leaf_key

    # -- lifecycle --------------------------------------------------------

    def prepare(self, chains_dir: Path, files: list[Path] | None = None) -> list[Chain]:
        """Mint leaves for every captured chain and write servable PEM files."""
        self.cache.mkdir(parents=True, exist_ok=True)
        sweep_stale(self.cache)
        self.workdir = Path(tempfile.mkdtemp(prefix="lab-", dir=self.cache))
        (self.workdir / "owner.pid").write_text(str(os.getpid()))
        material = self._key_material()

        for chain_file in (files if files is not None else sorted(chains_dir.glob("*.pem"))):
            blocks = split_pem(chain_file.read_text())
            if len(blocks) < 2:
                self.skip.append(f"{chain_file.name}: not a chain")
                continue
            intermediate = blocks[1]
            icn = _run(
                [self.openssl, "x509", "-noout", "-subject"],
                input_text=intermediate,
            ).strip().split("CN=")[-1].split(",")[0].strip()
            if icn not in material:
                self.skip.append(f"{chain_file.name}: no key for {icn}")
                continue

            ca_cert, ca_key = material[icn]
            leaf_pem, leaf_key = self._mint_leaf(ca_cert, ca_key, icn)

            # Self-check: the minted leaf must verify against its intermediate.
            _run(
                [
                    self.openssl, "verify", "-partial_chain",
                    "-trusted", str(ca_cert),
                    str(leaf_pem),
                ]
            )

            name = chain_file.stem.replace(".we-have-a-problem.com", "")
            served = self.workdir / f"{name}.pem"
            served.write_text(leaf_pem.read_text().rstrip() + "\n" + "\n".join(blocks[1:]) + "\n")
            self.chains.append(Chain(name=name, ca_cn=icn, path=served))
            self._leaf_keys[name] = leaf_key

        if not self.chains:
            raise LabError("no chains could be prepared")
        return self.chains

    def start(self) -> list[Chain]:
        for chain in self.chains:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(chain.path), str(self._leaf_keys[chain.name]))
            for httpd in _bind_pair(ctx):
                srv = _Server(httpd)
                srv.start()
                srv.ready.wait(2)
                chain.port = srv.port
                self._servers.append(srv)
        for chain in self.chains:
            with socket.create_connection(("127.0.0.1", chain.port), timeout=2):
                pass
        return self.chains

    def stop(self):
        for srv in self._servers:
            try:
                srv.stop()
            except Exception:
                pass
        self._servers.clear()

    def cleanup(self):
        self.stop()
        if self.workdir and self.workdir.exists():
            shutil.rmtree(self.workdir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()
