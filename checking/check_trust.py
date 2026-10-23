#!/usr/bin/env python3
"""Which TLS clients on this machine still trust the compromised eMudhra CAs?

The checker has two engines:

  local    (default) Mint a leaf certificate for localhost under each of the
           eight compromised intermediate CA keys, serve the twelve published
           chains on 127.0.0.1, and let every installed client connect to it.
           This asks the client's real TLS stack the real question, with no
           DNS and no third-party host involved.

  offline  Skip the sockets and verify the published chains against each
           client's CA bundle with `openssl verify`.  Faster, but only proves
           what the bundle says, not what the client does with it.

Examples
--------
    python3 checking/check_trust.py                 # local lab, full report
    python3 checking/check_trust.py --mode offline  # no servers, bundles only
    python3 checking/check_trust.py --json out.json --quick

Exit status is 1 when at least one installed client accepts a chain, so this
can be used as a CI-style canary.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import plistlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CACHE = HERE / ".cache"
sys.path.insert(0, str(HERE))

from lab import Lab, LabError, split_pem  # noqa: E402

VERSION = "1.0"

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


@dataclass
class Proc:
    rc: int
    out: str
    err: str


def sh(cmd: list[str], *, timeout: float = 8, input_text: str | None = None,
       env: dict | None = None, cwd: Path | None = None) -> Proc:
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=str(cwd) if cwd else None,
        )
        return Proc(proc.returncode, proc.stdout, proc.stderr)
    except FileNotFoundError:
        return Proc(127, "", f"{cmd[0]}: not found")
    except subprocess.TimeoutExpired:
        return Proc(124, "", "timed out")


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def first_line(text: str) -> str:
    return text.strip().splitlines()[0].strip() if text.strip() else ""


def vnum(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", text)[:8])


def vs_fixed(installed: str, fixed: str) -> str | None:
    """Compare an installed version with the disclosure's fixed version(s)."""
    if not installed or not fixed or fixed.strip().lower() == "pending":
        return None
    vi = vnum(installed)
    if not vi:
        return None
    for candidate in fixed.split(","):
        c = candidate.strip()
        if not c or c.lower() == "pending":
            continue
        vc = vnum(c)
        if vc and vi >= vc:
            return "patched"
    return "outdated"


def load_patched(html_path: Path | None) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Fixed versions, from the disclosure snapshot or the bundled JSON."""
    if html_path is not None and html_path.is_file():
        text = html_path.read_text(errors="replace")
        match = re.search(r"<table id=patched>(.*?)</table>", text, re.S)
        if match:
            rows: list[tuple[str, str]] = []
            for name, fixed in re.findall(r"<tr><td>(.*?)<td>(.*?)</tr>", match.group(1), re.S):
                clean = lambda s: re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s)).strip()
                rows.append((clean(name), clean(fixed).replace(" ,", ",")))
            if rows:
                return rows, {n: f for n, f in rows}
    bundled = HERE / "patched_versions.json"
    if bundled.is_file():
        data = json.loads(bundled.read_text())
        return list(data.items()), data
    return [], {}


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------


@dataclass
class Result:
    key: str
    name: str
    installed: bool = True
    version: str = ""
    fixed: str = ""
    store: str = ""
    method: str = ""
    accepted: int | None = None
    total: int | None = None
    verdict: str = ""
    note: str = ""
    group: str = "runtime"
    items: list = field(default_factory=list)

    def finalize(self) -> "Result":
        if not self.installed:
            self.verdict = "N/A"
        elif self.accepted is not None and self.total:
            self.verdict = "TRUSTS" if self.accepted else "REJECTS"
        elif self.verdict:
            pass
        else:
            state = vs_fixed(self.version, self.fixed)
            self.verdict = {"patched": "PATCHED", "outdated": "OUTDATED"}.get(state or "", "UNKNOWN")
        return self


def accepted_text(r: Result) -> str:
    unit = " CAs" if r.method.startswith("security") else ""
    if r.verdict == "TRUSTS" and r.accepted is not None:
        return f"TRUSTS {r.accepted}/{r.total}{unit}"
    if r.verdict == "REJECTS":
        return f"rejects 0/{r.total}{unit}"
    if r.verdict == "PATCHED":
        return "patched"
    if r.verdict == "OUTDATED":
        return "outdated"
    if r.verdict == "N/A":
        return "-"
    return "unknown"


# ---------------------------------------------------------------------------
# client probes (one handshake per chain)
# ---------------------------------------------------------------------------


def p_curl(chain, timeout):
    r = sh(["curl", "-sS", "-m", str(timeout), "-o", "/dev/null",
            "-w", "%{http_code}", chain.url], timeout=timeout + 4)
    detail = first_line(r.err) or f"exit {r.rc}"
    return (r.rc == 0 and r.out.strip() == "200"), detail


def p_openssl(chain, timeout):
    r = sh(["openssl", "s_client", "-connect", f"127.0.0.1:{chain.port}",
            "-servername", "localhost", "-verify_return_error", "-brief"],
           timeout=timeout + 4, input_text="")
    text = r.out + r.err
    ok = r.rc == 0 and "Verification: OK" in text
    detail = ""
    for line in text.splitlines():
        if "verify error" in line or "Verification error" in line or "Verification: OK" in line:
            detail = line.strip()
    return ok, detail or first_line(r.err)


def p_python(chain, timeout):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(("127.0.0.1", chain.port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost"):
                return True, "connected"
    except Exception as exc:  # noqa: BLE001 - report the client's own error
        return False, f"{type(exc).__name__}: {exc}"


def p_certifi(chain, timeout):
    try:
        import certifi

        ctx = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection(("127.0.0.1", chain.port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost"):
                return True, "connected"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


NODE_SCRIPT = """
const https = require('https');
const url = process.argv[1];
const req = https.get(url, {timeout: 8000, servername: 'localhost'}, res => {
  console.log('OK', res.statusCode); res.destroy(); process.exit(0);
});
req.on('error', e => { console.log('ERR', e.code || e.message); process.exit(1); });
req.on('timeout', () => { req.destroy(new Error('timeout')); });
"""

BUN_SCRIPT = """
try {
  const r = await fetch(process.argv[1]);
  console.log('OK', r.status); process.exit(0);
} catch (e) {
  console.log('ERR', e.code || e.message); process.exit(1);
}
"""


def p_node(chain, timeout):
    r = sh(["node", "-e", NODE_SCRIPT, chain.url], timeout=timeout + 6)
    ok = r.rc == 0 and r.out.startswith("OK")
    return ok, first_line(r.out) or first_line(r.err)


def p_bun(chain, timeout):
    r = sh(["bun", "-e", BUN_SCRIPT, chain.url], timeout=timeout + 6)
    ok = r.rc == 0 and r.out.startswith("OK")
    return ok, first_line(r.out) or first_line(r.err)


def p_ruby(chain, timeout):
    script = (
        "require 'net/http'; require 'uri'; "
        f"begin; Net::HTTP.get_response(URI({chain.url!r})); puts 'OK'; "
        "rescue => e; puts 'ERR ' + e.class.to_s; exit 1; end"
    )
    r = sh(["ruby", "-e", script], timeout=timeout + 6)
    return r.out.startswith("OK"), first_line(r.out) or first_line(r.err)


JAVA_SRC = """
import java.net.*;
import javax.net.ssl.*;

public class HttpsCheck {
    public static void main(String[] args) {
        try {
            HttpsURLConnection c = (HttpsURLConnection) new URL(args[0]).openConnection();
            c.setConnectTimeout(6000);
            c.setReadTimeout(6000);
            c.getResponseCode();
            System.out.println("OK");
        } catch (Exception e) {
            System.out.println("ERR " + e);
            System.exit(1);
        }
    }
}
"""

GO_SRC = """
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	tr := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "localhost"}}
	c := &http.Client{Transport: tr, Timeout: 6 * time.Second}
	r, err := c.Get(os.Args[1])
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(1)
	}
	fmt.Println("OK", r.StatusCode)
	r.Body.Close()
}
"""


class Helpers:
    """Compile the Java / Go probe programs once per run."""

    def __init__(self, cache: Path):
        self.cache = cache
        self.dir = cache / "helpers"
        self.lock = threading.Lock()
        self.java: Path | None = None
        self.go: Path | None = None
        self.java_error = ""
        self.go_error = ""

    def ensure_java(self) -> Path | None:
        with self.lock:
            if self.java is not None or self.java_error:
                return self.java
            if not (have("java") and have("javac")):
                self.java_error = "javac not found"
                return None
            self.dir.mkdir(parents=True, exist_ok=True)
            src = self.dir / "HttpsCheck.java"
            src.write_text(JAVA_SRC)
            r = sh(["javac", "--release", "11", "-d", str(self.dir), str(src)], timeout=90)
            if r.rc != 0:
                self.java_error = first_line(r.err)
                return None
            self.java = self.dir
            return self.java

    def ensure_go(self) -> Path | None:
        with self.lock:
            if self.go is not None or self.go_error:
                return self.go
            if not have("go"):
                self.go_error = "go not found"
                return None
            gdir = self.dir / "gohttp"
            gdir.mkdir(parents=True, exist_ok=True)
            (gdir / "main.go").write_text(GO_SRC)
            (gdir / "go.mod").write_text("module gohttp\n\ngo 1.21\n")
            env = os.environ.copy()
            env["GOCACHE"] = str(self.cache / "go-build")
            env["GOTOOLCHAIN"] = "local"
            r = sh(["go", "build", "-o", "gohttp", "."], timeout=120, env=env, cwd=gdir)
            if r.rc != 0:
                self.go_error = first_line(r.err)
                return None
            self.go = gdir / "gohttp"
            return self.go


def probe_java(chain, timeout, helpers: Helpers):
    cp = helpers.ensure_java()
    if cp is None:
        return None, helpers.java_error
    r = sh(["java", "-cp", str(cp), "HttpsCheck", chain.url], timeout=timeout + 10)
    return r.out.startswith("OK"), first_line(r.out) or first_line(r.err)


def probe_go(chain, timeout, helpers: Helpers):
    binary = helpers.ensure_go()
    if binary is None:
        return None, helpers.go_error
    r = sh([str(binary), chain.url], timeout=timeout + 6)
    return r.out.startswith("OK"), first_line(r.out) or first_line(r.err)


# ---------------------------------------------------------------------------
# context
# ---------------------------------------------------------------------------


class Ctx:
    def __init__(self, args):
        self.args = args
        self.mode = args.mode
        self.timeout = args.timeout
        self.cache = CACHE
        self.helpers = Helpers(CACHE)
        self.chains_dir = Path(args.chains).expanduser().resolve()
        self.chain_files = sorted(self.chains_dir.glob("*.pem"))
        self.openssl = shutil.which("openssl") or "openssl"
        self.servers = []
        self.limited = bool(args.top)
        self._local: dict[str, tuple[int, int, str]] | None = None
        self._java: dict[str, tuple[int, int, str]] = {}
        self._lock = threading.Lock()
        disclosure = Path(args.disclosure).expanduser().resolve() if args.disclosure else None
        self.patched_rows, self.patched = load_patched(disclosure)

    # -- local lab ------------------------------------------------------

    def start_lab(self):
        CACHE.mkdir(parents=True, exist_ok=True)
        self.lab = Lab(ROOT, CACHE, self.openssl, keys=getattr(self.args, "keys", None))
        files = self.chain_files if self.limited else None
        self.lab.prepare(self.chains_dir, files=files)
        self.servers = self.lab.start()
        return self.servers

    def stop_lab(self):
        if getattr(self, "lab", None):
            self.lab.cleanup()

    # -- bundle check ---------------------------------------------------

    def bundle_counts(self, bundle: Path) -> tuple[int, int]:
        accepted = 0
        for chain in self.chain_files:
            r = sh([self.openssl, "verify", "-CAfile", str(bundle),
                    "-untrusted", str(chain), str(chain)], timeout=15)
            if r.rc == 0:
                accepted += 1
        return accepted, len(self.chain_files)

    # -- local handshakes ----------------------------------------------

    def local(self) -> dict[str, tuple[int, int, str]]:
        """Run every installed client against every local chain once."""
        if self._local is not None:
            return self._local
        if not self.servers:
            self._local = {}
            return self._local

        clients = {
            "curl": p_curl,
            "openssl": p_openssl,
            "python": p_python,
            "certifi": p_certifi,
            "node": p_node,
            "bun": p_bun,
            "ruby": p_ruby,
        }
        if self.helpers.ensure_java():
            clients["java"] = lambda c, t: probe_java(c, t, self.helpers)
        if self.helpers.ensure_go():
            clients["go"] = lambda c, t: probe_go(c, t, self.helpers)

        tasks = [(name, fn, chain) for name, fn in clients.items() for chain in self.servers]
        results: dict[str, list] = {name: [] for name in clients}
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {
                pool.submit(fn, chain, self.timeout): (name, chain)
                for name, fn, chain in tasks
            }
            for fut in futures:
                name, chain = futures[fut]
                try:
                    ok, detail = fut.result()
                except Exception as exc:  # noqa: BLE001
                    ok, detail = None, f"{type(exc).__name__}: {exc}"
                results[name].append((ok, detail))

        summary = {}
        for name, values in results.items():
            good = sum(1 for ok, _ in values if ok)
            failures = [d for ok, d in values if not ok and d]
            summary[name] = (good, len(values), failures[0] if failures else "")
        self._local = summary
        return summary

    def java_local(self, home: Path, classes: Path) -> tuple[int, int, str]:
        """Handshake results for one specific JVM, cached per home."""
        key = str(home)
        with self._lock:
            cached = self._java.get(key)
        if cached is not None:
            return cached
        values = []
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(probe_java_home, home, chain, self.timeout, classes)
                       for chain in self.servers]
            for fut in futures:
                try:
                    values.append(fut.result())
                except Exception as exc:  # noqa: BLE001
                    values.append((None, f"{type(exc).__name__}: {exc}"))
        good = sum(1 for ok, _ in values if ok)
        failures = [d for ok, d in values if not ok and d]
        result = (good, len(values), failures[0] if failures else "")
        with self._lock:
            self._java[key] = result
        return result

    # -- macOS keychain -------------------------------------------------

    def macos_ca_check(self) -> tuple[int | None, int | None, str]:
        if sys.platform != "darwin" or not shutil.which("security"):
            return None, None, "not macOS"
        if not self.servers:
            return None, None, "needs the local lab (run without --mode offline)"

        picks = [c for c in self.servers if c.name.startswith("dv-g3b")]
        ok = 0
        detail = ""
        for chain in picks:
            blocks = split_pem(chain.path.read_text())[1:]  # drop the minted leaf
            cmd = ["security", "verify-cert", "-p", "ssl", "-l", "-L"]
            temp = []
            for i, block in enumerate(blocks):
                path = self.cache / f"keychain-{chain.name}-{i}.pem"
                path.write_text(block + "\n")
                cmd += ["-c", str(path)]
                temp.append(path)
            r = sh(cmd, timeout=15)
            text = r.out + r.err
            if "certificate verification successful" in text:
                ok += 1
            for line in text.splitlines():
                if "Cert Verify Result" in line or "CSSMERR" in line:
                    detail = line.strip()
        return ok, len(picks), detail

    # -- misc -----------------------------------------------------------

    def brew_version(self, formula: str) -> str:
        if not have("brew"):
            return ""
        r = sh(["brew", "list", "--versions", formula], timeout=25)
        parts = r.out.split()
        return parts[1] if len(parts) > 1 else ""


# ---------------------------------------------------------------------------
# technology probes
# ---------------------------------------------------------------------------


def t_macos(ctx: Ctx) -> Result:
    accepted, total, detail = ctx.macos_ca_check()
    note = "synthetic leaves fail Apple's CT policy, so the CA itself is tested"
    return Result(
        "macos", "macOS Security.framework", version=platform.mac_ver()[0],
        store="System keychain",
        method="security verify-cert -p ssl -l" if accepted is not None else "n/a",
        accepted=accepted, total=total, note=f"{detail}; {note}" if detail else note,
        group="system",
    )


def t_homebrew(ctx: Ctx) -> Result:
    version = ctx.brew_version("ca-certificates")
    prefix = first_line(sh(["brew", "--prefix"], timeout=20).out) if have("brew") else ""
    bundle = Path(prefix) / "etc" / "ca-certificates" / "cert.pem" if prefix else None
    if not version or bundle is None or not bundle.is_file():
        return Result("homebrew", "Homebrew ca-certificates", installed=False)
    accepted, total = ctx.bundle_counts(bundle)
    return Result("homebrew", "Homebrew ca-certificates", version=version,
                  store=str(bundle), method="openssl verify -CAfile",
                  accepted=accepted, total=total, group="ca-store")


def t_openssl(ctx: Ctx) -> Result:
    version = first_line(sh(["openssl", "version"], timeout=10).out)
    version = version.replace("OpenSSL ", "").split(" ")[0]
    store = ""
    r = sh(["openssl", "version", "-d"], timeout=10)
    m = re.search(r'"(.*?)"', r.out)
    if m:
        store = str(Path(m.group(1)) / "cert.pem")
    local = ctx.local().get("openssl") if ctx.mode == "local" else None
    if local:
        accepted, total, detail = local
        return Result("openssl", "OpenSSL", version=version, store=store,
                      method="live handshake, local lab", accepted=accepted,
                      total=total, note=detail, group="runtime")
    if store and Path(store).is_file():
        accepted, total = ctx.bundle_counts(Path(store))
        return Result("openssl", "OpenSSL", version=version, store=store,
                      method="openssl verify -CAfile", accepted=accepted,
                      total=total, group="runtime")
    return Result("openssl", "OpenSSL", version=version, store=store, group="runtime")


def t_curl(ctx: Ctx) -> Result:
    version = first_line(sh(["curl", "--version"], timeout=10).out).split(" ")[1]
    candidates = ["/etc/ssl/cert.pem", "/etc/pki/tls/certs/ca-bundle.crt",
                  "/etc/ssl/certs/ca-certificates.crt"]
    store = next((p for p in candidates if Path(p).is_file()), "")
    local = ctx.local().get("curl") if ctx.mode == "local" else None
    if local:
        accepted, total, detail = local
        return Result("curl", "curl", version=version, store=store,
                      method="live handshake, local lab", accepted=accepted,
                      total=total, note=detail, group="runtime")
    if store:
        accepted, total = ctx.bundle_counts(Path(store))
        return Result("curl", "curl", version=version, store=store,
                      method="openssl verify -CAfile", accepted=accepted,
                      total=total, group="runtime")
    return Result("curl", "curl", version=version, store=store, group="runtime")


def t_python_ssl(ctx: Ctx) -> Result:
    version = f"{platform.python_version()} / {ssl.OPENSSL_VERSION.split()[1]}"
    paths = ssl.get_default_verify_paths()
    store = paths.cafile or ""
    local = ctx.local().get("python") if ctx.mode == "local" else None
    if local:
        accepted, total, detail = local
        return Result("python", "Python ssl (default context)", version=version,
                      store=store, method="live handshake, local lab",
                      accepted=accepted, total=total, note=detail, group="runtime")
    if store:
        accepted, total = ctx.bundle_counts(Path(store))
        return Result("python", "Python ssl (default context)", version=version,
                      store=store, method="openssl verify -CAfile",
                      accepted=accepted, total=total, group="runtime")
    return Result("python", "Python ssl (default context)", version=version, group="runtime")


def t_certifi(ctx: Ctx) -> Result:
    try:
        import certifi
    except ImportError:
        return Result("certifi", "Python certifi", installed=False)
    local = ctx.local().get("certifi") if ctx.mode == "local" else None
    if local:
        accepted, total, detail = local
        return Result("certifi", "Python certifi", version=certifi.__version__,
                      store=certifi.where(), method="live handshake, local lab",
                      accepted=accepted, total=total, note=detail, group="ca-store")
    accepted, total = ctx.bundle_counts(Path(certifi.where()))
    return Result("certifi", "Python certifi", version=certifi.__version__,
                  store=certifi.where(), method="openssl verify -CAfile",
                  accepted=accepted, total=total, group="ca-store")


def t_pip(ctx: Ctx) -> Result:
    r = sh([sys.executable, "-m", "pip", "--version"], timeout=25)
    if r.rc != 0:
        return Result("pip", "pip", installed=False)
    version = first_line(r.out).split(" ")[1]
    r2 = sh([sys.executable, "-c",
             "import pip._vendor.certifi as c; print(c.where())"], timeout=20)
    bundle = first_line(r2.out)
    if bundle and Path(bundle).is_file():
        accepted, total = ctx.bundle_counts(Path(bundle))
        return Result("pip", "pip", version=version, store=bundle,
                      method="openssl verify on vendored certifi",
                      accepted=accepted, total=total, group="runtime")
    return Result("pip", "pip", version=version, group="runtime")


def t_uv(ctx: Ctx) -> Result:
    if not have("uv"):
        return Result("uv", "uv", installed=False)
    r = sh(["uv", "--version"], timeout=10)
    version = first_line(r.out).split(" ")[1]
    return Result("uv", "uv", version=version, store="rustls / webpki-roots (compiled in)",
                  method="version only", group="runtime",
                  note="no way to enumerate the compiled-in store offline")


def t_node(ctx: Ctx) -> Result:
    if not have("node"):
        return Result("node", "Node.js", installed=False)
    version = first_line(sh(["node", "-v"], timeout=10).out).lstrip("v")
    local = ctx.local().get("node") if ctx.mode == "local" else None
    if local:
        accepted, total, detail = local
        store = ""
        r = sh(["node", "-p", "require('tls').rootCertificates.length"], timeout=10)
        if r.rc == 0:
            store = f"tls.rootCertificates ({first_line(r.out)} roots)"
        return Result("node", "Node.js", version=version, store=store,
                      method="live handshake, local lab", accepted=accepted,
                      total=total, note=detail, group="runtime")
    r = sh(["node", "-e",
            "process.stdout.write(require('tls').rootCertificates.join('\\n'))"], timeout=25)
    if r.rc == 0 and "BEGIN CERTIFICATE" in r.out:
        bundle = ctx.cache / "node-roots.pem"
        bundle.parent.mkdir(parents=True, exist_ok=True)
        bundle.write_text(r.out)
        accepted, total = ctx.bundle_counts(bundle)
        return Result("node", "Node.js", version=version,
                      store="tls.rootCertificates", method="openssl verify -CAfile",
                      accepted=accepted, total=total, group="runtime")
    return Result("node", "Node.js", version=version, group="runtime")


def t_npm(ctx: Ctx) -> Result:
    if not have("npm"):
        return Result("npm", "npm", installed=False)
    version = first_line(sh(["npm", "-v"], timeout=20).out)
    node = t_node(ctx)
    return Result("npm", "npm", version=version, store="Node's root store",
                  method=node.method, accepted=node.accepted, total=node.total,
                  note="uses the Node.js store", group="runtime")


def t_bun(ctx: Ctx) -> Result:
    if not have("bun"):
        return Result("bun", "Bun", installed=False)
    version = first_line(sh(["bun", "--version"], timeout=10).out)
    local = ctx.local().get("bun") if ctx.mode == "local" else None
    if local:
        accepted, total, detail = local
        return Result("bun", "Bun", version=version, store="BoringSSL, compiled-in roots",
                      method="live handshake, local lab", accepted=accepted,
                      total=total, note=detail, group="runtime")
    return Result("bun", "Bun", version=version, store="BoringSSL, compiled-in roots",
                  method="version only", group="runtime")


def t_go(ctx: Ctx) -> Result:
    if not have("go"):
        return Result("go", "Go", installed=False)
    r = sh(["go", "version"], timeout=15)
    m = re.search(r"go(\d+\.\d+\.\d+)", r.out)
    version = m.group(1) if m else ""
    local = ctx.local().get("go") if ctx.mode == "local" else None
    if local:
        accepted, total, detail = local
        return Result("go", "Go", version=version,
                      store="crypto/x509 system pool", method="live handshake, local lab",
                      accepted=accepted, total=total, note=detail, group="runtime")
    return Result("go", "Go", version=version, store="crypto/x509 system pool",
                  method="version only", group="runtime",
                  note="Go 1.27 rejects these CA certificates outright: x509: not standards compliant")


def java_homes() -> list[dict]:
    """Every JVM this machine can see, the default one first."""
    homes: list[dict] = []
    seen: set[Path] = set()

    def add(home: Path, default: bool) -> None:
        try:
            resolved = home.resolve()
        except OSError:
            return
        if resolved in seen or not (home / "bin" / "java").exists():
            return
        seen.add(resolved)
        release: dict[str, str] = {}
        meta = home / "release"
        if meta.is_file():
            for line in meta.read_text(errors="replace").splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    release[key.strip()] = value.strip().strip('"')
        homes.append({"home": home, "release": release, "default": default})

    if sys.platform == "darwin" and Path("/usr/libexec/java_home").exists():
        r = sh(["/usr/libexec/java_home"], timeout=10)
        if r.rc == 0 and r.out.strip():
            add(Path(r.out.strip()), True)
    for base in (Path("/Library/Java/JavaVirtualMachines"),
                 Path.home() / "Library" / "Java" / "JavaVirtualMachines"):
        if not base.is_dir():
            continue
        # .jdk bundles (Temurin) and bare JBRs (IntelliJ) live side by side
        for entry in sorted(base.iterdir()):
            add(entry / "Contents" / "Home", False)
    return homes


def java_root_aliases(home: Path) -> list[str]:
    """Roots in this JVM's cacerts that matter for the compromise."""
    keytool = home / "bin" / "keytool"
    if not keytool.exists():
        return []
    r = sh([str(keytool), "-list", "-cacerts", "-storepass", "changeit"], timeout=30)
    hits = []
    for line in r.out.splitlines():
        alias = line.split(",")[0].strip().lower()
        if "emsign" in alias or "aaa_certificate" in alias:
            hits.append(alias)
    return hits


def probe_java_home(home: Path, chain, timeout: float, classes: Path) -> tuple[bool, str]:
    r = sh([str(home / "bin" / "java"), "-cp", str(classes), "HttpsCheck", chain.url],
           timeout=timeout + 10)
    return r.out.startswith("OK"), first_line(r.out) or first_line(r.err)


def export_cacerts(home: Path, cache: Path) -> Path | None:
    """Turn a JVM's cacerts into a PEM bundle for `openssl verify`."""
    keytool = home / "bin" / "keytool"
    if not keytool.exists():
        return None
    r = sh([str(keytool), "-list", "-rfc", "-cacerts", "-storepass", "changeit"], timeout=40)
    if r.rc != 0 or "BEGIN CERTIFICATE" not in r.out:
        return None
    bundle = cache / "java" / (home.parent.parent.name + "-" + home.parent.name + ".pem")
    bundle.parent.mkdir(parents=True, exist_ok=True)
    bundle.write_text("\n".join(split_pem(r.out)) + "\n")
    return bundle


def t_java(ctx: Ctx) -> list[Result]:
    homes = java_homes()
    if not homes:
        return [Result("java", "Java", installed=False)]

    classes = ctx.helpers.ensure_java()
    results: list[Result] = []
    for entry in homes:
        home: Path = entry["home"]
        release = entry["release"]
        version = release.get("JAVA_VERSION", "")
        implementor = (release.get("IMPLEMENTOR", "")
                       .replace("Eclipse Adoptium", "Temurin")
                       .replace("s.r.o.", "").strip())
        label = f"Java {version}" + (f" ({implementor})" if implementor else "")
        if entry["default"]:
            label += " [default]"
        store = str(home / "lib" / "security" / "cacerts")
        aliases = java_root_aliases(home)

        local = None
        if ctx.mode == "local" and classes is not None and ctx.servers:
            local = ctx.java_local(home, classes)

        if local:
            accepted, total, detail = local
            result = Result("java", label, version=version, store=store,
                            method="live handshake, local lab",
                            accepted=accepted, total=total,
                            note=detail, group="runtime")
        else:
            bundle = export_cacerts(home, ctx.cache)
            if bundle is not None:
                accepted, total = ctx.bundle_counts(bundle)
                result = Result("java", label, version=version, store=store,
                                method="openssl verify on exported cacerts",
                                accepted=accepted, total=total, group="runtime",
                                note="contains " + ", ".join(aliases) if aliases else "")
            elif aliases:
                result = Result("java", label, version=version, store=store,
                                method="cacerts inspection", verdict="OUTDATED",
                                group="runtime", note="contains " + ", ".join(aliases))
            else:
                result = Result("java", label, version=version, store=store,
                                method="cacerts inspection", verdict="PATCHED",
                                group="runtime", note="no emSign/AAA roots in cacerts")
        result.items = [{"home": str(home), "aliases": aliases,
                         "default": entry["default"]}]
        results.append(result)
    return results


def t_ruby(ctx: Ctx) -> Result:
    if not have("ruby"):
        return Result("ruby", "Ruby", installed=False)
    version = first_line(sh(["ruby", "-v"], timeout=20).out).split(" ")[1]
    r = sh(["ruby", "-ropenssl", "-e", "print OpenSSL::X509::DEFAULT_CERT_FILE"], timeout=25)
    store = first_line(r.out)
    local = ctx.local().get("ruby") if ctx.mode == "local" else None
    if local:
        accepted, total, detail = local
        return Result("ruby", "Ruby", version=version, store=store,
                      method="live handshake, local lab", accepted=accepted,
                      total=total, note=detail, group="runtime")
    if store and Path(store).is_file():
        accepted, total = ctx.bundle_counts(Path(store))
        return Result("ruby", "Ruby", version=version, store=store,
                      method="openssl verify -CAfile", accepted=accepted,
                      total=total, group="runtime")
    return Result("ruby", "Ruby", version=version, store=store, group="runtime")


def t_nss(ctx: Ctx) -> Result:
    version = ctx.brew_version("nss")
    if not version:
        return Result("nss", "NSS", installed=False)
    return Result("nss", "NSS", version=version, store="libnssckbi (built-in roots)",
                  method="version only", group="ca-store",
                  note="Firefox-family apps ship their own NSS; check those separately")


def read_plist(path: Path) -> dict:
    try:
        with path.open("rb") as fh:
            return plistlib.load(fh)
    except Exception:  # noqa: BLE001 - a broken app bundle is not an error here
        return {}


ELECTRON_ROOTS = ("/Applications", "/Applications/Utilities")


ROOT_MARKERS = {
    "g3": b"emSign ECC Root CA - G3",
    "aaa": b"AAA Certificate Services",
}


def count_marker(path: Path, needle: bytes, chunk: int = 8 << 20) -> int:
    """Occurrences of a byte string in a (large) binary."""
    if not path.is_file():
        return 0
    total = 0
    tail = b""
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            total += (tail + block).count(needle)
            tail = block[-(len(needle) - 1):] if len(block) >= len(needle) else block
    return total


def electron_apps(deep: bool = False) -> list[dict]:
    """Every .app in the usual places that embeds the Electron framework."""
    roots = [Path(p) for p in ELECTRON_ROOTS] + [Path.home() / "Applications"]
    found: list[dict] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for app in sorted(root.glob("*.app")):
            resolved = app.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            framework = app / "Contents" / "Frameworks" / "Electron Framework.framework"
            if not framework.is_dir():
                continue
            framework_version = ""
            for candidate in (
                framework / "Versions" / "A" / "Resources" / "Info.plist",
                framework / "Versions" / "Current" / "Resources" / "Info.plist",
                framework / "Resources" / "Info.plist",
            ):
                if not candidate.is_file():
                    continue
                info = read_plist(candidate)
                framework_version = (info.get("CFBundleVersion")
                                     or info.get("CFBundleShortVersionString") or "")
                if framework_version:
                    break
            meta = read_plist(app / "Contents" / "Info.plist")
            entry = {
                "name": meta.get("CFBundleName") or app.stem,
                "app_version": meta.get("CFBundleShortVersionString", ""),
                "electron": framework_version,
                "path": str(app),
            }
            if deep:
                binary = framework / "Versions" / "A" / "Electron Framework"
                entry["roots"] = {name: count_marker(binary, marker)
                                  for name, marker in ROOT_MARKERS.items()}
            found.append(entry)
    return found


def fix_for(version: str, fixed: str) -> str:
    """The smallest fixed release that covers `version`."""
    candidates = sorted({vnum(c) for c in fixed.split(",") if vnum(c)})
    if not candidates:
        return ""
    value = vnum(version)
    for candidate in candidates:
        if value <= candidate:
            return ".".join(str(part) for part in candidate)
    return ".".join(str(part) for part in candidates[-1])


def electron_patched(version: str, candidates: list[tuple[int, ...]]) -> bool:
    """The fix list is per major line: 42.11.16, 43.8.1, 44.9.1.

    A 44.x app needs 44.9.1, not 42.11.16; an app on a retired line (38.x)
    needs to move to any supported one.
    """
    value = vnum(version)
    if not value or not candidates:
        return False
    if value > max(candidates):
        return True
    same_line = [c for c in candidates if c[0] == value[0]]
    return bool(same_line) and value >= max(same_line)


def t_electron(ctx: Ctx) -> Result:
    apps = electron_apps(deep=getattr(ctx.args, 'deep', False))
    if not apps:
        return Result("electron", "Electron", installed=False)
    fixed = ctx.patched.get("Electron", "")
    candidates = [vnum(c) for c in fixed.split(",") if vnum(c)]
    outdated = 0
    for app in apps:
        app["patched"] = electron_patched(app["electron"], candidates)
        app["fix"] = fix_for(app["electron"], fixed)
        if not app["patched"]:
            outdated += 1
    verdict = "UNKNOWN" if not candidates else ("OUTDATED" if outdated else "PATCHED")
    note = f"{outdated} of {len(apps)} below the fixed release" if outdated else ""
    return Result("electron", "Electron", version=f"{len(apps)} apps",
                  store="Chromium root store + CRLSets", method="version only",
                  verdict=verdict, group="runtime", note=note, items=apps)


def sublime_installs() -> list[dict]:
    """Sublime Text bundles certifi for its Python plugin host."""
    found: list[dict] = []
    for base in (Path("/Applications"), Path.home() / "Applications"):
        if not base.is_dir():
            continue
        for app in sorted(base.glob("Sublime Text*.app")):
            bundle = app / "Contents" / "MacOS" / "Lib" / "python3" / "certifi" / "cacert.pem"
            if not bundle.is_file():
                continue
            meta = read_plist(app / "Contents" / "Info.plist")
            init = bundle.parent / "__init__.py"
            certifi_version = ""
            if init.is_file():
                match = re.search(r'__version__\s*=\s*["\']([^"\']+)',
                                  init.read_text(errors="replace"))
                if match:
                    certifi_version = match.group(1)
            found.append({
                "app": str(app),
                "build": meta.get("CFBundleShortVersionString", ""),
                "bundle": bundle,
                "certifi": certifi_version,
            })
    return found


def t_sublime(ctx: Ctx) -> list[Result]:
    installs = sublime_installs()
    if not installs:
        return [Result("sublime", "Sublime Text (plugin host)", installed=False)]
    results: list[Result] = []
    for item in installs:
        accepted, total = ctx.bundle_counts(item["bundle"])
        note = f"bundled certifi {item['certifi'] or '?'}"
        if sys.platform == "darwin":
            note += "; Package Control itself reads the macOS keychain"
        results.append(Result(
            "sublime", f"Sublime Text {item['build']} (plugin host)",
            version=item["certifi"] or item["build"],
            store=str(item["bundle"]),
            method="openssl verify on bundled certifi",
            accepted=accepted, total=total, note=note, group="runtime",
        ))
    return results


def t_rust(ctx: Ctx) -> Result:
    if have("rustc"):
        version = first_line(sh(["rustc", "--version"], timeout=15).out).split(" ")[1]
        return Result("rust", "Rust rustls-webpki / webpki-roots", version=version,
                      store="compiled into the crate", method="version only",
                      group="runtime", note="crate versions need a lockfile to check")
    return Result("rust", "Rust rustls-webpki / webpki-roots", installed=False)


def t_composer(ctx: Ctx) -> Result:
    if not have("composer"):
        return Result("composer", "Composer ca-bundle", installed=False)
    version = first_line(sh(["composer", "--version"], timeout=25).out).split(" ")[2] if have("composer") else ""
    return Result("composer", "Composer ca-bundle", version=version, group="runtime")


def t_elixir(ctx: Ctx) -> Result:
    if not have("elixir"):
        return Result("elixir", "Elixir castore", installed=False)
    version = first_line(sh(["elixir", "--version"], timeout=25).out)
    return Result("elixir", "Elixir castore", version=version, group="runtime")


def t_perl(ctx: Ctx) -> Result:
    if not have("perl"):
        return Result("perl", "Perl Mozilla::CA", installed=False)
    r = sh(["perl", "-MMozilla::CA", "-e", "print $Mozilla::CA::VERSION"], timeout=20)
    if r.rc != 0:
        return Result("perl", "Perl Mozilla::CA", installed=False,
                      note="perl is installed but the Mozilla::CA module is not")
    return Result("perl", "Perl Mozilla::CA", version=first_line(r.out), group="runtime")


def t_cfssl(ctx: Ctx) -> Result:
    if not have("cfssl"):
        return Result("cfssl", "Cloudflare CFSSL trust store", installed=False)
    return Result("cfssl", "Cloudflare CFSSL trust store", group="runtime")


def t_os_package(ctx: Ctx, key: str, name: str, distro: str) -> Result:
    if sys.platform != "linux":
        return Result(key, name, installed=False, note="not a Linux system")
    osr = Path("/etc/os-release")
    text = osr.read_text() if osr.is_file() else ""
    if f'ID={distro}' not in text and f'ID_LIKE="{distro}' not in text:
        return Result(key, name, installed=False, note="not this distribution")
    return Result(key, name, version="", group="ca-store")


TECHS = [
    ("macos", t_macos), ("homebrew", t_homebrew), ("openssl", t_openssl),
    ("curl", t_curl), ("python", t_python_ssl), ("certifi", t_certifi),
    ("pip", t_pip), ("uv", t_uv), ("node", t_node), ("npm", t_npm),
    ("bun", t_bun), ("go", t_go), ("java", t_java), ("ruby", t_ruby),
    ("nss", t_nss), ("electron", t_electron), ("sublime", t_sublime),
    ("rust", t_rust),
    ("composer", t_composer), ("elixir", t_elixir), ("perl", t_perl),
    ("cfssl", t_cfssl),
    ("ubuntu", lambda c: t_os_package(c, "ubuntu", "Ubuntu ca-certificates", "ubuntu")),
    ("debian", lambda c: t_os_package(c, "debian", "Debian ca-certificates", "debian")),
    ("arch", lambda c: t_os_package(c, "arch", "Arch Linux ca-certificates-mozilla", "arch")),
    ("gentoo", lambda c: t_os_package(c, "gentoo", "Gentoo ca-certificates", "gentoo")),
    ("fedora", lambda c: t_os_package(c, "fedora", "Fedora ca-certificates", "fedora")),
    ("freebsd", lambda c: t_os_package(c, "freebsd", "FreeBSD ca_root_nss", "freebsd")),
    ("chainguard", lambda c: t_os_package(c, "chainguard", "Chainguard ca-certificates", "chainguard")),
    ("alpine", lambda c: t_os_package(c, "alpine", "Alpine Linux ca-certificates", "alpine")),
]

# disclosure-table name -> result key, for the 'fixed in' column
FIXED_LOOKUP = {
    "macos": None,
    "homebrew": "Homebrew ca-certificates",
    "openssl": None,
    "curl": "curl CA bundle",
    "python": None,
    "certifi": "Python certifi",
    "pip": "pip",
    "uv": "uv",
    "node": "Node.js",
    "npm": None,
    "bun": "Bun",
    "go": "Go",
    "java": None,
    "ruby": None,
    "nss": "NSS",
    "electron": "Electron",
    "sublime": None,
    "rust": "Rust rustls-webpki",
    "composer": "Composer ca-bundle",
    "elixir": "Elixir castore",
    "perl": "Perl Mozilla::CA",
    "cfssl": "Cloudflare CFSSL trust store",
    "ubuntu": "Ubuntu ca-certificates",
    "debian": "Debian ca-certificates",
    "arch": "Arch Linux ca-certificates-mozilla",
    "gentoo": "Gentoo ca-certificates",
    "fedora": "Fedora ca-certificates",
    "freebsd": "FreeBSD ca_root_nss",
    "chainguard": "Chainguard ca-certificates",
    "alpine": "Alpine Linux ca-certificates",
}


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------


def shorten(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[: width - 3] + "..."


def method_short(method: str) -> str:
    if method.startswith("live handshake"):
        return "handshake"
    if method.startswith("openssl verify") or "cacerts" in method or "vendored" in method:
        return "bundle"
    if method.startswith("version"):
        return "version"
    if method.startswith("security"):
        return "keychain"
    return "-"


def render(results: list[Result], ctx: Ctx, elapsed: float) -> str:
    out = []
    out.append("")
    out.append("eMudhra intermediate CA compromise - local trust check")
    out.append("=" * 78)
    out.append(f"started   {time.strftime('%Y-%m-%d %H:%M:%S %z')}")
    out.append(f"mode      {ctx.mode}" + (
        f"  ({len(ctx.servers)} chains served on 127.0.0.1)" if ctx.servers else
        "  (bundles only, no sockets)"))
    out.append(f"chains    {len(ctx.chain_files)} from {ctx.chains_dir}")
    out.append("")

    installed = [r for r in results if r.installed]
    installed.sort(key=lambda r: (r.verdict != "TRUSTS", r.group, r.name))

    head = (f"{'TECH':<34} {'VERSION':<20} {'STORE':<32} "
            f"{'TEST':<10} {'RESULT':<15}")
    out.append(head)
    out.append("-" * len(head))
    for r in installed:
        out.append(
            f"{shorten(r.name, 34):<34} {shorten(r.version or '-', 20):<20} "
            f"{shorten(r.store or '-', 32):<32} {method_short(r.method):<10} "
            f"{accepted_text(r):<15}"
        )

    naive = [r for r in installed if r.verdict == "TRUSTS"]
    patched = [r for r in installed if r.verdict == "PATCHED"]
    unknown = [r for r in installed if r.verdict in ("UNKNOWN", "")]

    out.append("")
    if naive:
        out.append("STILL TRUSTS A COMPROMISED INTERMEDIATE")
        for r in naive:
            out.append(f"  - {r.name} {r.version}: accepts {r.accepted}/{r.total} chains")
            if r.note:
                out.append(f"    {shorten(r.note, 74)}")
    else:
        out.append("No installed client accepted a compromised chain.")

    if patched:
        out.append("")
        out.append("Patched by version (could not handshake-test): "
                   + ", ".join(f"{r.name} {r.version}" for r in patched))
    if unknown:
        out.append("")
        out.append("Unresolved: " + ", ".join(f"{r.name} {r.version}".strip() for r in unknown))

    missing = [r for r in results if not r.installed]
    if missing:
        out.append("")
        out.append("Not installed / not applicable here:")
        out.append("  " + ", ".join(r.name for r in missing))

    electron = next((r for r in results if r.key == "electron" and r.installed and r.items), None)
    if electron:
        out.append("")
        out.append(f"Electron applications ({len(electron.items)})")
        width = max(len(item["name"]) for item in electron.items) + 2
        version_width = max(len(item["app_version"]) for item in electron.items) + 2
        for item in sorted(electron.items, key=lambda i: (vnum(i["electron"]), i["name"])):
            status = "patched" if item["patched"] else f"outdated (needs {item['fix']}+)"
            out.append(
                f"  {item['name']:<{width}} {item['app_version']:<{version_width}} "
                f"Electron {item['electron']:<9} {status}"
                + (f"   roots g3={item['roots']['g3']} aaa={item['roots']['aaa']}"
                   if "roots" in item else "")
            )

    out.append("")
    browsers = installed_browsers()
    if browsers:
        out.append("Browsers installed (not exercised; they use their own root programmes):")
        out.append("  " + ", ".join(f"{name} {ver}".strip() for name, ver in browsers))
    out.append(f"finished in {elapsed:.1f}s")
    return "\n".join(out)


BROWSER_NAMES = ("Safari", "Chrome", "Chromium", "Firefox", "LibreWolf",
                 "Tor Browser", "Edge", "Brave", "Opera", "Vivaldi")


def installed_browsers() -> list[tuple[str, str]]:
    found = []
    for base in (Path("/Applications"), Path.home() / "Applications"):
        if not base.is_dir():
            continue
        for app in sorted(base.glob("*.app")):
            if not any(token in app.stem for token in BROWSER_NAMES):
                continue
            if "Profile" in app.stem or " Helper" in app.stem:
                continue
            info = app / "Contents" / "Info.plist"
            version = ""
            try:
                with info.open("rb") as fh:
                    version = plistlib.load(fh).get("CFBundleShortVersionString", "")
            except Exception:  # noqa: BLE001
                pass
            found.append((app.stem, version))
    return found


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def find_disclosure() -> Path | None:
    candidates = sorted((ROOT / "disclosure").glob("*Compromise*.html"))
    if not candidates:
        candidates = sorted((ROOT / "disclosure").glob("*.html"))
    return candidates[0] if candidates else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check which installed TLS clients still trust the compromised eMudhra intermediates.",
    )
    parser.add_argument("--mode", choices=["local", "offline"], default="local",
                        help="local lab handshakes (default) or bundle checks only")
    parser.add_argument("--chains", default=str(ROOT / "disclosure" / "chains"))
    parser.add_argument("--disclosure", default=str(find_disclosure() or ""))
    parser.add_argument("--keys", help="zip or directory with the recovered CA keys")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--json", nargs="?", const=str(HERE / "report.json"),
                        help="write machine-readable results (default checking/report.json)")
    parser.add_argument("--top", type=int, default=0,
                        help="only test the first N chains (debugging)")
    parser.add_argument("--deep", action="store_true",
                        help="also scan each Electron binary for the embedded roots (slow)")
    parser.add_argument("--only", default="",
                        help="comma-separated tech keys, e.g. java or java,curl")
    args = parser.parse_args(argv)

    wanted = {part.strip() for part in args.only.split(",") if part.strip()}

    started = time.time()
    ctx = Ctx(args)
    if args.top:
        ctx.chain_files = ctx.chain_files[: args.top]

    results: list[Result] = []
    try:
        if ctx.mode == "local":
            try:
                ctx.start_lab()
            except LabError as exc:
                print(f"error: {exc}", file=sys.stderr)
                print("hint: pass --keys PATH (zip or directory with the eight .pem/.key pairs), "
                      "or use --mode offline", file=sys.stderr)
                return 2
        for key, tech in TECHS:
            if wanted and key not in wanted:
                continue
            try:
                produced = tech(ctx)
            except Exception as exc:  # noqa: BLE001 - one broken probe must not kill the run
                produced = Result(key, key, verdict="UNKNOWN",
                                  note=f"probe failed: {type(exc).__name__}: {exc}")
            if isinstance(produced, Result):
                produced = [produced]
            for result in produced:
                table = FIXED_LOOKUP.get(result.key)
                if table and table in ctx.patched:
                    result.fixed = ctx.patched[table]
                results.append(result.finalize())
    finally:
        ctx.stop_lab()

    elapsed = time.time() - started
    print(render(results, ctx, elapsed))

    if args.json:
        payload = {
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "version": VERSION,
            "mode": args.mode,
            "chains": [c.name for c in ctx.servers] or [p.stem for p in ctx.chain_files],
            "results": [r.__dict__ for r in results],
        }
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"\nJSON written to {path}")

    return 1 if any(r.verdict == "TRUSTS" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
