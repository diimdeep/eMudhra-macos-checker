#!/usr/bin/env python3
"""Mark the compromised eMudhra intermediates "Never Trust" in the macOS keychain.

Chromium on macOS honors deny trust settings from the user and admin domains,
so one setting covers Chrome, Chromium, Edge, Brave, Opera, Vivaldi, Yandex and
Electron apps that use the system verifier.

The certificates come from the repo: the eight keys archive names the
compromised public keys, and every certificate in the chains archive that
carries one of those keys is a target (both the AAA-issued and the
emSign-issued copy of each intermediate; 14 in total). Roots and the emSign
cross-sign are not touched.

    python3 checking/distrust_keychain.py            # ask per certificate
    python3 checking/distrust_keychain.py --yes      # no questions
    python3 checking/distrust_keychain.py --admin    # System keychain, all users
    python3 checking/distrust_keychain.py --undo     # remove the settings again
    python3 checking/distrust_keychain.py --list     # show state, change nothing
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEYS_ZIP = ROOT / "keys" / "emudhra-intermediate-ca-keys.zip"
CHAINS_ZIP = ROOT / "disclosure" / "emudhra-test-host-chains.zip"
LOGIN_KEYCHAIN = Path.home() / "Library/Keychains/login.keychain-db"
SYSTEM_KEYCHAIN = Path("/Library/Keychains/System.keychain")

CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


@dataclass
class Target:
    pem: str
    sha256: str
    subject: str
    issuer: str
    path: Path | None = None


def run(cmd: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True)


def openssl(args: list[str], pem: str) -> str:
    r = run(["openssl", *args], stdin=pem)
    if r.returncode:
        sys.exit(f"openssl {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def spki_hash(pem: str) -> str:
    pub = openssl(["x509", "-pubkey", "-noout"], pem)
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"],
                         input=pub.encode(), capture_output=True, check=True).stdout
    return hashlib.sha256(der).hexdigest()


def read_certs(archive: Path, suffix: str = ".pem") -> list[str]:
    certs = []
    with zipfile.ZipFile(archive) as zf:
        for name in sorted(zf.namelist()):
            if name.endswith(suffix) and not name.startswith(("/", "..")):
                certs += CERT_RE.findall(zf.read(name).decode())
    return certs


def find_targets() -> list[Target]:
    key_certs = read_certs(KEYS_ZIP)
    bad_keys = {spki_hash(p) for p in key_certs}
    if len(bad_keys) != 8:
        sys.exit(f"expected 8 compromised keys in {KEYS_ZIP.name}, found {len(bad_keys)}")
    found: dict[str, Target] = {}
    # The keys archive carries the two code-signing CAs, which have no test host.
    for pem in key_certs + read_certs(CHAINS_ZIP):
        if spki_hash(pem) not in bad_keys:
            continue
        der_hash = hashlib.sha256(
            subprocess.run(["openssl", "x509", "-outform", "der"], input=pem.encode(),
                           capture_output=True, check=True).stdout).hexdigest()
        if der_hash in found:
            continue
        subject = openssl(["x509", "-noout", "-subject", "-nameopt", "RFC2253"], pem)
        issuer = openssl(["x509", "-noout", "-issuer", "-nameopt", "RFC2253"], pem)
        found[der_hash] = Target(
            pem, der_hash,
            subject.split("=", 1)[1].strip(), issuer.split("=", 1)[1].strip())
    # A compromised key also signs leaves; those are not CA certificates.
    targets = [t for t in found.values() if "CA:TRUE" in openssl(
        ["x509", "-noout", "-ext", "basicConstraints"], t.pem)]
    return sorted(targets, key=lambda t: (t.subject, t.issuer))


def short_cn(dn: str) -> str:
    m = re.search(r"CN=([^,]+)", dn)
    return m.group(1) if m else dn


def current_state(t: Target, admin: bool) -> str:
    cmd = ["security", "dump-trust-settings"] + (["-d"] if admin else [])
    r = run(cmd)
    text = r.stdout + r.stderr
    if "No Trust Settings" in text:
        return "no setting"
    # dump-trust-settings prints names, not hashes; match on subject CN and
    # confirm with the deny result code (3) that follows it.
    blocks = re.split(r"\n(?=Cert \d+:)", text)
    cn = short_cn(t.subject)
    for b in blocks:
        if f"Cert" in b and re.search(rf"Cert \d+: {re.escape(cn)}\n", b):
            if "kSecTrustSettingsResultDeny" in b:
                return "never trust"
            return "has settings"
    return "no setting"


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip().lower()
    except EOFError:
        return "q"


def apply(t: Target, tmp: Path, admin: bool, undo: bool) -> tuple[bool, str]:
    path = tmp / f"{t.sha256[:16]}.pem"
    path.write_text(t.pem + "\n")
    t.path = path
    if undo:
        cmd = ["security", "remove-trusted-cert"] + (["-d"] if admin else []) + [str(path)]
    else:
        keychain = SYSTEM_KEYCHAIN if admin else LOGIN_KEYCHAIN
        cmd = ["security", "add-trusted-cert", "-r", "deny"]
        cmd += ["-d"] if admin else []
        cmd += ["-k", str(keychain), str(path)]
    r = run(cmd)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def still_verifies(t: Target) -> bool:
    r = run(["security", "verify-cert", "-c", str(t.path), "-p", "ssl", "-L"])
    return "certificate verification successful" in (r.stdout + r.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--admin", action="store_true",
                    help="admin domain and System keychain (affects every user; asks for authorization)")
    ap.add_argument("--undo", action="store_true", help="remove the trust settings")
    ap.add_argument("--list", action="store_true", help="show targets and state, change nothing")
    ap.add_argument("--yes", "-y", action="store_true", help="do not ask per certificate")
    args = ap.parse_args()

    if sys.platform != "darwin":
        sys.exit("macOS only")
    for p in (KEYS_ZIP, CHAINS_ZIP):
        if not p.is_file():
            sys.exit(f"missing {p}")

    targets = find_targets()
    domain = "admin (System keychain)" if args.admin else "user (login keychain)"
    print(f"{len(targets)} compromised intermediate certificates, domain: {domain}\n")
    for i, t in enumerate(targets, 1):
        print(f"{i:2}. {short_cn(t.subject):22} issued by {short_cn(t.issuer):28} "
              f"{t.sha256[:8].upper()}  [{current_state(t, args.admin)}]")
    if args.list:
        return 0

    verb = "Remove Never Trust from" if args.undo else "Set Never Trust on"
    print(f"\nAnswers: y = yes, n = skip, a = yes to all remaining, q = quit\n")
    changed = failed = 0
    everything = args.yes
    with tempfile.TemporaryDirectory(prefix="emudhra-distrust-") as d:
        tmp = Path(d)
        for i, t in enumerate(targets, 1):
            label = f"{short_cn(t.subject)} / {short_cn(t.issuer)} {t.sha256[:8].upper()}"
            if not everything:
                a = ask(f"{verb} {label}? [y/n/a/q] ")
                if a == "q":
                    break
                if a == "a":
                    everything = True
                elif a != "y":
                    continue
            ok, msg = apply(t, tmp, args.admin, args.undo)
            if not ok:
                failed += 1
                print(f"  failed: {msg}")
                continue
            changed += 1
            if args.undo:
                print("  removed")
            else:
                blocked = not still_verifies(t)
                print("  never trust set" + ("" if blocked else "; security verify-cert still succeeds"))
    print(f"\n{changed} changed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
