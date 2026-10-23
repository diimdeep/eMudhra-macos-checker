#!/usr/bin/env python3
"""Patch Sublime Text's bundled certifi store and ad-hoc re-sign the app.

Sublime Text ships its own CA bundle at

    Sublime Text.app/Contents/MacOS/Lib/python3/certifi/cacert.pem

and the plugin host's Python imports that package, not the system store.  If it
is older than the certifi release that dropped the compromised eMudhra roots,
plugins keep trusting them.  Replacing the file breaks the code signature, so
the bundle has to be signed again; an ad-hoc signature is enough for local use.

    python3 checking/patch_sublime.py --dry-run     # show what would happen
    python3 checking/patch_sublime.py               # patch every Sublime install
    python3 checking/patch_sublime.py --restore     # put the original bundle back

Quit Sublime before running this.  App updates replace the bundle, so re-run
after every update.  Re-signing changes the app's identity: macOS may ask for
privacy permissions again, and Gatekeeper will no longer see a notarized
signature (the app still launches).  --restore puts the original files back
but keeps the ad-hoc signature; reinstall Sublime to get the vendor's back.
"""

from __future__ import annotations

import argparse
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from apps import app_bundles  # noqa: E402
from lab import LabError, resolve_chains  # noqa: E402

CERTIFI_REL = Path("Contents") / "MacOS" / "Lib" / "python3" / "certifi"
DEFAULT_BACKUP = Path.home() / "Library" / "Application Support" / "emudhra-check" / "sublime"


def sh(cmd: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timed out")


def fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def find_apps(explicit: list[str]) -> list[Path]:
    if explicit:
        return [Path(p).expanduser().resolve() for p in explicit]
    return list(app_bundles(pattern="Sublime Text*.app"))


def backup_path(app: Path, root: Path) -> Path:
    """Keep the original bundle outside the app: code inside Contents/MacOS
    must be signed, and an unsigned backup directory would break signing.

    Top-level apps keep the old `<stem>/certifi` path so existing backups are
    still found; apps in subfolders get the folder names in front.
    """
    for base in (Path("/Applications"), Path.home() / "Applications"):
        try:
            rel = app.relative_to(base)
        except ValueError:
            continue
        if len(rel.parts) > 1:
            return root / "__".join(rel.with_suffix("").parts) / "certifi"
    return root / app.stem / "certifi"


def certifi_dir(app: Path) -> Path | None:
    candidate = app / CERTIFI_REL
    if (candidate / "cacert.pem").is_file():
        return candidate
    return None


def read_build(app: Path) -> str:
    try:
        with (app / "Contents" / "Info.plist").open("rb") as fh:
            return plistlib.load(fh).get("CFBundleShortVersionString", "?")
    except Exception:  # noqa: BLE001
        return "?"


def read_certifi_version(package: Path) -> str:
    try:
        text = (package / "__init__.py").read_text(errors="replace")
    except OSError:
        return "?"
    for line in text.splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip("\"'")
    return "?"


def vnum(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", text))


def accepted_chains(bundle: Path, chains: list[Path]) -> tuple[int, int]:
    good = 0
    for chain in chains:
        result = sh(["openssl", "verify", "-CAfile", str(bundle),
                     "-untrusted", str(chain), str(chain)], timeout=20)
        if result.returncode == 0:
            good += 1
    return good, len(chains)


def candidate_sources() -> list[Path]:
    """Certifi packages installed elsewhere on the machine."""
    out: list[Path] = []
    probe = (
        "import certifi, sys; "
        "print(certifi.__version__); print(certifi.where())"
    )
    for python in ("python3",):
        result = sh([python, "-c", probe], timeout=30)
        if result.returncode != 0:
            continue
        lines = result.stdout.strip().splitlines()
        if len(lines) >= 2:
            out.append(Path(lines[1]).parent)
    probe_vendor = (
        "import pip._vendor.certifi as c; print(c.__version__); print(c.where())"
    )
    result = sh([sys.executable, "-c", probe_vendor], timeout=30)
    if result.returncode == 0:
        lines = result.stdout.strip().splitlines()
        if len(lines) >= 2:
            out.append(Path(lines[1]).parent)
    seen: set[Path] = set()
    unique = []
    for path in out:
        resolved = path.resolve()
        if resolved not in seen and (path / "cacert.pem").is_file():
            seen.add(resolved)
            unique.append(path)
    return unique


def choose_source(explicit: str | None, chains: list[Path]) -> Path:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if path.is_file():
            return path
        if (path / "cacert.pem").is_file():
            good, total = accepted_chains(path / "cacert.pem", chains)
            print(f"  candidate {read_certifi_version(path):<12} accepts {good}/{total}  {path}")
            if good:
                print("  warning: this bundle still accepts some chains", file=sys.stderr)
            return path
        fail(f"{path} is not a certifi package or PEM bundle")
    best: tuple[int, Path] | None = None
    for package in candidate_sources():
        good, total = accepted_chains(package / "cacert.pem", chains)
        version = read_certifi_version(package)
        print(f"  candidate {version:<12} accepts {good}/{total}  {package}")
        if good == 0 and (best is None or vnum(version) > vnum(read_certifi_version(best[1]))):
            best = (good, package)
    if best is None:
        fail("no installed certifi bundle rejects all chains; pass --source")
    return best[1]


def sign(path: Path, dry: bool) -> bool:
    if dry:
        print(f"  would sign {path}")
        return True
    result = sh(["codesign", "--force", "--timestamp=none", "--sign", "-", str(path)])
    if result.returncode != 0:
        print(f"  codesign failed for {path}: {result.stderr.strip()[:200]}", file=sys.stderr)
        return False
    return True


def install_package(source: Path, dest: Path) -> None:
    """Install a certifi package into `dest`, or a PEM bundle over its cacert.pem.

    Homebrew ships these as symlinks into its Cellar; dereference them, drop
    tests/__pycache__, and make everything writable so codesign can attach the
    per-file detached signatures macOS expects under Contents/MacOS.
    """
    if source.is_dir():
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True)
        for entry in sorted(source.iterdir()):
            if not entry.is_file():
                continue
            if entry.suffix not in (".py", ".pem", ".typed") and entry.name != "LICENSE":
                continue
            target = dest / entry.name
            shutil.copy2(entry, target)  # copy2 follows symlinks
            target.chmod(0o644)
    else:
        # A bare bundle replaces only the PEM; the package code stays.
        target = dest / "cacert.pem"
        shutil.copy2(source, target)
        target.chmod(0o644)


def resign(app: Path, dry: bool, package: Path | None = None) -> bool:
    # Files under Contents/MacOS carry their own detached signatures, so the
    # freshly copied resources have to be signed before the bundle.
    if package is not None and package.is_dir():
        for entry in sorted(package.iterdir()):
            if entry.is_file() and not entry.is_symlink():
                if not sign(entry, dry):
                    return False
    # The vendor's Mach-O signatures stay valid; only the new resources and
    # the bundle seal need signing.
    return sign(app, dry)


def verify_signature(app: Path) -> bool:
    result = sh(["codesign", "--verify", "--deep", "--strict", str(app)], timeout=180)
    if result.returncode != 0:
        print(f"  signature check failed: {result.stderr.strip()[:300]}", file=sys.stderr)
        return False
    return True


def running() -> bool:
    return sh(["pgrep", "-f", "Sublime Text.app/Contents/MacOS/sublime_text"]).returncode == 0


def patch_app(app: Path, source: Path, chains: list[Path], dry: bool,
              backup_root: Path) -> bool:
    package = certifi_dir(app)
    if package is None:
        print(f"skip {app}: no bundled certifi")
        return True
    backup = backup_path(app, backup_root)
    good, total = accepted_chains(package / "cacert.pem", chains)
    if backup.exists():
        if good == 0:
            print(f"skip {app}: already patched (backup at {backup}); use --restore")
            return True
        shutil.rmtree(backup)  # restored earlier, keep a fresh copy

    print(f"\n{app.name} (build {read_build(app)})")
    print(f"  current certifi {read_certifi_version(package)}: accepts {good}/{total}")

    if dry:
        print(f"  would back up {package} -> {backup}")
        print(f"  would install {source}")
        resign(app, dry, package)
        return True

    shutil.copytree(package, backup)
    install_package(source, package)

    good, total = accepted_chains(package / "cacert.pem", chains)
    print(f"  new certifi {read_certifi_version(package)}: accepts {good}/{total}")
    if good != 0:
        print("  warning: patched bundle still accepts chains", file=sys.stderr)

    if not resign(app, dry=False, package=package):
        fail(f"could not re-sign {app}; restore with --restore")
    if not verify_signature(app):
        fail(f"signature verification failed for {app}")

    resources = len([f for f in package.iterdir() if f.is_file()])
    print(f"  patched; {resources} resources and the bundle re-signed ad-hoc")
    return good == 0


def restore_app(app: Path, chains: list[Path], backup_root: Path) -> bool:
    package = certifi_dir(app)
    if package is None:
        print(f"skip {app}: no bundled certifi")
        return True
    backup = backup_path(app, backup_root)
    if not backup.is_dir():
        print(f"skip {app}: no backup found")
        return True

    shutil.rmtree(package)
    shutil.copytree(backup, package)
    for entry in package.rglob("*"):
        entry.chmod(0o755 if entry.is_dir() else 0o644)
    shutil.rmtree(backup)
    good, total = accepted_chains(package / "cacert.pem", chains)
    print(f"{app.name}: restored certifi {read_certifi_version(package)} (accepts {good}/{total})")
    if not resign(app, dry=False, package=package):
        fail(f"could not re-sign {app} after restore")
    return verify_signature(app)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replace Sublime Text's bundled certifi store and ad-hoc re-sign the app.",
    )
    parser.add_argument("--app", action="append", default=[],
                        help="Sublime Text.app to patch (repeatable; default: all found)")
    parser.add_argument("--source", help="certifi package or PEM bundle to install")
    parser.add_argument("--chains", help="directory or zip with the twelve chains")
    parser.add_argument("--restore", action="store_true", help="restore the original bundle")
    parser.add_argument("--backup-dir", default=str(DEFAULT_BACKUP),
                        help="where to keep the original bundle")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true", help="patch even if Sublime is running")
    parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    args = parser.parse_args(argv)

    try:
        chains_dir = resolve_chains(ROOT, HERE / ".cache", args.chains)
    except LabError as exc:
        fail(str(exc))
    chains = sorted(chains_dir.glob("*.pem"))
    if not chains:
        fail(f"no chains in {chains_dir}")

    apps = find_apps(args.app)
    if not apps:
        fail("no Sublime Text.app found; pass --app")

    if not args.restore and not args.dry_run and running() and not args.force:
        fail("Sublime Text is running; quit it first (or pass --force)")

    if args.restore:
        ok = True
        for app in apps:
            ok = restore_app(app, chains, Path(args.backup_dir).expanduser()) and ok
        return 0 if ok else 1

    print(f"chains: {len(chains)} from {chains_dir}")
    print("looking for a certifi that rejects every chain:")
    source = choose_source(args.source, chains)
    print(f"source: {source}  (certifi {read_certifi_version(source) if source.is_dir() else '?'})")

    if not args.dry_run and not args.yes:
        print("\nThis replaces the CA bundle inside the app and re-signs it ad-hoc.")
        print("App updates will undo the patch. Continue? [y/N] ", end="", flush=True)
        if input().strip().lower() not in ("y", "yes"):
            return 1

    ok = True
    for app in apps:
        ok = patch_app(app, source, chains, args.dry_run,
                       Path(args.backup_dir).expanduser()) and ok
    if not ok:
        return 1
    print("\ndone" if not args.dry_run else "\ndry run complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
