#!/usr/bin/env python3
"""Sublime Text plugin: does this editor's TLS stack trust the compromised CAs?

The plugin host has its own Python, its own OpenSSL, and its own certifi, so it
is a separate client from the shell — this asks it directly, against the local
lab started by ``checking/serve_lab.py``.

Install (either copy the file into Packages/User yourself, or let
``serve_lab.py --install-plugin`` do it), then run "eMudhra: check local trust"
from the command palette.  The report opens in an output panel.

The same code runs headless for testing:

    python3 checking/sublime/local_trust_check.py checking/.cache/lab.json
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys

TIMEOUT = 6.0

try:  # only available inside Sublime
    import sublime
    import sublime_plugin
except ImportError:  # pragma: no cover - headless use
    sublime = None


def certifi_module():
    try:
        import certifi
        return certifi
    except ImportError:
        return None


def probe(port: int, cafile: str | None = None) -> tuple[bool, str]:
    """One TLS handshake against a loopback chain."""
    try:
        context = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        with socket.create_connection(("127.0.0.1", int(port)), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as tls:
                tls.getpeercert()
        return True, ""
    except Exception as exc:  # noqa: BLE001 - the client's own error is the result
        return False, f"{type(exc).__name__}: {exc}"


def run_checks(lab_file: str) -> dict:
    with open(lab_file, encoding="utf-8") as fh:
        lab = json.load(fh)

    certifi = certifi_module()
    cafile = certifi.where() if certifi else None
    certifi_version = getattr(certifi, "__version__", "not installed") if certifi else "not installed"

    rows = []
    for chain in lab.get("chains", []):
        default_ok, default_error = probe(chain["port"])
        certifi_ok, certifi_error = probe(chain["port"], cafile)
        rows.append({
            "name": chain.get("name", str(chain["port"])),
            "port": chain["port"],
            "default": default_ok,
            "default_error": default_error,
            "certifi": certifi_ok,
            "certifi_error": certifi_error,
        })

    return {
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "openssl": ssl.OPENSSL_VERSION,
        "certifi": certifi_version,
        "cafile": cafile or "",
        "default_paths": str(ssl.get_default_verify_paths()),
        "rows": rows,
    }


def report_text(result: dict) -> str:
    accepted = sum(1 for row in result["rows"] if row["certifi"])
    total = len(result["rows"])
    lines = [
        "eMudhra local trust check - Sublime Text plugin host",
        "=" * 58,
        f"python     {result['python']}  ({result['executable']})",
        f"openssl    {result['openssl']}",
        f"certifi    {result['certifi']}",
        f"cafile     {result['cafile'] or '-'}",
        f"defaults   {result['default_paths']}",
        "",
        f"{'chain':<34}{'default':<12}{'certifi':<10}",
        "-" * 58,
    ]
    for row in result["rows"]:
        default = "accepted" if row["default"] else "rejected"
        certifi = "ACCEPTED" if row["certifi"] else "rejected"
        lines.append(f"{row['name']:<34}{default:<12}{certifi:<10}")
        if row["certifi_error"]:
            lines.append(f"  certifi: {row['certifi_error']}")
    lines.append("")
    if accepted:
        lines.append(f"RESULT: certifi accepts {accepted}/{total} chains - the plugin host still trusts the CAs.")
        lines.append("Patch the bundled certifi and re-sign the app, then run this again.")
    else:
        lines.append(f"RESULT: certifi rejects {total}/{total} chains - the plugin host is clean.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Sublime glue
# ---------------------------------------------------------------------------

if sublime is not None:

    class EmudhraTrustCheckCommand(sublime_plugin.WindowCommand):
        def run(self, lab: str | None = None) -> None:
            path = lab or sublime.load_settings("EmudhraTrustCheck.sublime-settings").get("lab_file", "")
            if not path:
                self.window.show_input_panel(
                    "lab.json written by serve_lab.py:", "", self._check, None, None)
                return
            self._check(path)

        def _check(self, path: str) -> None:
            self.window.status_message("eMudhra: checking local chains...")
            sublime.set_timeout_async(lambda: self._run(path), 10)

        def _run(self, path: str) -> None:
            try:
                text = report_text(run_checks(path))
            except Exception as exc:  # noqa: BLE001
                text = f"eMudhra: check failed\n\n{type(exc).__name__}: {exc}"
            sublime.set_timeout(lambda: self._show(text), 0)

        def _show(self, text: str) -> None:
            panel = self.window.create_output_panel("emudhra_trust")
            panel.run_command("select_all")
            panel.run_command("right_delete")
            panel.run_command("append", {"characters": text})
            self.window.run_command("show_panel", {"panel": "output.emudhra_trust"})
            self.window.status_message("eMudhra: done")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the Sublime plugin host against the local lab.")
    parser.add_argument("lab", help="lab.json written by serve_lab.py")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)
    result = run_checks(args.lab)
    print(json.dumps(result, indent=2) if args.json else report_text(result))
    return 0 if not any(row["certifi"] for row in result["rows"]) else 1


if __name__ == "__main__":
    sys.exit(main())
