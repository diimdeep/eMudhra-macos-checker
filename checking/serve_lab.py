#!/usr/bin/env python3
"""Run the loopback chain lab and keep it up for the Sublime plugin.

    python3 checking/serve_lab.py                 # start, print lab.json path
    python3 checking/serve_lab.py --install-plugin  # also install the plugin

The servers stay up until Ctrl-C.  ``lab.json`` lists the twelve chains and
their ephemeral ports; the Sublime plugin reads it to test the plugin host's
TLS stack without touching the network.
"""

from __future__ import annotations

import argparse
import json
import shutil
import signal
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CACHE = HERE / ".cache"
sys.path.insert(0, str(HERE))

from lab import Lab, LabError, resolve_chains  # noqa: E402

PLUGIN = HERE / "sublime" / "local_trust_check.py"
COMMANDS = HERE / "sublime" / "Emudhra.sublime-commands"
SETTINGS_NAME = "EmudhraTrustCheck.sublime-settings"


def sublime_user_dir() -> Path:
    return Path.home() / "Library" / "Application Support" / "Sublime Text" / "Packages" / "User"


def install_plugin(lab_file: Path) -> Path:
    user = sublime_user_dir()
    user.mkdir(parents=True, exist_ok=True)
    shutil.copy2(PLUGIN, user / PLUGIN.name)
    shutil.copy2(COMMANDS, user / COMMANDS.name)
    settings = user / SETTINGS_NAME
    settings.write_text(json.dumps({"lab_file": str(lab_file)}, indent=2) + "\n")
    return user


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the twelve chains for the Sublime plugin.")
    parser.add_argument("--chains", help="directory or zip with the twelve chains")
    parser.add_argument("--json-out", default=str(CACHE / "lab.json"))
    parser.add_argument("--keys", help="zip or directory with the recovered CA keys")
    parser.add_argument("--install-plugin", action="store_true",
                        help="copy the plugin and settings into Packages/User")
    args = parser.parse_args(argv)

    try:
        chains_dir = resolve_chains(ROOT, CACHE, args.chains)
    except LabError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    lab = Lab(ROOT, CACHE, "openssl", keys=args.keys)
    lab_file = Path(args.json_out).expanduser().resolve()
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(0))
    try:
        lab.prepare(chains_dir)
        lab.start()

        lab_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "chains": [{"name": chain.name, "port": chain.port} for chain in lab.chains],
        }
        lab_file.write_text(json.dumps(payload, indent=2) + "\n")

        print(f"{len(lab.chains)} chains on 127.0.0.1 and ::1, lab file: {lab_file}")
        if args.install_plugin:
            user = install_plugin(lab_file)
            print(f"plugin installed in {user}")
            print('run "eMudhra: check local trust" from the command palette')
        print("Ctrl-C to stop")

        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        lab.cleanup()
        try:
            lab_file.unlink()
        except OSError:
            pass
        print("\nlab stopped, lab.json removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
