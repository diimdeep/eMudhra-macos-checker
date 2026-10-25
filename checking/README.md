# checking/

Does this Mac still trust the compromised eMudhra intermediate CAs?

`local` mode completes real TLS handshakes against a loopback lab; `offline`
inspects CA bundles with `openssl verify`.

## Requirements

macOS, Python 3 (standard library only), `openssl` on `PATH`. `codesign` only
for the patcher.

## Run

```sh
python3 checking/check_trust.py                 # local lab, the default
python3 checking/check_trust.py --mode offline  # no sockets, no keys
python3 checking/check_trust.py --only java     # one technology
python3 checking/check_trust.py --deep          # also read Electron binaries
python3 checking/check_trust.py --json          # write checking/report.json
```

| flag | meaning |
|---|---|
| `--mode local` | real handshakes against the loopback lab (default) |
| `--mode offline` | `openssl verify` against each client's CA bundle |
| `--only a,b` | run only these technologies (`java`, `curl`, `electron`, …) |
| `--keys PATH` | alternate key archive; default is the shipped zip |
| `--chains PATH` | alternate chain directory or zip |
| `--json [PATH]` | write results as JSON (default `checking/report.json`) |
| `--deep` | scan each Electron binary for the embedded roots |
| `--scan DIR` | also look for certifi copies under DIR (repeatable; home is always scanned) |
| `--top N` | test only the first N chains (debugging) |
| `--timeout S` | per-probe timeout (default 8) |
| `--no-progress` | do not draw the progress line (it is off anyway when stderr is not a terminal) |

## Targets

`--only` takes the keys in the first column. TEST is how the row is decided in
the default `local` mode; `--mode offline` turns every handshake into a bundle
check where the client has a readable bundle.

| key | target | where it looks | TEST |
|---|---|---|---|
| `macos` | macOS Security.framework | System keychain, SSL policy | keychain: `security verify-cert` on each chain's intermediates (12) |
| `homebrew` | Homebrew `ca-certificates` | `$(brew --prefix)/etc/ca-certificates/cert.pem` | bundle |
| `openssl` | OpenSSL on `PATH` | its `OPENSSLDIR/cert.pem` | handshake (`s_client`) |
| `curl` | curl on `PATH` | CA file from `curl -v` | handshake |
| `python` | Python `ssl`, default context | the interpreter running the checker | handshake |
| `certifi` | Python certifi | importable by that interpreter | handshake |
| `pip` | pip's vendored certifi | `pip._vendor.certifi` | bundle |
| `uv` | uv | compiled-in webpki-roots | version |
| `node` | Node.js | `tls.rootCertificates` | handshake (`https.get`) |
| `npm` | npm | Node's store | same result as `node` |
| `bun` | Bun | compiled-in roots | handshake (`fetch`) |
| `deno` | Deno | compiled-in Mozilla roots, or the keychain with `DENO_TLS_CA_STORE=system` | handshake (`fetch`) |
| `go` | Go | `crypto/x509` system pool | handshake (compiled `net/http` client) |
| `java` | every JVM | `java_home` default, `/Library/Java/JavaVirtualMachines`, `~/Library/Java/JavaVirtualMachines` (JetBrains `jbr-*` included) | handshake per JVM |
| `ruby` | Ruby | `OpenSSL::X509::DEFAULT_CERT_FILE` | handshake (`Net::HTTP`) |
| `nss` | Homebrew NSS | built-in roots | version |
| `electron` | Electron apps | app bundles in `/Applications` and `~/Applications`, up to 3 folders deep | version per app; `--deep` adds root markers |
| `sublime` | Sublime Text plugin host | `Sublime Text*.app` in `/Applications` and `~/Applications`, up to 3 folders deep; bundled certifi | bundle |
| `pythons` | other Python 3 interpreters | `python3*` on `PATH`, Homebrew `python@*`, python.org framework, pyenv, `/usr/bin/python3` | handshake per interpreter; bundle for its certifi |
| `apps` | CA files inside app bundles | `cacert.pem`, `ca-bundle.crt`, `ca-certificates.crt`, `curl-ca-bundle.crt` in any app found above | bundle per file |
| `venvs` | certifi copies in venvs and user site-packages | Spotlight search under home and every `--scan DIR` | bundle per copy |
| `chromium` | Chromium-family browsers (Chromium, Chrome, Brave, Edge, Vivaldi, Yandex) | found by bundle id among the apps above; each chain is loaded over DevTools (`--headless=new --remote-debugging-port=0`) in a throwaway profile seeded with the real profile's `CertificateRevocation` and `PKIMetadata` | handshake per browser |
| `rust` | Rust rustls-webpki / webpki-roots | `rustc` present; crates not inspected | version |
| `composer` | Composer ca-bundle | `composer` on `PATH` | version of `composer`, not of its bundle |
| `elixir` | Elixir castore | `elixir` on `PATH` | version of `elixir`, not of castore |
| `perl` | Perl Mozilla::CA | module importable | version |
| `cfssl` | Cloudflare CFSSL trust store | `cfssl` on `PATH` | detected only |
| `ubuntu` `debian` `arch` `gentoo` `fedora` `freebsd` `chainguard` `alpine` | distribution `ca-certificates` | `/etc/os-release` | `-` on macOS |

The `chromium` row counts `ERR_CERTIFICATE_TRANSPARENCY_REQUIRED` as trusted:
the chain verified to a trusted root and only the lab leaf's missing CT proofs
stopped the page, which a key holder can obtain.

Other browsers (Safari, Firefox, LibreWolf, Tor Browser, Opera) are listed with
their versions but not tested.


## How it works

The lab needs two inputs:

* `disclosure/emudhra-test-host-chains.zip` — twelve chains as served by the
  test hosts (the disclosure's `chains.zip`), published
  with the [disclosure site](https://emudhra.we-have-a-problem.com/)
  ([source](https://github.com/galadran/we-have-a-problem.com)): 3 kinds
  (`dv`, `ov`, `ev`) × 2 generations × 2 trust paths.
* `keys/emudhra-intermediate-ca-keys.zip` — the eight compromised keys and
  their certificates.

An unzipped `disclosure/chains/*.pem` takes precedence over the chains zip;
the zip is extracted once into `checking/.cache/chains-<hash>/`.

For each chain `lab.py` keeps `chain[1:]`, mints a `localhost` leaf under the
matching key, and serves `leaf → intermediate [→ cross-sign]` on `127.0.0.1`.
Leaves last 30 days; extracted keys are deleted with the run. Each chain is
served on both `127.0.0.1` and `::1`, since clients resolve `localhost` to
either. A run killed before cleanup leaves a `lab-*` directory; the next run
removes it.

Both trust paths matter: emSign anchors at `emSign ECC Root CA - G3`, AAA at
`AAA Certificate Services`. certifi has the first and not the second; old Java
had both.

## Modes

| mode | does | proves | needs |
|---|---|---|---|
| `local` | TLS handshake per client per chain | what the client will do | keys |
| `offline` | `openssl verify` per chain | what the bundle contains | chains |

## Reading the output

```
TECH                     VERSION   TEST      RESULT       STORE
Java <ver> (<vendor>)    ...       handshake rejects 0/12 /Library/Java/JavaVirtualMachines/<jdk>/Contents/Home/lib/security/cacerts
curl                     ...       handshake rejects 0/12 /etc/ssl/cert.pem
NSS                      ...       version   patched      libnssckbi (built-in roots)
Electron                 N apps    version   outdated     Chromium root store + CRLSets
macOS Security.framework ...       keychain  rejects 0/12 System keychain
```


`TEST` is how the row was decided: `handshake` (strongest), `bundle`,
`version` (version only), `keychain` (CA tested under Apple's SSL policy),
`-` (not testable).

`RESULT` is `TRUSTS n/12` (bad), `rejects 0/12`, `patched` / `outdated`
(version only), `unknown`, or `-`. A probe that times out, cannot connect, or
crashes counts as an error, never as a rejection; a row with errors and no
acceptances reads `unknown, n/12 err` and is listed under "Unresolved".

Version rows compare against the fix for the installed release line: Go
1.27.0 needs 1.27.3 even though 1.26.10 is also listed, and a line with no
fix (Composer 1.5, Electron 38) is outdated.

Electron gets a per-app list below the table (and `results[].items` in JSON);
`--deep` adds root counts. Fixed releases are per major line: 42.11.16, 43.8.1,
44.9.1.

## Java

One row per JVM: the default from `/usr/libexec/java_home`, plus every bundle
under `/Library/Java/JavaVirtualMachines` and
`~/Library/Java/JavaVirtualMachines`, including JetBrains' `jbr-*`. Each is
tested with its own `bin/java` and `cacerts`. Updating one does not update the
others.

## Sublime

The plugin host has its own Python, OpenSSL and certifi.

```sh
python3 checking/serve_lab.py --install-plugin
# restart Sublime, then: "eMudhra: check local trust"
```

Two columns: default `ssl` context, then bundled `certifi`. Ctrl-C stops the lab. The plugin's
verdict counts a chain as trusted if either column accepts it.

To patch:

```sh
python3 checking/patch_sublime.py --dry-run
python3 checking/patch_sublime.py
python3 checking/patch_sublime.py --restore
```

It swaps `Contents/MacOS/Lib/python3/certifi` for a clean bundle and re-signs
ad-hoc; the backup lives in `~/Library/Application Support/emudhra-check/`.
Quit Sublime first. Updates undo the patch, and the new signature resets
Gatekeeper and TCC expectations.
`--restore` puts the original files back but keeps the ad-hoc signature;
reinstall Sublime to get the vendor's signature back. `--source` accepts a
certifi package directory or a bare PEM bundle (which replaces only
`cacert.pem`).

## Caveats

* **macOS**: CT rejects every minted leaf, so the row tests each chain's
  intermediate (and cross-sign) under the SSL policy instead.
* **Java**: the probe is compiled with `--release 8` so Java 8 homes can run it.
* **Go**: refuses these certificates as `not standards compliant` before trust
  is consulted.
* **NSS, uv, Electron**: version-only; their stores are compiled in or per-app.
* **Browsers**: listed, not exercised.
* **Linux rows**: `n/a` unless running on that distribution.

## Files

* `check_trust.py` — inventory, probes, report.
* `lab.py` — mints leaves, runs the loopback servers.
* `serve_lab.py` — keeps the lab up for the Sublime plugin.
* `sublime/local_trust_check.py` — the plugin.
* `patch_sublime.py` — swaps Sublime's certifi, re-signs ad-hoc.
* `progress.py` — the one-line progress display on stderr.
* `apps.py` — finds app bundles, including ones in subfolders, and the CA files inside them.
* `patched_versions.json` — fixed releases from the disclosure.
* `report.json` — last JSON result, written on `--json`.

## Adding a client

Add `t_<name>(ctx) -> Result`, register it in `TECHS` as `("<key>", t_<name>)`.
Use `ctx.local()["<probe>"]` for a handshake, `ctx.bundle_counts(path)` for a
bundle, or neither for version-only. Probes return `(True | False | None,
detail)`; pass the client's failure text through `classify()` so only real
certificate rejections count as `False`. Return a list for technologies with several
installations. `FIXED_LOOKUP` maps the row to its fixed version.
