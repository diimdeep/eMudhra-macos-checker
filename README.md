# eMudhra macOS checker

Does Mac still trust the compromised eMudhra intermediate CAs?

In October 2026, eight eMudhra intermediate CA keys turned out to be recoverable
from their public certificates. This repo asks each installed TLS client to complete a real handshake against a certificate issued under one of those CAs, locally.

Background: [disclosure site](https://emudhra.we-have-a-problem.com/) ·
[source](https://github.com/galadran/we-have-a-problem.com).

## How it works

1. `checking/lab.py` takes the twelve captured chains, keeps each intermediate
   and cross-sign, and mints a `localhost` leaf under the matching compromised
   key.
2. It serves them on `127.0.0.1`.
3. `checking/check_trust.py` connects with every installed client and records
   who accepts.


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


## Run

```sh
python3 checking/check_trust.py
```

```
TECH                     VERSION   TEST      RESULT       STORE
Java <ver> (<vendor>)    ...       handshake rejects 0/12 /Library/Java/JavaVirtualMachines/<jdk>/Contents/Home/lib/security/cacerts
curl                     ...       handshake rejects 0/12 /etc/ssl/cert.pem
NSS                      ...       version   patched      libnssckbi (built-in roots)
Electron                 N apps    version   outdated     Chromium root store + CRLSets
```


## Two modes

| mode | does | needs |
|---|---|---|
| `local` (default) | real TLS handshake per client per chain | keys |
| `offline` | `openssl verify` against each client's bundle | chains only |


## Layout

```
checking/              checker, lab, keychain distrust, Sublime plugin and patcher
disclosure/            twelve captured chains (emudhra-test-host-chains.zip)
keys/                  eight recovered CA keys and certificates (zip)
KEYS.md                how keys, certificates, chains and test hosts relate
```

## Requirements

macOS, Python 3 (standard library only), `openssl` on `PATH`. `codesign` only
for the patcher.


## Also here

- Distrust the 14 compromised intermediates in the keychain:
  `python3 checking/distrust_keychain.py` sets Never Trust per certificate,
  asking first. `--admin` uses the System keychain, `--undo` reverts,
  `--list` shows state. Chromium on macOS honors local distrust, which should
  cover Chrome, Edge, Brave, Opera, Vivaldi, Yandex and Electron apps that use
  the system verifier.
- Check from inside Sublime: `python3 checking/serve_lab.py --install-plugin`,
  then “eMudhra: check local trust”.
- Patch Sublime: `python3 checking/patch_sublime.py` swaps its bundled certifi
  and re-signs ad-hoc.

## About the keys

Included so the lab runs out of the box. They are derivable from the public
certificates in milliseconds, so this adds no exposure.

`keys/emudhra-intermediate-ca-keys.zip` repackages the public
`emudrahahahahaha` repository (commit `c43b3f0`)
