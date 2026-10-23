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


## Run

```sh
python3 checking/check_trust.py
```

```
TECH                     VERSION   STORE                        TEST       RESULT
Java <ver> (<vendor>)    ...       JDK cacerts                  handshake  rejects 0/12
curl                     ...       /etc/ssl/cert.pem            handshake  rejects 0/12
NSS                      ...       libnssckbi (built-in roots)  version    patched
Electron                 N apps    Chromium + CRLSets           version    outdated
```


## Two modes

| mode | does | needs |
|---|---|---|
| `local` (default) | real TLS handshake per client per chain | keys |
| `offline` | `openssl verify` against each client's bundle | chains only |


## Layout

```
checking/              checker, lab, Sublime plugin and patcher
disclosure/            twelve captured chains (emudhra-test-host-chains.zip)
keys/                  eight recovered CA keys and certificates (zip)
KEYS.md                how keys, certificates, chains and test hosts relate
```

## Requirements

macOS, Python 3 (standard library only), `openssl` on `PATH`. `codesign` only
for the patcher.


## Also here

- Check from inside Sublime: `python3 checking/serve_lab.py --install-plugin`,
  then “eMudhra: check local trust”.
- Patch Sublime: `python3 checking/patch_sublime.py` swaps its bundled certifi
  and re-signs ad-hoc.

## About the keys

Included so the lab runs out of the box. They are derivable from the public
certificates in milliseconds, so this adds no exposure.

`keys/emudhra-intermediate-ca-keys.zip` repackages the public
`emudrahahahahaha` repository (commit `c43b3f0`)
