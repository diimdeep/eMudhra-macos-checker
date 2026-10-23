# How the keys, certificates and chains relate

Eight private keys were compromised, one per intermediate CA name. Each of
the six TLS intermediates has two certificates for the same key: one issued
by the AAA root and one by emSign Root TLS CA - G3. The two code-signing CAs
have only the AAA certificate.

Everything below was derived from the two archives in this repo by parsing
every certificate and comparing public keys:

* `keys/emudhra-intermediate-ca-keys.zip`
* `disclosure/emudhra-test-host-chains.zip`

Notation: a certificate is named by the first 8 hex digits of its SHA-256
fingerprint (`BC7952B1`). A key is named by the first two bytes of its
Subject Key Identifier (`key E21E`). Certificates that share a key ID share a
public key.

## One TLS intermediate

The same pattern repeats for all six TLS intermediates. `EM DV TLS CA - G3B`
is shown.

```
   ROOT KEYS NOT COMPROMISED
 ┌──────────────────────────┐          ┌──────────────────────────┐
 │ AAA Certificate Services │          │ emSign ECC Root CA - G3  │
 │ Comodo/Sectigo, key A011 │          │ key 7C5D                 │
 └────────────┬─────────────┘          └────────────┬─────────────┘
              │                                     │ cross-sign 37BAA2EA
              │                                     │ valid to 2039
              │                        ┌────────────▼─────────────┐
              │                        │ emSign Root TLS CA - G3  │
              │                        │ key E13A                 │
              │                        └────────────┬─────────────┘
   cert BC7952B1                          cert FB2603CC
   valid to 2028                          valid to 2040
   (in keys zip and the -aaa chain)       (only in the chains zip)
              │                                     │
              └───────────────┐     ┌───────────────┘
                              ▼     ▼
               ╔══════════════════════════════════╗
               ║  EM DV TLS CA - G3B              ║
               ║  key E21E   private scalar d=156 ║  <- compromised
               ╚════════════════╤═════════════════╝
                                │ anyone holding d can sign
                                ▼
                     leaf for any hostname
          (validates through both paths: same subject, same key)
```

A leaf signed with the key carries the intermediate's subject as its issuer
and `E21E` as its Authority Key Identifier. Both intermediate certificates
match on those two fields, so a client can build either path:

* `leaf -> BC7952B1 -> AAA Certificate Services`
* `leaf -> FB2603CC -> emSign Root TLS CA - G3 -> emSign ECC Root CA - G3`

A store that removed only one of these anchors, or distrusted only one of the
two intermediate certificates, still accepts the leaf through the other.

## All eight keys

| CA (one key each) | key | d | cert issued by AAA (to 2028) | cert issued by emSign TLS G3 (to 2040) | test hosts |
|---|---|---|---|---|---|
| EM DV TLS CA - G3B | E21E | 156 | BC7952B1 | FB2603CC | dv-g3b, dv-g3b-aaa |
| EM DV TLS CA - G3C | AE7E | 230 | 7C65BB9C | FEE3B62F | dv-g3c, dv-g3c-aaa |
| EM EV TLS CA - G3B | 3EDC | 115 | 8251AE25 | 02A34296 | ev-g3b, ev-g3b-aaa |
| EM EV TLS CA - G3C | A625 | 56 | 608D94B2 | A25BF677 | ev-g3c, ev-g3c-aaa |
| EM OV TLS CA - G3B | 9BD8 | 155 | 34425930 | 0D6F34BA | ov-g3b, ov-g3b-aaa |
| EM OV TLS CA - G3C | 34EA | 4 | 356FDEF2 | 10658DC6 | ov-g3c, ov-g3c-aaa |
| EM OV CS CA - G3B | 79FA | 66 | 9A9E091B | none | none (code signing) |
| EM OV CS CA - G3C | EE6F | 237 | 9D119AE8 | none | none (code signing) |

All eight keys are on curve P-384 (secp384r1). Every private scalar `d` is a
number from 4 to 237. A P-384 private key should be a random 384-bit number.
A key this small is found by trying at most 256 values of `d` against the
public key in the certificate. This is why the keys are derivable from the
public certificates in milliseconds.

The certificates outside the compromised set:

| certificate | subject | issuer | key | valid to |
|---|---|---|---|---|
| 37BAA2EA | emSign Root TLS CA - G3 | emSign ECC Root CA - G3 | E13A | 2039 |

The cross-sign is shared by all six non-AAA chains. Its key and the two root
keys (`A011`, `7C5D`) are not part of the compromise.

## What each archive contributes

```
keys/emudhra-intermediate-ca-keys.zip            disclosure/emudhra-test-host-chains.zip
 8 x  CA.key  (private scalar d)                  12 x <kind>-<gen>[-aaa]-emudhra.pem
 8 x  CA.pem  (the AAA-issued cert) ──same──┐
                                     cert    │    *-aaa (6):  leaf -> [AAA-issued cert]
                                             └──────────────────────────┘
                                                  plain (6):  leaf -> emSign-issued cert
                                                                   -> emSign TLS G3 cross-sign

  lab.py:  key from the keys zip ──signs──> new localhost leaf
           + chain[1:] from the chains zip ──> served on 127.0.0.1 and ::1
```

Both archives are needed. The keys archive supplies the signing keys, but its
certificates cover only the AAA path. The emSign-issued intermediates and the
ECC Root G3 cross-sign exist only in the chains archive. Without it, the lab
can build at most 6 of the 12 chains, all on the AAA path.

The code-signing CAs have no test-host chain, so the lab skips them. They
appear only in the keys archive.

The chain files are named `<kind>-<gen>[-aaa]-emudhra.we-have-a-problem.com.pem`:

* `<kind>` is `dv`, `ov` or `ev`.
* `<gen>` is `g3b` (eMudhra BV, NL) or `g3c` (eMudhra Inc, US).
* `-aaa` marks the AAA path. Without it, the file holds the emSign path.

The leaves in the published chains were also signed with these keys. They
expire in May 2027. The lab discards them and mints its own `localhost`
leaves, valid for 30 days.

## Reproduce

Compare a certificate's key with a private key:

```sh
openssl x509 -in CERT.pem -noout -pubkey
openssl pkey -in CA.key -pubout
```

Print a private scalar:

```sh
openssl pkey -in CA.key -noout -text    # the "priv:" field
```

List subject, issuer, key IDs and expiry for one certificate:

```sh
openssl x509 -in CERT.pem -noout -subject -issuer -fingerprint -sha256 \
    -ext subjectKeyIdentifier,authorityKeyIdentifier -enddate
```
