# RetroCert

A root certificate rescue tool for old Macs whose certificate store has gone
stale, causing HTTPS connections to fail.

*(日本語版: [README.ja.md](README.ja.md))*

## Overview

    Old Mac
      ↓
    Launch RetroCert
      ↓
    Fetch the latest CA list from a VPS
      ↓
    Apply it to the Keychain
      ↓
    Retry the HTTPS connection

The VPS side only hosts a static certificate set + version manifest — it
never generates certificates on demand, so server load is minimal. The
target use case is "sites that would work again if only the certificate
store were up to date."

This is designed to be used by an arbitrary number of old-machine owners,
so the client itself (the whole runnable toolkit) is also distributed from
the VPS.

## Important: real-world scope (verified on actual hardware)

RetroCert can only fix "sites that fail purely because of an expired /
missing root certificate." Verified on a real PowerMac G4 running Safari:

- A site whose certificate we fixed **and** whose server was configured to
  still accept old clients (TLS 1.0, legacy ciphers) — this project's own
  VPS — **connected successfully**.
- A typical modern site (e.g. apple.com, which only offers TLS 1.2/1.3 with
  ECDHE-only cipher suites) **failed with "Could not establish a secure
  connection."** This is a TLS protocol/cipher mismatch, not a certificate
  problem, and it's a hard limitation of Tiger's `SecureTransport`
  implementation that RetroCert cannot fix.

In other words, RetroCert does **not** "fix any HTTPS site." It only helps
when the failure is purely certificate-related *and* the server still
accepts legacy TLS.

On top of that, in practice most people who still actively use Tiger-era
Macs have already moved from Safari/Mail.app to Aquafox (a TenFourFox-family
Firefox fork) and Thunderbird — both of which ship their own NSS certificate
store independent of the OS Keychain, and (confirmed by inspecting the
shipped binary) already bundle modern roots such as ISRG Root X1. So
RetroCert's practical audience is limited to the minority who deliberately
keep using stock Safari/Mail.app. **This is not a general-purpose "make an
old Mac browse the modern web" tool** — that caveat should be stated up
front to avoid overpromising.

## Ideas for reusing this elsewhere

Given the above, the direct value of "fixing web browsing on an old Mac" is
limited — but the mechanisms built here may be useful for other purposes:

1. **As a generic "offline private key, tamper-evident even over plain
   HTTP" distribution framework.** Nothing here is certificate-specific —
   the same pattern works for any payload.
   - Generate a keypair with `publisher/generate_keys.py`, bundle any
     payload you like (game patches, fonts, config files, dictionary data,
     …) into a `manifest.json`-style file and sign it, then verify it with
     the same mechanism as `client/verify.py`.
   - The core idea — keeping the signing key on a machine you control while
     treating the distribution server as untrusted — is reusable for any
     small hobby project's auto-update feature that doesn't want the
     overhead of Sparkle/TUF-style infrastructure.

2. **`client/verify.py` as a standalone, dependency-free Pure Python RSA
   signature verifier.** It implements RSA-PKCS#1 v1.5 + SHA-256
   verification in about 90 lines using only `hashlib`, `pow()`, and a tiny
   hand-rolled ASN.1 DER parser. Handy anywhere you can't install
   `cryptography`/`pyOpenSSL` — old Python builds, sandboxes without pip
   access, or an installer's bootstrap step that shouldn't need extra
   dependencies.

3. **Generalizing beyond Mac to any "legacy/embedded device with a frozen
   certificate store."** `client/store.py`'s per-OS dispatch layer exists
   specifically to make this easy. Old routers, NAS boxes, multi-function
   printers, industrial equipment, and old Linux/Windows servers all make
   HTTPS calls outside a browser, and plenty of them never get their
   certificate store updated. Reframed as "a toolkit for extending the life
   of legacy devices' TLS clients" rather than "web browsing on an old Mac,"
   this could serve a much broader need — just add a new backend such as
   `store_windows.py` or `store_linux.py`.

4. **(Future idea, not attempted here) Supporting Aquafox/Thunderbird's own
   NSS certificate store.** We skipped this because `certutil` isn't
   available on the target machine, but a custom binding that calls
   `libnss3.dylib` directly via `ctypes` could in principle add certificates
   to Aquafox/Thunderbird's `cert9.db`. Ironically, this is where the
   feature people would actually use lives — but it requires matching NSS's
   internal API/ABI exactly, which is a meaningfully larger engineering
   effort.

## Supported OSes

- macOS: OS X 10.4 (Tiger) and later
- Windows: planned (designed to be extended by adding
  `client/store_windows.py`; not implemented yet)

## Security model (tamper detection even over plain HTTP)

Some old machines have TLS stacks too old to speak HTTPS at all, so
fetching certificate updates supports both HTTP and HTTPS. Since HTTP can be
tampered with or spoofed, the following mechanism keeps it safe anyway:

    Dev machine (the private key lives ONLY here — never on the VPS)
      ↓ sign manifest.json / the client distribution with the private key
    Signed files (manifest.json + .sig + certs/ + retrocert-client.{tar.gz,zip} + .sig)
      ↓ upload (signed files only — the private key is never uploaded)
    VPS (just serves the signed files — holds no private key at all)
      ↓ HTTP/HTTPS
    RetroCert (verifies the signature with its bundled public key before
               trusting anything)

**Important:** key generation and signing happen only in `publisher/` (on a
trusted machine such as your dev Mac — never on the VPS). Never putting the
private key on the VPS is the core of this design: **even if the VPS is
compromised, an attacker cannot produce a valid signature**, so a tampered
`manifest.json` or certificate file is rejected by RetroCert's own
verification.

1. Generate a keypair on your dev machine (`publisher/generate_keys.py`,
   once; never let the private key leave this machine).
2. Sign `manifest.json` and the client distribution archive with that key,
   on the same machine.
3. Upload only the signed output to the VPS (never upload `keys/`).
4. The client verifies the signature with its bundled public key
   (`client/vps_public_key.pem`) before trusting anything.
5. Each individual certificate file is checked against the SHA-256 recorded
   in the (already verified) manifest, so signing the manifest once is
   enough to cover everything it references.

**Operational note (Trust On First Use):** obtain the client distribution
(which includes `vps_public_key.pem`) the first time over a channel you
already trust — e.g. a modern PC with working HTTPS — verify its signature
there, then transfer it to the old machine. That first acquisition is the
only place trust has to come from out of band; every update after that is
protected by signature verification even over plain HTTP.

## Directory layout

    RetroCert/
    ├── client/   … the rescue tool itself (targets Python 3.12; this is what gets distributed)
    │   ├── retrocert.py       … entry point (OS-independent logic)
    │   ├── store.py           … per-OS store dispatch layer
    │   ├── store_macos.py     … macOS implementation (uses the `security`/`openssl` commands)
    │   ├── store_windows.py   … Windows implementation (planned)
    │   ├── manifest.py        … fetches the manifest/certificates from the VPS
    │   ├── verify.py          … signature verification (tamper check)
    │   ├── state.py           … tracks which certificates RetroCert itself added
    │   ├── config.py          … VPS_BASE_URL and other settings
    │   └── vps_public_key.pem … public key used for verification (replace with your own before distributing)
    └── publisher/   … publisher-side scripts (run on your dev machine, never on the VPS)
        ├── generate_keys.py   … generates the signing keypair (once; private key stays local)
        ├── build_bundle.py    … builds the certificate bundle + signed manifest
        ├── package_client.py … builds and signs the client distribution archive
        └── README.md

## Using the client (on the old Mac, e.g. a PowerMac G4)

    cd client
    python3.12 retrocert.py            # dry run (shows the diff only, no changes)
    python3.12 retrocert.py --apply    # actually apply changes to the Keychain
    python3.12 retrocert.py --apply --system  # apply system-wide (requires sudo)

Before running it, set `VPS_BASE_URL` in `client/config.py` to your own VPS
URL, and put your own public key in `client/vps_public_key.pem`.

## Using the publisher (on your dev machine — never on the VPS)

See `publisher/README.md`.

## Status (as of 2026-09-12)

- The client and publisher tooling are fully implemented, including
  signature verification, HTTP support, and distribution package building.
  The private key never touches the VPS (signing happens only on the dev
  machine; the VPS only ever serves already-signed static files).
- Verified on a real PowerMac G4 (Mac OS X 10.4 Tiger, Python 3.12.11)
  against a production VPS: fetched and applied real certificates,
  growing the trust store from 158 to 238 entries (80 RSA roots added; 41
  ECC roots were skipped, since Tiger's certificate library predates
  ECC support).
- Measured the real-world effect in Safari: the project's own VPS (with
  TLS 1.0 re-enabled) improved; a mainstream modern site (apple.com) still
  failed due to a TLS protocol mismatch unrelated to certificates. See the
  scope section above for the resulting, fairly narrow real-world
  applicability.
- Given that scope, this is being released as a small, low-key reference
  implementation rather than something actively promoted or developed
  further — useful mainly for the niche audience described above, and for
  anyone who wants to repurpose the underlying mechanisms (see "Ideas for
  reusing this elsewhere").

## License

MIT — see [LICENSE](LICENSE).
