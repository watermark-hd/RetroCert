# RetroCert Publisher

*(日本語版: [README.ja.md](README.ja.md))*

## Role and an important assumption

**The scripts in this directory are never run on the VPS.** Run them on a
trusted machine you control — your dev Mac — which is where the signing key
lives.

    Dev machine (where you run publisher/. The private key lives ONLY here)
      ↓ sign manifest.json / the client distribution with the private key
    Signed manifest.json + .sig + certs/ + retrocert-client.{tar.gz,zip} + .sig
      ↓ upload via rsync etc. (never include the private key here)
    VPS (just serves the signed static files — holds no private key at all)
      ↓ HTTP/HTTPS
    RetroCert (the client — verifies the signature with its bundled public
               key before trusting anything)

Because of this separation, **the private key is never exposed even if the
VPS is compromised** — an attacker can't produce a valid signature, so a
tampered `manifest.json` or certificate can be rejected on the client side
(the VPS is treated purely as "an untrusted place to host already-signed
files").

Never upload the `keys/` directory (the private key `generate_keys.py`
creates) to the VPS. Only upload the contents of `dist/`.

## Usage (run everything on your dev machine)

0. (First time only) generate a signing keypair:

       python3 generate_keys.py

   → produces `keys/signing_key.pem` (the private key — never let it leave
      this machine) and `keys/signing_pub.pem` (the public key).
      Copy the contents of `keys/signing_pub.pem` into
      `client/vps_public_key.pem`.

1. Build the certificate bundle and signed manifest:

       python3 build_bundle.py

   → produces `dist/certs/*.pem`, `dist/manifest.json`, and
      `dist/manifest.json.sig`. Signing happens with the private key on
      this machine; `dist/` never contains the private key itself.

2. Build the client distribution archive (for distributing the whole
   runnable toolkit):

       echo 'VPS_BASE_URL = "https://<your-vps>/retrocert/"' > deploy_config.py
       python3 package_client.py

   `deploy_config.py` is git-ignored and lets you bake your real
   `VPS_BASE_URL` into the packaged `config.py` without editing
   `client/config.py` itself (which stays a placeholder template in the
   repo). If you skip this step, the package ships with the placeholder
   URL — which is intentional for a plain template build, but not usable
   as-is.

   → produces both `dist/retrocert-client.tar.gz` and
      `dist/retrocert-client.zip` (plus a `.sig` for each). Both contain the
      same files, including `bootstrap_ca.pem` (required for the client's
      own outgoing HTTPS requests — don't forget it if you ever build the
      archive by hand). `.zip` is there because Windows Explorer can't
      natively extract `.tar.gz` by double-click, while both macOS and
      Windows can open `.zip` natively. Users should obtain either archive
      over a channel they already trust (e.g. a modern PC), verify the
      signature, and then transfer it to the old machine.

3. Upload only `dist/` to the VPS's static-file directory (e.g. served by
   nginx):

       rsync -av dist/ user@vps:/var/www/retrocert/

   Never include `keys/` in this command.
   Also serve it over plain HTTP in addition to HTTPS (some old machines'
   TLS stacks are too old to even establish HTTPS at all).

4. Example nginx config (on the VPS):

       location /retrocert/ {
           root /var/www;
           autoindex off;
       }

5. Refresh it periodically (via cron/launchd **on your dev machine**, e.g.
   every Sunday at 3am):

       0 3 * * 0 cd /path/to/RetroCert/publisher && python3 build_bundle.py && rsync -av dist/ user@vps:/var/www/retrocert/

   Never register this in the VPS's own crontab — that would require the
   private key to live on the VPS, defeating the whole point.

## Handling revoked certificates

`build_bundle.py` compares against the previously generated
`manifest.json` and automatically adds the common names of any
certificates that dropped out of this run's CA bundle to `revoked`. The
client uses this to remove only the certificates it previously added
itself that match (it never touches certificates the user already had).

## Client-side configuration

Set `VPS_BASE_URL` in `client/config.py` to:

    https://<your-vps>/retrocert/
