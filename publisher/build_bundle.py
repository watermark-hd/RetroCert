#!/usr/bin/env python3
"""RetroCert Publisher: 最新のルート証明書セットと署名済みマニフェストを生成する

想定運用:
  ・このスクリプトは署名鍵(keys/signing_key.pem)を保管する開発用Macなど、
    信頼できる端末上でのみ実行する（VPS上では絶対に実行しない）
  ・生成される dist/ 配下だけをVPSへアップロードして nginx 等で静的配信する
  ・クライアント(RetroCert本体)はマニフェストと証明書ファイルを取得するだけなので
    VPS側の負荷は非常に軽い（証明書を毎回生成するわけではない）
  ・VPSには秘密鍵を置かないため、VPSが突破されても正しい署名は作れない
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import urllib.request
from dataclasses import dataclass
from datetime import date
from pathlib import Path

# 信頼できる最新のルート証明書バンドルの取得元
# curlプロジェクトが配布している、Mozillaのトラストストア由来のcacert.pemを利用
CA_SOURCE_URL = "https://curl.se/ca/cacert.pem"

DIST_DIR = Path(__file__).parent / "dist"
CERTS_DIR = DIST_DIR / "certs"
MANIFEST_PATH = DIST_DIR / "manifest.json"
MANIFEST_SIG_PATH = DIST_DIR / "manifest.json.sig"
PRIVATE_KEY_PATH = Path(__file__).parent / "keys" / "signing_key.pem"

_PEM_PATTERN = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


@dataclass
class CertInfo:
    common_name: str
    filename: str
    sha256: str


def fetch_ca_bundle() -> str:
    with urllib.request.urlopen(CA_SOURCE_URL, timeout=60) as resp:
        return resp.read().decode("utf-8")


def split_bundle(bundle_text: str) -> list[str]:
    """複数証明書が連結されたバンドルを1証明書ずつに分割する"""
    return _PEM_PATTERN.findall(bundle_text)


def der_sha256(pem: str) -> str:
    """クライアント側(store_macos.sha256_fingerprint)と同一基準のフィンガープリント。

    PEMのBase64本体はそもそもDER表現そのものなので、openssl等を介さず
    Base64デコードのみで求める。これにより、クライアント側の古いopenssl
    （例: Tigerの0.9.7l）とのDER再エンコード結果の食い違いを避けられる
    （特にECC証明書で顕在化した）。
    """
    lines = [line for line in pem.splitlines() if line and "-----" not in line]
    der = base64.b64decode("".join(lines))
    return hashlib.sha256(der).hexdigest()


def common_name(pem: str) -> str:
    proc = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-nameopt", "sep_multiline"],
        input=pem.encode("utf-8"), capture_output=True,
    )
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("CN="):
            return line[3:]
    return "unknown"


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", name).strip("-").lower()
    return slug or "cert"


def sign_manifest() -> None:
    """マニフェストに署名する（HTTP配信でも改竄を検知できるようにするため）

    クライアント側は同梱された公開鍵でこの署名を検証してから
    マニフェストの内容（各証明書のsha256）を信用する。個々の証明書ファイルは
    署名済みマニフェストのsha256で検証されるため、ここで署名するのは
    manifest.json 1つだけで足りる。
    """
    if not PRIVATE_KEY_PATH.exists():
        print(f"警告: 署名鍵がありません({PRIVATE_KEY_PATH})。先に generate_keys.py を実行してください")
        print("  署名なしのマニフェストは配布しないでください（改竄検知が効きません）")
        return
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(PRIVATE_KEY_PATH),
         "-out", str(MANIFEST_SIG_PATH), str(MANIFEST_PATH)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"マニフェストの署名に失敗しました: {proc.stderr.strip()}")
    print(f"マニフェストに署名しました: {MANIFEST_SIG_PATH}")


def build() -> None:
    print("最新のCAバンドルを取得中...")
    bundle_text = fetch_ca_bundle()
    pems = split_bundle(bundle_text)
    print(f"{len(pems)} 件の証明書を検出しました")

    # 前回のマニフェストと比較し、消えた証明書を「失効」として扱う
    previous_names: set[str] = set()
    if MANIFEST_PATH.exists():
        prev = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        previous_names = {c["common_name"] for c in prev.get("certs", [])}

    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    certs: list[CertInfo] = []
    used_filenames: set[str] = set()
    for pem in pems:
        cn = common_name(pem)
        base = slugify(cn)
        filename = f"{base}.pem"
        i = 2
        while filename in used_filenames:
            filename = f"{base}-{i}.pem"
            i += 1
        used_filenames.add(filename)

        (CERTS_DIR / filename).write_text(pem, encoding="utf-8")
        # マニフェストにはVPS_BASE_URLからの相対パスを記録する（実体はcerts/配下にある）
        certs.append(CertInfo(common_name=cn, filename=f"certs/{filename}", sha256=der_sha256(pem)))

    current_names = {c.common_name for c in certs}
    revoked = sorted(previous_names - current_names)

    manifest = {
        "version": date.today().isoformat(),
        "certs": [c.__dict__ for c in certs],
        "revoked": revoked,
    }
    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"マニフェストを書き出しました: {MANIFEST_PATH}")
    print(f"  バージョン: {manifest['version']}")
    print(f"  証明書数: {len(certs)} / 失効: {len(revoked)}")

    sign_manifest()


if __name__ == "__main__":
    build()
