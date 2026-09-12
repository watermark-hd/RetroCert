#!/usr/bin/env python3
"""RetroCert クライアント本体をVPSから配布するためのパッケージを作成する

このスクリプトも build_bundle.py と同様、秘密鍵を保管する開発用Macなど
信頼できる端末上でのみ実行する（VPS上では実行しない）。

不特定多数の利用者が使えるようにするため、クライアント一式(*.py)と
検証用の公開鍵をtar.gzにまとめ、この端末上の秘密鍵で署名してdist/に配置する。
利用者はまずこのアーカイブを（信頼できる経路＝現行のPC・ブラウザ経由のHTTPS等で）
入手し、古いMac/PCへ転送して使う想定（＝最初の入手だけは信頼できる経路で行う
Trust On First Use。以後の証明書更新はHTTPでも署名検証で安全性を確保する）。
"""
from __future__ import annotations

import subprocess
import tarfile
from pathlib import Path

CLIENT_DIR = Path(__file__).parent.parent / "client"
DIST_DIR = Path(__file__).parent / "dist"
ARCHIVE_PATH = DIST_DIR / "retrocert-client.tar.gz"
ARCHIVE_SIG_PATH = DIST_DIR / "retrocert-client.tar.gz.sig"
PRIVATE_KEY_PATH = Path(__file__).parent / "keys" / "signing_key.pem"
PUBLIC_KEY_PATH = Path(__file__).parent / "keys" / "signing_pub.pem"


def build() -> None:
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    with tarfile.open(ARCHIVE_PATH, "w:gz") as tar:
        for py_file in sorted(CLIENT_DIR.glob("*.py")):
            tar.add(py_file, arcname=f"retrocert/{py_file.name}")
        if PUBLIC_KEY_PATH.exists():
            tar.add(PUBLIC_KEY_PATH, arcname="retrocert/vps_public_key.pem")
        else:
            print(f"警告: 公開鍵がありません({PUBLIC_KEY_PATH})。generate_keys.pyを先に実行してください")

    print(f"パッケージを作成しました: {ARCHIVE_PATH}")

    if not PRIVATE_KEY_PATH.exists():
        print(f"警告: 署名鍵がありません({PRIVATE_KEY_PATH})。署名なしで配布しないこと")
        return

    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(PRIVATE_KEY_PATH),
         "-out", str(ARCHIVE_SIG_PATH), str(ARCHIVE_PATH)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"パッケージの署名に失敗しました: {proc.stderr.strip()}")
    print(f"署名しました: {ARCHIVE_SIG_PATH}")
    print()
    print("配布時の案内文言の例:")
    print("  1. retrocert-client.tar.gz と .sig, vps_public_key.pem を入手")
    print("  2. 現行の安全な環境で署名を検証してから古い機種へ転送してください")


if __name__ == "__main__":
    build()
