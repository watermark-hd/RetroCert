#!/usr/bin/env python3
"""署名用の鍵ペアを生成する（初回のみ実行）

このスクリプトは開発用Macなど、信頼できる端末上で実行すること
（VPS上では絶対に実行しない。秘密鍵をVPSに置かないことが本設計の要）。

RetroCertはHTTP経由でも改竄を検知できるようにするため、
この端末上の秘密鍵でマニフェスト等に署名し、クライアント側に同梱した
公開鍵で検証する。VPSは署名済みファイルを置くだけの「信頼しない置き場」。

生成される秘密鍵(signing_key.pem)はこの端末の外に絶対に出さないこと。
公開鍵(signing_pub.pem)はクライアント側 (client/vps_public_key.pem) に
コピーして配布する。
"""
from __future__ import annotations

import subprocess
from pathlib import Path

KEYS_DIR = Path(__file__).parent / "keys"
PRIVATE_KEY = KEYS_DIR / "signing_key.pem"
PUBLIC_KEY = KEYS_DIR / "signing_pub.pem"


def main() -> None:
    KEYS_DIR.mkdir(exist_ok=True)
    if PRIVATE_KEY.exists():
        print(f"既に鍵が存在します: {PRIVATE_KEY}")
        print("鍵を再生成すると、配布済みクライアントは検証に失敗するようになるため注意してください。")
        return

    subprocess.run(["openssl", "genrsa", "-out", str(PRIVATE_KEY), "4096"], check=True)
    subprocess.run(
        ["openssl", "rsa", "-in", str(PRIVATE_KEY), "-pubout", "-out", str(PUBLIC_KEY)],
        check=True,
    )
    PRIVATE_KEY.chmod(0o600)

    print(f"秘密鍵を生成しました: {PRIVATE_KEY} (絶対に外部へ出さないこと)")
    print(f"公開鍵を生成しました: {PUBLIC_KEY}")
    print("この公開鍵の内容を client/vps_public_key.pem にコピーしてから")
    print("クライアントを配布してください。")


if __name__ == "__main__":
    main()
