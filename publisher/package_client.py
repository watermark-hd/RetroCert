#!/usr/bin/env python3
"""RetroCert クライアント本体をVPSから配布するためのパッケージを作成する

このスクリプトも build_bundle.py と同様、秘密鍵を保管する開発用Macなど
信頼できる端末上でのみ実行する（VPS上では実行しない）。

不特定多数の利用者が使えるようにするため、クライアント一式(*.py + 同梱データ)と
検証用の公開鍵をアーカイブにまとめ、この端末上の秘密鍵で署名してdist/に配置する。
利用者はまずこのアーカイブを（信頼できる経路＝現行のPC・ブラウザ経由のHTTPS等で）
入手し、古いMac/PCへ転送して使う想定（＝最初の入手だけは信頼できる経路で行う
Trust On First Use。以後の証明書更新はHTTPでも署名検証で安全性を確保する）。

.tar.gzと.zipの両方を生成する。.tar.gzはmacOSのFinderで問題なく開けるが、
Windows標準のエクスプローラーは.tar.gzをネイティブに解凍できないため、
どちらのOSでもダブルクリックで開ける.zipも用意している。

重要: client/config.py はGitHubに公開するテンプレートでもあるため、
リポジトリ上は常にプレースホルダーのVPS_BASE_URLにしておきたい。しかし
配布パッケージ自体は本番の実URLで動く必要がある。この2つの要求を
両立させるため、gitignore済みのローカルファイル deploy_config.py に
実際のVPS_BASE_URLを書いておくと、パッケージ内のconfig.pyだけそちらの
値に差し替えて出力する（client/config.py自体は書き換えない）。
deploy_config.pyが無ければテンプレートのプレースホルダーのまま出力する。
"""
from __future__ import annotations

import io
import re
import subprocess
import tarfile
import time
import zipfile
from pathlib import Path

CLIENT_DIR = Path(__file__).parent.parent / "client"
DIST_DIR = Path(__file__).parent / "dist"
PRIVATE_KEY_PATH = Path(__file__).parent / "keys" / "signing_key.pem"
PUBLIC_KEY_PATH = Path(__file__).parent / "keys" / "signing_pub.pem"
# gitignore済み。本番用のVPS_BASE_URLをここに書いておく（例: VPS_BASE_URL = "https://example.com/retrocert/"）
DEPLOY_CONFIG_PATH = Path(__file__).parent / "deploy_config.py"

# クライアント動作に必要なファイル一式（*.pyだけでなく同梱データも含む）
# bootstrap_ca.pemはVPSへの初回HTTPS接続の検証に必須（config.py参照）なので
# 同梱を忘れないこと。config.pyは内容を差し替える可能性があるため別扱い(_resolved_config_bytes)。
INCLUDE_FILES = [
    f for f in sorted(CLIENT_DIR.glob("*.py")) if f.name != "config.py"
] + [CLIENT_DIR / "bootstrap_ca.pem"]


def _resolved_config_bytes() -> bytes:
    """パッケージに入れるconfig.pyの内容を返す（deploy_config.pyがあればVPS_BASE_URLを差し替える）"""
    text = (CLIENT_DIR / "config.py").read_text(encoding="utf-8")
    if not DEPLOY_CONFIG_PATH.exists():
        print(f"警告: {DEPLOY_CONFIG_PATH} がないため、config.pyはプレースホルダーのまま配布物に入ります")
        return text.encode("utf-8")

    deploy_ns: dict = {}
    exec(DEPLOY_CONFIG_PATH.read_text(encoding="utf-8"), deploy_ns)
    deploy_url = deploy_ns.get("VPS_BASE_URL")
    if not deploy_url:
        return text.encode("utf-8")

    text = re.sub(
        r'VPS_BASE_URL = ".*"',
        f'VPS_BASE_URL = "{deploy_url}"',
        text, count=1,
    )
    print(f"config.py内のVPS_BASE_URLを配布用に差し替えました: {deploy_url}")
    return text.encode("utf-8")


def _tar_add_bytes(tar: tarfile.TarFile, data: bytes, arcname: str) -> None:
    """メモリ上のバイト列をファイルとしてtarに追加する（config.py差し替え用）"""
    info = tarfile.TarInfo(name=arcname)
    info.size = len(data)
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))


def _sign(path: Path) -> Path | None:
    if not PRIVATE_KEY_PATH.exists():
        print(f"警告: 署名鍵がありません({PRIVATE_KEY_PATH})。署名なしで配布しないこと")
        return None
    sig_path = path.with_name(path.name + ".sig")
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(PRIVATE_KEY_PATH),
         "-out", str(sig_path), str(path)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"パッケージの署名に失敗しました: {proc.stderr.strip()}")
    return sig_path


def build() -> None:
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    missing = [f for f in INCLUDE_FILES if not f.exists()]
    if missing:
        raise RuntimeError(f"必要なファイルが見つかりません: {missing}")
    if not PUBLIC_KEY_PATH.exists():
        print(f"警告: 公開鍵がありません({PUBLIC_KEY_PATH})。generate_keys.pyを先に実行してください")

    config_bytes = _resolved_config_bytes()

    tar_path = DIST_DIR / "retrocert-client.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        for f in INCLUDE_FILES:
            tar.add(f, arcname=f"retrocert/{f.name}")
        _tar_add_bytes(tar, config_bytes, "retrocert/config.py")
        if PUBLIC_KEY_PATH.exists():
            tar.add(PUBLIC_KEY_PATH, arcname="retrocert/vps_public_key.pem")
    print(f"パッケージを作成しました: {tar_path}")

    zip_path = DIST_DIR / "retrocert-client.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in INCLUDE_FILES:
            zf.write(f, arcname=f"retrocert/{f.name}")
        zf.writestr("retrocert/config.py", config_bytes)
        if PUBLIC_KEY_PATH.exists():
            zf.write(PUBLIC_KEY_PATH, arcname="retrocert/vps_public_key.pem")
    print(f"パッケージを作成しました: {zip_path}（Windows/macOS共通でダブルクリック展開可）")

    for path in (tar_path, zip_path):
        sig_path = _sign(path)
        if sig_path:
            print(f"署名しました: {sig_path}")

    print()
    print("配布時の案内文言の例:")
    print("  1. retrocert-client.zip（またはtar.gz）と.sig, vps_public_key.pemを入手")
    print("  2. 現行の安全な環境で署名を検証してから古い機種へ転送してください")


if __name__ == "__main__":
    build()
