"""VPSから証明書マニフェスト・証明書ファイルを取得する

古い機種ではHTTPS自体が使えない場合がある（TLSスタックが古すぎる等）ため、
HTTP経由での取得にも対応する。その代わりHTTPは改竄されうるので、
マニフェストはVPS側の秘密鍵で署名されたものを、クライアント同梱の公開鍵で
検証してから使う。個々の証明書ファイルは、検証済みマニフェストに記載された
sha256で照合するため、マニフェスト1つの署名検証で全体の改竄検知が効く。
"""
from __future__ import annotations

import json
import ssl
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import verify


@dataclass
class CertEntry:
    common_name: str
    filename: str
    sha256: str


@dataclass
class Manifest:
    version: str
    certs: list[CertEntry]
    revoked: list[str]  # 失効・削除対象のコモンネーム一覧


def _build_ssl_context(ca_bundle: str | None) -> ssl.SSLContext:
    if ca_bundle:
        return ssl.create_default_context(cafile=ca_bundle)
    return ssl.create_default_context()


def _fetch_bytes(base_url: str, filename: str, ca_bundle: str | None) -> bytes:
    url = urljoin(base_url, filename)
    # httpの場合はSSLコンテキストを渡さない（HTTPS専用パラメータのため）
    if urlsplit(url).scheme == "https":
        with urllib.request.urlopen(url, context=_build_ssl_context(ca_bundle), timeout=30) as resp:
            return resp.read()
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.read()


def fetch_manifest(
    base_url: str,
    manifest_filename: str,
    public_key_path: Path,
    ca_bundle: str | None = None,
) -> Manifest:
    """マニフェストを取得し、署名を検証したうえで返す。

    署名検証に失敗した場合は例外を投げ、絶対に内容を信用しない
    （HTTP経由での改竄・なりすましを防ぐための最終防衛線）。
    """
    manifest_bytes = _fetch_bytes(base_url, manifest_filename, ca_bundle)
    sig_bytes = _fetch_bytes(base_url, manifest_filename + ".sig", ca_bundle)

    with tempfile.TemporaryDirectory() as tmpdir:
        data_path = Path(tmpdir) / "manifest.json"
        sig_path = Path(tmpdir) / "manifest.json.sig"
        data_path.write_bytes(manifest_bytes)
        sig_path.write_bytes(sig_bytes)
        if not verify.verify_signature(data_path, sig_path, public_key_path):
            raise RuntimeError(
                "マニフェストの署名検証に失敗しました。改竄の可能性があるため処理を中止します。"
            )

    data = json.loads(manifest_bytes)
    certs = [CertEntry(**c) for c in data["certs"]]
    return Manifest(version=data["version"], certs=certs, revoked=data.get("revoked", []))


def fetch_cert_bytes(base_url: str, filename: str, ca_bundle: str | None = None) -> bytes:
    return _fetch_bytes(base_url, filename, ca_bundle)
