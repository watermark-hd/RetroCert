"""macOS証明書ストア操作ラッパー

標準搭載の `security` コマンドと `openssl` コマンドのみを利用し、
外部ライブラリへの依存を避けている（自作Python環境でも動かすため）。

OS Xのバージョンによって挙動が大きく異なることが実機検証で判明している:

  - 10.5 (Leopard) 以降: `security add-trusted-cert` / `security delete-certificate`
    というTrust Settings API相当のCLIが使えるため、通常のキーチェーン
    （login.keychain / System.keychain）に対して操作する。

  - 10.4 (Tiger): 上記コマンドが存在しない。ルート信頼は
    `/System/Library/Keychains/X509Anchors` というアンカー専用ストアに
    証明書が「存在するかどうか」だけで決まる（Trust Settingsという概念自体がない）。
    実機(PowerMac G4, Darwin 8.11.0)で以下を検証済み:
      * 一覧取得: `security find-certificate -a -p /System/Library/Keychains/X509Anchors`
      * 追加:     `security add-certificates -k <path> <cert.der>`
                  （PEMは `CL_UNKNOWN_FORMAT` で失敗する。DER形式必須）
      * 削除:     対応するコマンドがTigerの `security` に存在しない
                  （`delete-certificate` は10.5以降で追加されたコマンド）
      * 楕円曲線(ECC/ECDSA)証明書は、DER化しても `security add-certificates`
        が `CL_UNKNOWN_FORMAT` で拒否する（2005年当時のCSSM証明書ライブラリが
        ecPublicKey OIDを認識しないため）。RSA系証明書は問題なく追加できる。

PEM→DER変換について: PEMのBase64本体はそもそもDER表現そのものであり、
再変換に外部コマンド(openssl)は不要（Base64デコードのみで済む）。
これにより、システムの古いopensslがECC等の証明書を正しく再変換できない
問題も同時に回避している。
"""
from __future__ import annotations

import base64
import hashlib
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path

import config

# ecPublicKey (1.2.840.10045.2.1) のASN.1 DER表現。
# この並びがDER中に含まれていれば楕円曲線(ECC/ECDSA)公開鍵と判定する。
_EC_PUBLIC_KEY_OID = bytes.fromhex("06072a8648ce3d0201")


def _pem_to_der(pem_bytes: bytes) -> bytes:
    """PEM証明書のBase64本体をデコードしてDER形式のバイト列を返す"""
    lines = [
        line for line in pem_bytes.decode("ascii").splitlines()
        if line and "-----" not in line
    ]
    return base64.b64decode("".join(lines))


@dataclass
class InstalledCert:
    common_name: str
    sha256: str  # DERエンコードに対するSHA-256フィンガープリント


def _is_tiger() -> bool:
    version = platform.mac_ver()[0]  # 例: "10.4.11"
    if not version:
        return False
    parts = version.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return False
    return (major, minor) <= (10, 4)


def sha256_fingerprint(pem_bytes: bytes) -> str:
    """PEM証明書をDERへ変換してSHA-256フィンガープリントを求める。

    キーチェーン内の証明書とVPS配布物を同一基準で比較するための共通関数。
    publisher側(publisher/build_bundle.py)も同じ変換方式(Base64デコード)を
    使っているため、両者は常に同じフィンガープリントを算出する。
    """
    return hashlib.sha256(_pem_to_der(pem_bytes)).hexdigest()


def _common_name(pem_bytes: bytes) -> str:
    proc = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-nameopt", "sep_multiline"],
        input=pem_bytes, capture_output=True,
    )
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("CN="):
            return line[3:]
    return "(不明な証明書)"


def _split_pem_blocks(text: str) -> list[bytes]:
    blocks: list[bytes] = []
    current: list[str] = []
    in_block = False
    for line in text.splitlines():
        if "-----BEGIN CERTIFICATE-----" in line:
            in_block = True
            current = [line]
        elif "-----END CERTIFICATE-----" in line:
            current.append(line)
            blocks.append(("\n".join(current) + "\n").encode("utf-8"))
            in_block = False
        elif in_block:
            current.append(line)
    return blocks


def is_legacy_anchor_mode() -> bool:
    """呼び出し元(retrocert.py)がTiger特有の挙動を案内するために使う"""
    return _is_tiger()


def _target_path(keychain: str) -> str:
    """Tigerでは常にX509Anchorsを対象にする（--systemの指定有無に関わらない）"""
    return config.TIGER_ANCHORS_PATH if _is_tiger() else keychain


def list_installed_certs(keychain: str) -> list[InstalledCert]:
    """指定キーチェーン（Tigerの場合はX509Anchors固定）内の証明書一覧を取得する"""
    target = _target_path(keychain)
    proc = subprocess.run(
        ["security", "find-certificate", "-a", "-p", target],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"証明書一覧の取得に失敗しました: {proc.stderr.strip()}")

    certs: list[InstalledCert] = []
    for pem_bytes in _split_pem_blocks(proc.stdout):
        certs.append(InstalledCert(
            common_name=_common_name(pem_bytes),
            sha256=sha256_fingerprint(pem_bytes),
        ))
    return certs


def add_trusted_cert(cert_path: str, keychain: str, system_wide: bool = False) -> None:
    """証明書をルート信頼として追加する"""
    if _is_tiger():
        _tiger_add_cert(cert_path)
        return

    args = ["security", "add-trusted-cert"]
    if system_wide:
        args += ["-d"]
    args += ["-r", "trustRoot", "-k", keychain, cert_path]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"証明書の追加に失敗しました: {proc.stderr.strip()}")


def delete_cert(common_name: str, keychain: str) -> None:
    """コモンネームを指定して証明書を削除する"""
    if _is_tiger():
        _tiger_remove_cert(common_name)
        return

    proc = subprocess.run(
        ["security", "delete-certificate", "-c", common_name, "-t", keychain],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"証明書の削除に失敗しました: {proc.stderr.strip()}")


# --- Tiger (OS X 10.4) 専用処理 ---

def _ensure_pristine_backup() -> None:
    """初回変更前のX509Anchorsを保存しておく（将来の削除機能・復元用）"""
    backup = config.TIGER_ANCHORS_BACKUP
    if backup.exists():
        return
    backup.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["cp", config.TIGER_ANCHORS_PATH, str(backup)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"オリジナルのアンカーストアのバックアップに失敗しました: {proc.stderr.strip()}")


def _tiger_add_cert(cert_path: str) -> None:
    _ensure_pristine_backup()

    der_bytes = _pem_to_der(Path(cert_path).read_bytes())
    if _EC_PUBLIC_KEY_OID in der_bytes:
        raise RuntimeError(
            "OS X 10.4 (Tiger) は楕円曲線(ECC/ECDSA)証明書に対応していないためスキップします"
            "（2005年当時の証明書ライブラリがこの形式を認識しないため。RSA系証明書は問題ありません）"
        )

    der_path = Path(cert_path).with_suffix(".der")
    der_path.write_bytes(der_bytes)
    try:
        proc = subprocess.run(
            ["security", "add-certificates", "-k", config.TIGER_ANCHORS_PATH, str(der_path)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                "証明書の追加に失敗しました（sudoで実行していますか？）: "
                f"{proc.stderr.strip()}"
            )
    finally:
        der_path.unlink(missing_ok=True)


def _tiger_remove_cert(common_name: str) -> None:
    """Tigerでの自動削除は未対応。

    Tigerの `security` には `delete-certificate` に相当するコマンドが
    存在しないため、システムのルート信頼ストア(X509Anchors)を丸ごと
    入れ替えるリスクを避け、v1では手動対応を促すに留める。
    """
    raise RuntimeError(
        f"OS X 10.4 (Tiger) では証明書の自動削除に対応していません（対象: {common_name}）。"
        f"必要であれば {config.TIGER_ANCHORS_BACKUP} を参考に手動で対応してください。"
    )
