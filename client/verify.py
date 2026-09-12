"""VPSから配布されるマニフェストの署名を検証する

外部コマンド（openssl の dgst -verify）には依存しない。
理由: 対象となる古い機種のシステムopensslが古すぎてSHA-256自体を
サポートしていない場合があることが実機で判明したため
（PowerMac G4 / OS X 10.4 Tiger 搭載の OpenSSL 0.9.7l で確認済み。
 SHA-256はOpenSSL 0.9.8以降の機能）。

一方、自作ビルドのPython（例: 上記G4上のPython 3.12）は独自に新しい
OpenSSLへリンクされており、hashlibのsha256は問題なく使えるため、
それだけで完結するPure PythonのRSA-PKCS#1 v1.5署名検証を実装している。
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

# SHA-256のDigestInfoプレフィックス（PKCS#1 v1.5, RFC 3447 / RFC 8017）
# SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING(32bytes) } の
# OCTET STRINGの中身(ハッシュ本体)より前の固定バイト列
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class _DerReader:
    """最小限のASN.1 DERパーサー（RSA公開鍵の取り出しに必要な分だけ実装）"""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read_tlv(self) -> bytes:
        """次のTLV（タグ・長さ・値）を読み、値(value)部分だけを返す"""
        self.pos += 1  # タグは今回の用途では種類を判別する必要がないため読み飛ばす
        length = self.data[self.pos]
        self.pos += 1
        if length & 0x80:
            n_bytes = length & 0x7F
            length = int.from_bytes(self.data[self.pos:self.pos + n_bytes], "big")
            self.pos += n_bytes
        value = self.data[self.pos:self.pos + length]
        self.pos += length
        return value


def _parse_rsa_public_key(pem_bytes: bytes) -> tuple[int, int]:
    """SubjectPublicKeyInfo形式のPEM (openssl rsa -pubout の出力) から (n, e) を取り出す"""
    lines = [line for line in pem_bytes.decode("ascii").splitlines() if "-----" not in line]
    der = base64.b64decode("".join(lines))

    outer = _DerReader(der).read_tlv()  # 最外周のSEQUENCE
    r = _DerReader(outer)
    r.read_tlv()  # AlgorithmIdentifier（rsaEncryption固定なので内容は見ない）
    bitstring = r.read_tlv()  # BIT STRING
    key_der = bitstring[1:]  # 先頭1バイトは未使用ビット数（常に0x00）

    inner = _DerReader(key_der).read_tlv()  # SEQUENCE { INTEGER n, INTEGER e }
    r2 = _DerReader(inner)
    n_bytes = r2.read_tlv()
    e_bytes = r2.read_tlv()
    return int.from_bytes(n_bytes, "big"), int.from_bytes(e_bytes, "big")


def verify_signature(data_path: Path, signature_path: Path, public_key_path: Path) -> bool:
    """RSA-PKCS#1 v1.5 + SHA-256 署名を検証する。検証成功でTrue"""
    if not public_key_path.exists() or public_key_path.stat().st_size == 0:
        raise RuntimeError(
            f"署名検証用の公開鍵が未設定です: {public_key_path}\n"
            "publisher/generate_keys.py で生成した公開鍵をこのファイルにコピーしてください。"
        )

    n, e = _parse_rsa_public_key(public_key_path.read_bytes())
    signature = signature_path.read_bytes()
    sig_int = int.from_bytes(signature, "big")

    key_size_bytes = (n.bit_length() + 7) // 8
    decrypted = pow(sig_int, e, n).to_bytes(key_size_bytes, "big")

    digest = hashlib.sha256(data_path.read_bytes()).digest()
    expected_suffix = _SHA256_DIGEST_INFO_PREFIX + digest

    # EMSA-PKCS1-v1_5パディング: 0x00 0x01 [0xFF...] 0x00 || DigestInfo
    if not decrypted.startswith(b"\x00\x01"):
        return False
    try:
        sep = decrypted.index(b"\x00", 2)
    except ValueError:
        return False
    padding = decrypted[2:sep]
    if len(padding) < 8 or any(b != 0xFF for b in padding):
        return False
    return decrypted[sep + 1:] == expected_suffix
