#!/usr/bin/env python3
"""RetroCert: 古いMac向けルート証明書レスキューツール（クライアント本体）

流れ:
  1. 古いOSの証明書ストア（Keychain）を確認
  2. VPSから最新の証明書セット（マニフェスト）を取得
  3. 差分を計算（追加すべき証明書／失効した証明書）
  4. 新しいルート証明書を登録し、不要な証明書を整理
  5. 終了
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

import config
import store
import manifest as manifest_mod
import state as state_mod


def _ca_bundle_path() -> str | None:
    if config.BOOTSTRAP_CA_BUNDLE is None:
        return None
    p = Path(config.BOOTSTRAP_CA_BUNDLE)
    return str(p) if p.exists() else None


def run(apply_changes: bool, system_wide: bool) -> int:
    keychain_target = config.SYSTEM_KEYCHAIN if system_wide else config.LOGIN_KEYCHAIN

    print("=== RetroCert: ルート証明書レスキュー ===")
    if store.is_legacy_anchor_mode():
        print(f"OS X 10.4 (Tiger) を検出: 常にシステムのアンカーストア({config.TIGER_ANCHORS_PATH})に反映します")
        print("  ※ 削除の自動対応は未対応です。追加のみ行います（要sudo）")
    else:
        print(f"対象キーチェーン: {keychain_target}")

    st = state_mod.load_state()

    print("[1/5] 現在の証明書ストアを確認中...")
    try:
        installed = store.list_installed_certs(keychain_target)
    except RuntimeError as e:
        print(f"エラー: {e}", file=sys.stderr)
        return 1
    installed_fingerprints = {c.sha256 for c in installed}
    print(f"  現在 {len(installed)} 件の証明書が登録されています")

    print(f"[2/5] VPSから最新の証明書セットを取得中... ({config.VPS_BASE_URL})")
    try:
        mf = manifest_mod.fetch_manifest(
            config.VPS_BASE_URL, config.MANIFEST_FILENAME,
            config.SIGNING_PUBLIC_KEY, ca_bundle=_ca_bundle_path()
        )
    except Exception as e:
        print(f"エラー: VPSへの接続に失敗しました: {e}", file=sys.stderr)
        return 1
    print(f"  最新バージョン: {mf.version} (前回反映: {st.last_version or '未反映'})")

    print("[3/5] 差分を確認中...")
    missing = [c for c in mf.certs if c.sha256 not in installed_fingerprints]
    tracked_names = {e.common_name for e in st.installed_by_retrocert}
    obsolete = [
        e for e in st.installed_by_retrocert
        if e.common_name in mf.revoked and e.common_name in tracked_names
    ]
    print(f"  追加予定: {len(missing)} 件")
    for c in missing:
        print(f"    + {c.common_name}")
    print(f"  削除予定（失効・不要）: {len(obsolete)} 件")
    for e in obsolete:
        print(f"    - {e.common_name}")

    if not apply_changes:
        print("\n(ドライランモード: 実際の変更は行っていません。反映するには --apply を指定してください)")
        return 0

    print("[4/5] 証明書を登録・整理中...")
    with tempfile.TemporaryDirectory() as tmpdir:
        for c in missing:
            try:
                data = manifest_mod.fetch_cert_bytes(
                    config.VPS_BASE_URL, c.filename, ca_bundle=_ca_bundle_path()
                )
                if store.sha256_fingerprint(data) != c.sha256:
                    print(f"  警告: {c.common_name} はフィンガープリントが一致しないためスキップしました", file=sys.stderr)
                    continue
                # c.filenameは"certs/xxx.pem"のようにサブディレクトリを含む場合があるが、
                # ここではローカルの一時保存先なのでディレクトリ構造は不要（ベース名のみ使う）
                cert_path = Path(tmpdir) / Path(c.filename).name
                cert_path.write_bytes(data)
                store.add_trusted_cert(str(cert_path), keychain_target, system_wide=system_wide)
                state_mod.record_install(st, c.common_name, c.sha256)
                print(f"  追加完了: {c.common_name}")
            except Exception as e:
                print(f"  警告: {c.common_name} の追加に失敗しました: {e}", file=sys.stderr)

        for e in obsolete:
            try:
                store.delete_cert(e.common_name, keychain_target)
                state_mod.record_removal(st, e.common_name)
                print(f"  削除完了: {e.common_name}")
            except Exception as ex:
                print(f"  警告: {e.common_name} の削除に失敗しました: {ex}", file=sys.stderr)

    st.last_version = mf.version
    state_mod.save_state(st)

    print("[5/5] 完了しました。")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="RetroCert: 古いMac向けルート証明書レスキューツール")
    parser.add_argument("--apply", action="store_true", help="実際に証明書の追加・削除を行う（未指定時はドライラン）")
    parser.add_argument("--system", action="store_true", help="System.keychainに反映する（要sudo・マシン全体に影響）")
    args = parser.parse_args()
    return run(apply_changes=args.apply, system_wide=args.system)


if __name__ == "__main__":
    sys.exit(main())
