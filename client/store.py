"""OS別の証明書ストア操作を切り替えるディスパッチ層

対応OS:
  - macOS (OS X 10.4 Tiger 以降): store_macos.py（security / opensslコマンド利用）
  - Windows: store_windows.py（未実装・今後追加予定。certutilコマンドを想定）

retrocert.py本体はこのモジュール経由でのみストア操作を行い、
OS差分をここに閉じ込める。
"""
from __future__ import annotations

import platform

_system = platform.system()

if _system == "Darwin":
    from store_macos import (  # noqa: F401
        InstalledCert,
        sha256_fingerprint,
        list_installed_certs,
        add_trusted_cert,
        delete_cert,
        is_legacy_anchor_mode,
    )
elif _system == "Windows":
    # store_windows.py 実装後にここを切り替える
    raise NotImplementedError("Windows対応は未実装です（今後追加予定）")
else:
    raise NotImplementedError(f"未対応のOSです: {_system}")
