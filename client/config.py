"""RetroCert クライアント設定"""
from pathlib import Path

# VPS側で証明書セットとバージョン情報を配信しているベースURL
# 末尾は必ず "/" で終えること（相対パス結合のため）
# ※ ここはプレースホルダー。配布・運用する際は自分のVPSのURLに書き換えること
#   （publisher/README.md参照）
VPS_BASE_URL = "https://your-vps.example.com/retrocert/"

# マニフェストファイル名（VPS_BASE_URL 直下に配置されている想定）
MANIFEST_FILENAME = "manifest.json"

# 古いMac側でのインストール状態を保存する場所
# ※ このプロジェクトフォルダの外だが、対象マシン固有の永続状態のためやむを得ない例外
STATE_DIR = Path.home() / "Library" / "Application Support" / "RetroCert"
STATE_FILE = STATE_DIR / "state.json"

# VPS側の秘密鍵で署名されたマニフェストを検証するための公開鍵
# （配布パッケージに同梱される。server/generate_keys.py で生成した
#  signing_pub.pem の内容をこのファイルにコピーしておくこと）
# ※ 古い機種はHTTPSが使えない場合があるため、マニフェストはHTTPでも
#    取得できるようにしているが、この署名検証によって改竄を検知する。
SIGNING_PUBLIC_KEY = Path(__file__).parent / "vps_public_key.pem"

# VPSへの初回接続時に使うブートストラップ用CA証明書
# 自作ビルドのPython（例: PowerMac G4のPython 3.12）はOS本体のKeychainとは
# 独立したSSL検証を行い、CAバンドルが組み込まれていないと自分自身の
# HTTPS通信すら検証できないことが実機で判明したため、常にこれを同梱・使用する。
# （RetroCertが修復する対象はOS側のKeychainであり、Python自身のSSL検証とは別物）
BOOTSTRAP_CA_BUNDLE = Path(__file__).parent / "bootstrap_ca.pem"

# 証明書を登録する対象キーチェーン
# デフォルトはログインキーチェーン（sudo不要・対象ユーザーのみに影響）
LOGIN_KEYCHAIN = "login.keychain"
# システム全体に反映したい場合はこちら（要sudo）
SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"

# --- OS X 10.4 (Tiger) 専用設定 ---
# TigerにはTrust Settings API（10.5以降のadd-trusted-cert/delete-certificate）が
# 存在しない。ルート信頼はこのアンカー専用ストアへの証明書の「存在」で決まる。
TIGER_ANCHORS_PATH = "/System/Library/Keychains/X509Anchors"
# 初回変更前のオリジナルを保存しておく場所（削除機能を将来的に実装する際の復元用）
TIGER_ANCHORS_BACKUP = STATE_DIR / "X509Anchors.pristine-backup"
