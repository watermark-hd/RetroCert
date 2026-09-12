# RetroCert Publisher（発行者側ツール）

*(English version: [README.md](README.md))*

## 役割と重要な前提
**このディレクトリのスクリプトはVPS上では実行しません。**
署名鍵を保管する、あなたの手元の信頼できる端末（開発用Mac）で実行してください。

    開発用Mac（このpublisher/を実行する場所。秘密鍵はここだけに存在）
      ↓ 秘密鍵で manifest.json / クライアント配布物に署名
    署名済みの manifest.json + .sig + certs/ + retrocert-client.{tar.gz,zip} + .sig
      ↓ rsync 等でアップロード（ここには秘密鍵を含めない）
    VPS（署名済みの静的ファイルを置いて配信するだけ。秘密鍵は一切置かない）
      ↓ HTTP/HTTPS
    RetroCert（クライアント。同梱の公開鍵で署名を検証してから内容を信用する）

この分離により、**VPSが突破されても秘密鍵は盗まれず**、攻撃者は正しい署名を
作れないため、悪意あるmanifest.jsonや証明書に差し替えられてもRetroCert側で
拒否できます（VPSは「署名済みファイルを置くだけの信頼しない置き場」という位置づけ）。

`keys/` ディレクトリ（`generate_keys.py` が作る秘密鍵）は絶対にVPSへ
アップロードしないでください。アップロードするのは `dist/` の中身だけです。

## 使い方（すべて開発用Mac側で実行）

0. （初回のみ）署名鍵ペアを生成する

       python3 generate_keys.py

   → `keys/signing_key.pem`（秘密鍵・この端末の外に絶対に出さない）と
      `keys/signing_pub.pem`（公開鍵）が生成されます。
      `keys/signing_pub.pem` の内容を `client/vps_public_key.pem` にコピーしてください。

1. 証明書バンドルと署名済みマニフェストを生成する

       python3 build_bundle.py

   → `dist/certs/*.pem`、`dist/manifest.json`、`dist/manifest.json.sig` が生成されます。
      署名はこの端末上の秘密鍵で行われ、`dist/` には秘密鍵は含まれません。

2. クライアント配布アーカイブを生成する（実行ファイル一式の配布用）

       python3 package_client.py

   → `dist/retrocert-client.tar.gz` と `dist/retrocert-client.zip`（それぞれの
      署名 `.sig` も含む）が生成されます。両方に同じ内容が入っており、
      `bootstrap_ca.pem`（クライアント自身のHTTPS通信の検証に必須。手動で
      アーカイブを作る場合は入れ忘れないこと）も同梱されます。`.zip`を
      用意している理由は、Windowsのエクスプローラーは`.tar.gz`をダブル
      クリックでネイティブに解凍できないため（`.zip`ならmacOS/Windowsどちらも
      標準機能で開けます）。利用者はどちらかを安全な経路（現行PC等）で入手し、
      署名検証後に古い機種へ転送します。

3. `dist/` 配下だけをVPS上の静的配信ディレクトリ（nginx等）へアップロードする

       rsync -av dist/ user@vps:/var/www/retrocert/

   `keys/` は絶対にこのコマンドに含めないこと。
   HTTPでもアクセスできるよう、nginxはHTTPSに加えてポート80でも配信してください
   （古い機種はTLSが古すぎてHTTPSに接続できない場合があるため）。

4. nginx設定例（VPS側）

       location /retrocert/ {
           root /var/www;
           autoindex off;
       }

5. 定期的に最新化する（開発用Mac側のcron/launchdで、例: 毎週日曜3時）

       0 3 * * 0 cd /path/to/RetroCert/publisher && python3 build_bundle.py && rsync -av dist/ user@vps:/var/www/retrocert/

   ※ VPS側のcrontabには絶対に登録しないこと（秘密鍵がVPSに必要になってしまうため）。

## 失効証明書の扱い
`build_bundle.py` は前回生成した `manifest.json` と比較し、
今回のCAバンドルから消えた証明書のコモンネームを自動的に `revoked` に
追加します。クライアント側はこれを見て、自分が過去に追加した証明書の
うち該当するものだけを削除します（ユーザーが元々持っていた証明書には
手を出しません）。

## クライアント側の設定
`client/config.py` の `VPS_BASE_URL` を

    https://<あなたのVPS>/retrocert/

に変更してください。
