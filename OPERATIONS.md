# RetroCert 運用ガイド（証明書・暗号の知識がなくても読める版）

このファイルは「実際に運用するときに何をすればいいか」だけをまとめたものです。
仕組みの詳細は README.ja.md にありますが、ここでは「押すべきボタン」だけ書きます。

## そもそも何なのか（3行で）

- 古いMacはルート証明書（Webサイトの本人確認に使う「信頼できる印鑑リスト」）が
  更新されないため、最近のサイトにHTTPS接続できなくなることがある。
- RetroCertは、あなたのVPS(サーバー)から最新の印鑑リストを取ってきて
  古いMacに反映するツール。
- 「秘密鍵」（署名するための本物の印鑑）は絶対にあなたの手元のMacだけに置き、
  VPSには「印鑑を押した後の紙（署名済みファイル）」だけを置く。これにより、
  VPSが乗っ取られても、印鑑（秘密鍵）自体は盗まれない。

## 日常でやること: 証明書リストの定期更新

サイトのルート証明書は時々入れ替わるので、ときどき更新が必要です（3〜6ヶ月おき程度で十分）。

このMac（今の開発環境）で:

```bash
cd /Users/watermark/developer/RetroCert/publisher
python3 build_bundle.py
```

これで最新の証明書リストが作られ、自動的に署名もされます。
（`publisher/keys/signing_key.pem` という秘密鍵ファイルを使って署名します。
このファイルは絶対に他人に渡さない・VPSにアップロードしないこと）

できたファイルをVPSへアップロード:

```bash
rsync -avz dist/manifest.json dist/manifest.json.sig dist/certs/ \
  ubuntu@160.16.214.159:/var/www/retrocert/certs/
rsync -avz dist/manifest.json dist/manifest.json.sig \
  ubuntu@160.16.214.159:/var/www/retrocert/
```

これだけで、古いMac側は次回起動時に自動的に新しいリストを取りに来ます
（古いMac側のコードは何も変更しなくてよい）。

## クライアント（古いMacで動くプログラム本体）を修正したとき

`client/` フォルダの中のプログラムを直したときだけ必要な作業です。
証明書リストの更新だけなら不要です。

```bash
cd /Users/watermark/developer/RetroCert/publisher

# 初回だけ: 本番のURLを書いたファイルを作る（このファイルはGit管理外＝公開されない）
echo 'VPS_BASE_URL = "https://oldmac.policy-log.jp/retrocert/"' > deploy_config.py

python3 package_client.py
```

→ `dist/retrocert-client.tar.gz` と `dist/retrocert-client.zip` ができます
（どちらも同じ内容。Windowsの人はzip、Macの人はどちらでも開けます）。

VPSへアップロード:

```bash
rsync -avz dist/retrocert-client.tar.gz dist/retrocert-client.tar.gz.sig \
           dist/retrocert-client.zip dist/retrocert-client.zip.sig \
  ubuntu@160.16.214.159:/var/www/retrocert/
```

**注意**: `client/config.py` というファイル自体は絶対に本番用の値に書き換えて
コミットしないこと（GitHub公開用のテンプレートなので、プレースホルダーのままに
しておく）。本番用の値は上の `deploy_config.py` だけに書く。

## 鍵（秘密鍵）について、これだけは絶対に守ること

- `publisher/keys/signing_key.pem` が「秘密鍵」＝本物の印鑑そのもの。
  - このファイルは**このMacの外に絶対に出さない**（メール添付、Slack、
    GitHubへのアップロード、VPSへのアップロード、すべて禁止）。
  - `.gitignore` で自動的にGit管理から除外されているので、
    普通に `git add` してもうっかりコミットされることはない。
- もしこの秘密鍵が漏れてしまったら（PCを盗まれた、誤って公開した等）:
  1. すぐに `publisher/keys/` フォルダを削除し、`generate_keys.py` を
     実行して鍵を作り直す。
  2. 新しい公開鍵を `client/vps_public_key.pem`（配布時のみ、通常は
     `deploy_config.py` 的な仕組みと同様に扱う）に反映し、クライアントを
     再パッケージング・再配布する。
  3. 古い鍵で署名された証明書リストはもう安全とはみなせないので、
     VPS側のファイルも作り直したものに置き換える。
  4. 一度配ってしまった古いクライアント（古い公開鍵入り）は、
     漏れた秘密鍵で偽の証明書を送り込まれるリスクが残る。
     可能なら利用者に新しいクライアントの入手を案内する。

## 何か壊れたときに確認する順番

1. **VPS上にファイルがちゃんとあるか**

       curl -sI https://oldmac.policy-log.jp/retrocert/manifest.json

   `HTTP/2 200` が出ればOK。404なら配置忘れ。

2. **manifest.jsonの中身が読めるか**

       curl -s https://oldmac.policy-log.jp/retrocert/manifest.json | head

   JSONが表示されればOK。

3. **署名が合っているか**（古いMac側で実行したときのエラーメッセージで判断）
   - 「マニフェストの署名検証に失敗しました」と出たら、`manifest.json` と
     `manifest.json.sig` の組が合っていない（片方だけ更新して片方古いまま
     アップロードした、等）。両方セットで作り直してアップロードする。

4. **証明書ファイル個別のダウンロードが失敗する**
   - `manifest.json` に書いてあるファイル名（`certs/xxx.pem`）と、実際に
     VPS上にあるファイルの場所が食い違っていないか確認する。

     ```bash
     curl -sI https://oldmac.policy-log.jp/retrocert/certs/isrg-root-x1.pem
     ```

## 超ざっくり用語集

- **証明書 / ルート証明書**: 「このサイトは本物です」という電子的な印鑑証明書。
  ルート証明書は、その印鑑証明書自体が本物かどうかを保証する「元締めの印鑑」。
- **秘密鍵 / 公開鍵**: 秘密鍵は「本物の印鑑」（絶対に人に見せない）。
  公開鍵は「その印鑑で押された跡が本物かどうかを誰でも確認できる道具」
  （みんなに配って良い）。
- **署名**: 秘密鍵（印鑑）でファイルに押した跡。公開鍵があれば誰でも
  「これは本当にその秘密鍵で押されたものか」を確認できる。
- **改竄検知**: ファイルの内容が途中で誰かに書き換えられていないかを、
  署名を使って確認すること。
