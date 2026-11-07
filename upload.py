"""YouTube Data API v3 で動画を投稿する（Python 標準ライブラリのみ）。

使い方:
    python tools/upload.py auth                              初回の認可。ブラウザで許可する
    python tools/upload.py whoami                            認可したチャンネル名を表示
    python tools/upload.py upload episodes/q001-area [--public | --at 2026-11-08T19:00]

- 認証ファイル: secrets/client_secret_*.json（Google Cloud の「デスクトップ アプリ」用 OAuth クライアント）
- 認可の結果: secrets/token.json（リフレッシュトークン）。外部に出さない
- 既定は非公開で投稿する。監査を通していない API プロジェクトは公開設定にかかわらず非公開に固定される
- 秘密の値（client_secret・トークン）は標準出力に出さない
"""
import base64
import hashlib
import http.server
import json
import secrets as token_bytes
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECRETS = ROOT / "secrets"
TOKEN_PATH = SECRETS / "token.json"
SCOPES = "https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.readonly"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
API = "https://www.googleapis.com/youtube/v3"
UPLOAD_API = "https://www.googleapis.com/upload/youtube/v3/videos"
JST = timezone(timedelta(hours=9))

# 投稿の共通設定（channel/profile.md と同じ）
CATEGORY_ENTERTAINMENT = "24"
TAGS = ["ずんだもん", "四国めたん", "2択クイズ", "クイズ", "雑学"]


def client():
    files = sorted(SECRETS.glob("client_secret_*.json"))
    if not files:
        raise SystemExit("secrets/client_secret_*.json がない")
    return json.loads(files[0].read_text(encoding="utf-8"))["installed"]


def post_form(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data)) as res:
            return json.load(res)
    except urllib.error.HTTPError as error:
        # エラー本文にトークンは含まれないが、念のため種類だけ出す
        body = json.loads(error.read() or b"{}")
        raise SystemExit(f"トークン取得に失敗: {error.code} {body.get('error')} {body.get('error_description', '')}")


def authorize():
    """ループバック方式（PKCE 付き）で認可コードを受け取り、トークンを保存する。"""
    info = client()
    verifier = token_bytes.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = token_bytes.token_urlsafe(16)
    result = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if query.get("state", [None])[0] == state:
                result.update({k: v[0] for k, v in query.items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            message = "認可が完了しました。このタブは閉じて構いません。" if "code" in result else "認可できませんでした。"
            self.wfile.write(f"<p>{message}</p>".encode())

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    redirect = f"http://127.0.0.1:{server.server_address[1]}"
    url = AUTH_URL + "?" + urllib.parse.urlencode({
        "client_id": info["client_id"], "redirect_uri": redirect, "response_type": "code", "scope": SCOPES,
        "access_type": "offline", "prompt": "consent", "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    # バックグラウンド実行でも URL がすぐ見えるよう、表示を即時に出し、ファイルにも残す
    (SECRETS / "auth_url.txt").write_text(url, encoding="utf-8")
    print("ブラウザで Google の認可画面を開きます。チャンネルのアカウントで許可してください。", flush=True)
    print(url, flush=True)
    webbrowser.open(url)
    while "code" not in result and "error" not in result:
        server.handle_request()
    server.server_close()
    if "error" in result:
        raise SystemExit(f"認可が拒否された: {result['error']}")

    token = post_form(TOKEN_URL, {
        "client_id": info["client_id"], "client_secret": info["client_secret"], "code": result["code"],
        "code_verifier": verifier, "grant_type": "authorization_code", "redirect_uri": redirect,
    })
    if "refresh_token" not in token:
        raise SystemExit("リフレッシュトークンが返らなかった。もう一度 auth を実行する")
    save_token(token)
    print("認可を保存しました: secrets/token.json")


def save_token(token):
    token["expires_at"] = time.time() + token.get("expires_in", 3600) - 60
    TOKEN_PATH.write_text(json.dumps(token), encoding="utf-8")


def access_token():
    if not TOKEN_PATH.exists():
        raise SystemExit("未認可。先に python tools/upload.py auth を実行する")
    token = json.loads(TOKEN_PATH.read_text(encoding="utf-8"))
    if time.time() < token.get("expires_at", 0):
        return token["access_token"]
    info = client()
    fresh = post_form(TOKEN_URL, {
        "client_id": info["client_id"], "client_secret": info["client_secret"],
        "refresh_token": token["refresh_token"], "grant_type": "refresh_token",
    })
    token.update(fresh)
    save_token(token)
    return token["access_token"]


def api_get(path, params):
    url = f"{API}/{path}?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token()}"})
    with urllib.request.urlopen(request) as res:
        return json.load(res)


def whoami():
    data = api_get("channels", {"part": "snippet", "mine": "true"})
    for item in data.get("items", []):
        print(f"{item['snippet']['title']} ({item['id']})")


def metadata(episode_dir, privacy, publish_at):
    script = json.loads((episode_dir / "script.json").read_text(encoding="utf-8"))
    lines = (episode_dir / "description.txt").read_text(encoding="utf-8").splitlines()
    description = "\n".join(lines[2:]).strip()  # 1 行目はタイトル、2 行目は空行
    status = {
        "privacyStatus": privacy,
        "selfDeclaredMadeForKids": False,
        # 写実的な生成映像・実在人物の改変・動画の主役となる AI 音楽を含まない（channel/profile.md）
        "containsSyntheticMedia": False,
    }
    if publish_at:
        status["publishAt"] = publish_at
    return {
        "snippet": {
            "title": script["title"], "description": description, "tags": TAGS,
            "categoryId": CATEGORY_ENTERTAINMENT, "defaultLanguage": "ja", "defaultAudioLanguage": "ja",
        },
        "status": status,
    }


def upload(episode_dir, privacy, publish_at):
    video = episode_dir / "final.mp4"
    body = json.dumps(metadata(episode_dir, privacy, publish_at)).encode("utf-8")
    size = video.stat().st_size
    start = urllib.request.Request(
        f"{UPLOAD_API}?uploadType=resumable&part=snippet,status", data=body, method="POST",
        headers={"Authorization": f"Bearer {access_token()}", "Content-Type": "application/json; charset=UTF-8",
                 "X-Upload-Content-Type": "video/mp4", "X-Upload-Content-Length": str(size)},
    )
    try:
        with urllib.request.urlopen(start) as res:
            session = res.headers["Location"]
    except urllib.error.HTTPError as error:
        raise SystemExit(f"投稿の開始に失敗: {error.code} {error.read().decode(errors='replace')[:500]}")

    # ショートは数 MB なので 1 回で送る。失敗時は最大 3 回まで送り直す
    for attempt in range(3):
        request = urllib.request.Request(session, data=video.read_bytes(), method="PUT",
                                         headers={"Content-Type": "video/mp4", "Content-Length": str(size)})
        try:
            with urllib.request.urlopen(request) as res:
                result = json.load(res)
                break
        except urllib.error.HTTPError as error:
            if error.code >= 500 and attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            raise SystemExit(f"動画の送信に失敗: {error.code} {error.read().decode(errors='replace')[:500]}")

    record = {
        "video_id": result["id"], "url": f"https://youtube.com/shorts/{result['id']}",
        "privacy_requested": privacy, "publish_at": publish_at,
        "privacy_actual": result.get("status", {}).get("privacyStatus"),
        "uploaded_at": datetime.now(JST).isoformat(timespec="seconds"),
    }
    (episode_dir / "upload.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(record, ensure_ascii=False, indent=2))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    args = sys.argv[1:]
    if not args or args[0] not in ("auth", "whoami", "upload"):
        raise SystemExit(__doc__)
    if args[0] == "auth":
        authorize()
    elif args[0] == "whoami":
        whoami()
    else:
        episode = Path(args[1])
        privacy, publish_at = "private", None
        if "--public" in args:
            privacy = "public"
        if "--at" in args:
            # 予約公開は非公開＋公開日時の指定。日本時間で受け取り UTC にして送る
            local = datetime.fromisoformat(args[args.index("--at") + 1]).replace(tzinfo=JST)
            publish_at = local.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        upload(episode, privacy, publish_at)


if __name__ == "__main__":
    main()
