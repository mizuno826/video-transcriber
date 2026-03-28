import os
import re
import json
import time
import datetime
import asyncio
import ipaddress
import logging
from pathlib import Path
from typing import Optional
from functools import partial
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api.formatters import TextFormatter
from playwright.async_api import async_playwright

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("video-transcriber")
logger.setLevel(logging.INFO)

# ============================================================
# セキュリティ設定
# ============================================================

# 同時WebSocket接続数の上限
MAX_WS_CONNECTIONS = 5
# バッチ処理の1回あたり件数（自動分割の単位）
BATCH_SIZE = 10
# ローカル動画ファイルサイズ上限（10GB - 分割処理するので大きくてOK）
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024 * 1024
# 分割処理の閾値（このサイズ以上なら自動分割、500MB）
CHUNK_THRESHOLD_BYTES = 500 * 1024 * 1024
# 分割チャンクの長さ（秒）: 10分
CHUNK_DURATION_SEC = 600
# WebSocketレート制限（秒あたり最大メッセージ数）
WS_RATE_LIMIT = 5
WS_RATE_WINDOW = 1.0
# 検索クエリの最大長
MAX_QUERY_LENGTH = 200
# URLの最大長
MAX_URL_LENGTH = 2048
# フォルダスキャン時の最大ファイル数
MAX_SCAN_FILES = 1000

# アクセス禁止パス（正規化後の小文字で比較）
BLOCKED_PATH_PREFIXES_WIN = [
    "c:\\windows", "c:\\program files", "c:\\program files (x86)",
    "c:\\programdata", "c:\\$recycle.bin", "c:\\system volume information",
]
BLOCKED_PATH_PREFIXES_UNIX = [
    "/etc", "/var", "/usr", "/bin", "/sbin", "/boot", "/proc", "/sys", "/dev",
    "/root", "/lib", "/lib64",
]

# SSRF防止: 内部ネットワークのCIDR
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# WebSocket接続カウンター
active_ws_connections = 0

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


# ============================================================
# セキュリティミドルウェア
# ============================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])
app.mount("/static", StaticFiles(directory="static"), name="static")


# ============================================================
# バリデーション関数
# ============================================================

def is_blocked_path(path: str) -> bool:
    """システムディレクトリや危険なパスへのアクセスをブロック"""
    try:
        resolved = str(Path(path).resolve()).lower()
    except (OSError, ValueError):
        return True

    if os.name == "nt":
        resolved = resolved.replace("/", "\\")
        for prefix in BLOCKED_PATH_PREFIXES_WIN:
            if resolved.startswith(prefix):
                return True
    else:
        for prefix in BLOCKED_PATH_PREFIXES_UNIX:
            if resolved == prefix or resolved.startswith(prefix + "/"):
                return True
    return False


def validate_path(path: str) -> tuple[bool, str]:
    """パスの安全性を検証。(valid, error_message)を返す"""
    if not path or not path.strip():
        return False, "パスが指定されていません"
    path = path.strip()
    # null byteチェック
    if "\x00" in path:
        return False, "不正なパスです"
    # 長すぎるパスの拒否
    if len(path) > 500:
        return False, "パスが長すぎます"
    # パストラバーサル文字列チェック
    normalized = os.path.normpath(path)
    if ".." in Path(normalized).parts:
        return False, "不正なパスです（相対パス参照は使用できません）"
    # システムディレクトリチェック
    if is_blocked_path(normalized):
        return False, "システムディレクトリへのアクセスは許可されていません"
    return True, ""


def validate_folder_path(folder: str) -> tuple[bool, str]:
    """フォルダパスの安全性を検証"""
    valid, err = validate_path(folder)
    if not valid:
        return False, err
    folder = os.path.normpath(folder.strip())
    if not os.path.isdir(folder):
        return False, f"フォルダが見つかりません: {folder}"
    return True, ""


def validate_save_dir(save_dir: str) -> tuple[bool, str]:
    """保存先ディレクトリの安全性を検証"""
    if not save_dir or not save_dir.strip():
        return True, ""  # 任意項目なので空はOK
    return validate_path(save_dir)


def validate_file_path(filepath: str) -> tuple[bool, str]:
    """ファイルパスの安全性を検証"""
    valid, err = validate_path(filepath)
    if not valid:
        return False, err
    filepath = os.path.normpath(filepath.strip())
    if not os.path.isfile(filepath):
        return False, f"ファイルが見つかりません: {filepath}"
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in VIDEO_EXTENSIONS:
        return False, f"対応していないファイル形式です: {ext}"
    file_size = os.path.getsize(filepath)
    if file_size > MAX_FILE_SIZE_BYTES:
        size_gb = file_size / (1024 * 1024 * 1024)
        return False, f"ファイルサイズが上限（10GB）を超えています: {size_gb:.1f}GB"
    return True, ""


def validate_url(url: str) -> tuple[bool, str]:
    """URLの安全性を検証"""
    if not url or not url.strip():
        return False, "URLを入力してください"
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        return False, "URLが長すぎます"
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "不正なURLです"
    if parsed.scheme not in ("http", "https"):
        return False, "HTTPまたはHTTPSのURLのみ対応しています"
    if not parsed.hostname:
        return False, "不正なURLです"
    # SSRF防止: 内部ネットワークへのアクセスをブロック
    hostname = parsed.hostname
    try:
        addr = ipaddress.ip_address(hostname)
        for network in PRIVATE_NETWORKS:
            if addr in network:
                return False, "内部ネットワークへのアクセスは許可されていません"
    except ValueError:
        # ホスト名がIPアドレスでない場合はDNS解決して確認
        import socket
        try:
            resolved = socket.getaddrinfo(hostname, None)
            for info in resolved:
                try:
                    addr = ipaddress.ip_address(info[4][0])
                    for network in PRIVATE_NETWORKS:
                        if addr in network:
                            return False, "内部ネットワークへのアクセスは許可されていません"
                except ValueError:
                    continue
        except socket.gaierror:
            return False, f"ホスト名を解決できません: {hostname}"
    return True, ""


def validate_youtube_id(video_id: str) -> bool:
    """YouTube動画IDの形式を検証"""
    return bool(re.fullmatch(r'[a-zA-Z0-9_-]{11}', video_id))


def validate_query(query: str) -> tuple[bool, str]:
    """検索クエリを検証"""
    if not query or not query.strip():
        return False, "検索キーワードを入力してください"
    if len(query) > MAX_QUERY_LENGTH:
        return False, f"検索キーワードが長すぎます（最大{MAX_QUERY_LENGTH}文字）"
    return True, ""


def sanitize_error(error: str) -> str:
    """エラーメッセージから内部情報を除去"""
    # ファイルパスやスタックトレースを含む可能性のある情報をサニタイズ
    if not error:
        return error
    # 既知の安全なエラーメッセージはそのまま返す
    safe_prefixes = [
        "字幕が見つかりません", "ダウンロード失敗", "ダウンロードエラー",
        "文字起こしエラー", "保存エラー", "ページ取得エラー",
    ]
    for prefix in safe_prefixes:
        if error.startswith(prefix):
            return error
    # 長すぎるエラーメッセージは切り詰め
    if len(error) > 300:
        return error[:300] + "..."
    return error


# ============================================================
# レート制限
# ============================================================

class RateLimiter:
    def __init__(self, max_calls: int, window: float):
        self.max_calls = max_calls
        self.window = window
        self.timestamps: list[float] = []

    def allow(self) -> bool:
        now = time.monotonic()
        self.timestamps = [t for t in self.timestamps if now - t < self.window]
        if len(self.timestamps) >= self.max_calls:
            return False
        self.timestamps.append(now)
        return True


# ============================================================
# 定数・ユーティリティ
# ============================================================

LANGUAGE_MAP = {
    "af": "アフリカーンス語", "am": "アムハラ語", "ar": "アラビア語",
    "as": "アッサム語", "az": "アゼルバイジャン語", "ba": "バシキール語",
    "be": "ベラルーシ語", "bg": "ブルガリア語", "bn": "ベンガル語",
    "bo": "チベット語", "br": "ブルトン語", "bs": "ボスニア語",
    "ca": "カタルーニャ語", "cs": "チェコ語", "cy": "ウェールズ語",
    "da": "デンマーク語", "de": "ドイツ語", "el": "ギリシャ語",
    "en": "英語", "eo": "エスペラント語", "es": "スペイン語",
    "et": "エストニア語", "eu": "バスク語", "fa": "ペルシア語",
    "fi": "フィンランド語", "fo": "フェロー語", "fr": "フランス語",
    "ga": "アイルランド語", "gl": "ガリシア語", "gu": "グジャラート語",
    "ha": "ハウサ語", "haw": "ハワイ語", "he": "ヘブライ語",
    "hi": "ヒンディー語", "hr": "クロアチア語", "ht": "ハイチ語",
    "hu": "ハンガリー語", "hy": "アルメニア語", "id": "インドネシア語",
    "is": "アイスランド語", "it": "イタリア語", "ja": "日本語",
    "jw": "ジャワ語", "ka": "ジョージア語", "kk": "カザフ語",
    "km": "クメール語", "kn": "カンナダ語", "ko": "韓国語",
    "la": "ラテン語", "lb": "ルクセンブルク語", "ln": "リンガラ語",
    "lo": "ラオ語", "lt": "リトアニア語", "lv": "ラトビア語",
    "mg": "マダガスカル語", "mi": "マオリ語", "mk": "マケドニア語",
    "ml": "マラヤーラム語", "mn": "モンゴル語", "mr": "マラーティー語",
    "ms": "マレー語", "mt": "マルタ語", "my": "ミャンマー語",
    "ne": "ネパール語", "nl": "オランダ語", "nn": "ノルウェー語(ニーノシュク)",
    "no": "ノルウェー語", "oc": "オック語", "pa": "パンジャブ語",
    "pl": "ポーランド語", "ps": "パシュトー語", "pt": "ポルトガル語",
    "ro": "ルーマニア語", "ru": "ロシア語", "sa": "サンスクリット語",
    "sd": "シンド語", "si": "シンハラ語", "sk": "スロバキア語",
    "sl": "スロベニア語", "sn": "ショナ語", "so": "ソマリ語",
    "sq": "アルバニア語", "sr": "セルビア語", "su": "スンダ語",
    "sv": "スウェーデン語", "sw": "スワヒリ語", "ta": "タミル語",
    "te": "テルグ語", "tg": "タジク語", "th": "タイ語",
    "tk": "トルクメン語", "tl": "タガログ語", "tr": "トルコ語",
    "tt": "タタール語", "uk": "ウクライナ語", "ur": "ウルドゥー語",
    "uz": "ウズベク語", "vi": "ベトナム語", "yi": "イディッシュ語",
    "yo": "ヨルバ語", "yue": "広東語", "zh": "中国語",
    "zh-CN": "中国語(簡体)", "zh-TW": "中国語(繁体)",
    "zh-Hans": "中国語(簡体)", "zh-Hant": "中国語(繁体)",
}


def get_language_name_ja(code: str) -> str:
    if not code:
        return "言語不明"
    code = code.strip().lower().replace("_", "-")
    if code in LANGUAGE_MAP:
        return LANGUAGE_MAP[code]
    base = code.split("-")[0]
    if base in LANGUAGE_MAP:
        return LANGUAGE_MAP[base]
    return "言語不明"


def sanitize_filename(name: str) -> str:
    return re.sub(r'[\\/:*?"<>|]', '_', name).strip()


def extract_youtube_ids(html: str, url: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    ids = {}
    patterns = [
        r'(?:youtube\.com/embed/|youtube\.com/watch\?v=|youtu\.be/|youtube\.com/v/)([a-zA-Z0-9_-]{11})',
        r'youtube\.com/embed/([a-zA-Z0-9_-]{11})',
    ]
    for iframe in soup.find_all("iframe"):
        src = iframe.get("src", "") or iframe.get("data-src", "")
        for p in patterns:
            m = re.search(p, src)
            if m:
                ids[m.group(1)] = True
    for text in [str(soup), html]:
        for p in patterns:
            for m in re.finditer(p, text):
                ids[m.group(1)] = True
    return [{"type": "youtube", "video_id": vid} for vid in ids]


def extract_audio_urls(html: str, base_url: str) -> list[dict]:
    from urllib.parse import urljoin
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    audio_exts = ('.mp3', '.m4a', '.wav', '.ogg', '.flac', '.aac', '.wma', '.opus')
    for audio in soup.find_all("audio"):
        src = audio.get("src", "")
        if src:
            urls.add(src)
        for source in audio.find_all("source"):
            s = source.get("src", "")
            if s:
                urls.add(s)
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if any(href.lower().endswith(ext) for ext in audio_exts):
            urls.add(href)
    for p in re.finditer(r'(https?://[^\s"\'<>]+\.(?:mp3|m4a|wav|ogg|flac|aac|wma|opus))', html, re.IGNORECASE):
        urls.add(p.group(1))
    results = []
    for u in urls:
        full = urljoin(base_url, u)
        results.append({"type": "audio", "url": full, "title": os.path.basename(u).rsplit('.', 1)[0] or "audio"})
    return results


def extract_video_urls(html: str, base_url: str) -> list[dict]:
    from urllib.parse import urljoin
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    video_exts = ('.mp4', '.webm', '.mkv', '.avi', '.mov', '.wmv', '.m4v')
    for video in soup.find_all("video"):
        src = video.get("src", "")
        if src:
            urls.add(src)
        for source in video.find_all("source"):
            s = source.get("src", "")
            if s:
                urls.add(s)
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if any(href.lower().endswith(ext) for ext in video_exts):
            urls.add(href)
    for p in re.finditer(r'(https?://[^\s"\'<>]+\.(?:mp4|webm|mkv|avi|mov|wmv|m4v))', html, re.IGNORECASE):
        urls.add(p.group(1))
    results = []
    for u in urls:
        full = urljoin(base_url, u)
        results.append({"type": "video", "url": full, "title": os.path.basename(u).rsplit('.', 1)[0] or "video"})
    return results


def get_youtube_title(video_id: str) -> str:
    if not validate_youtube_id(video_id):
        return f"YouTube_{video_id[:20]}"
    try:
        r = requests.get(
            f"https://www.youtube.com/watch?v={video_id}",
            headers={"Accept-Language": "ja,en"},
            timeout=10,
        )
        m = re.search(r'<title>(.*?)</title>', r.text)
        if m:
            title = m.group(1).replace(" - YouTube", "").strip()
            if title:
                return title
    except Exception:
        pass
    return f"YouTube_{video_id}"


def _try_subtitle_api(video_id: str) -> dict | None:
    """youtube-transcript-api で字幕テキストを取得する。成功時はdict、失敗時はNoneを返す。"""
    try:
        logger.info("[Step1:字幕API] %s: 字幕一覧を取得中...", video_id)
        api = YouTubeTranscriptApi()
        transcript_list = api.list(video_id)

        manual, generated, available = [], [], []
        for t in transcript_list:
            available.append(f"{t.language_code}({'auto' if t.is_generated else 'manual'})")
            (generated if t.is_generated else manual).append(t)
        logger.info("[Step1:字幕API] %s: 利用可能=[%s]", video_id, ", ".join(available))

        preferred = ("ja", "ja-JP", "en")

        def find_by_lang(items):
            for lang in preferred:
                for t in items:
                    if t.language_code == lang or t.language_code.startswith(lang.split("-")[0]):
                        return t
            return items[0] if items else None

        # 優先順位: 手動字幕(ja→en→他) → 自動生成字幕(ja→en→他)
        transcript = find_by_lang(manual) or find_by_lang(generated)
        if transcript is None:
            logger.warning("[Step1:字幕API] %s: 字幕トラックなし", video_id)
            return None

        logger.info("[Step1:字幕API] %s: fetch中 lang=%s auto=%s", video_id, transcript.language_code, transcript.is_generated)
        fetched = transcript.fetch()
        text = TextFormatter().format_transcript(fetched)
        logger.info("[Step1:字幕API] %s: 成功 lang=%s 文字数=%d", video_id, transcript.language_code, len(text))
        src = "自動生成字幕" if transcript.is_generated else "手動字幕"
        return {"text": text, "lang": transcript.language_code, "source": src}
    except Exception as e:
        logger.warning("[Step1:字幕API] %s: %s: %s", video_id, type(e).__name__, str(e)[:150])
        return None


def _try_yt_dlp_subtitles(video_id: str, tmp_dir: str) -> dict | None:
    """yt-dlp で字幕ファイルをダウンロードして解析する。成功時はdict、失敗時はNoneを返す。"""
    import subprocess
    os.makedirs(tmp_dir, exist_ok=True)
    out_path = os.path.join(tmp_dir, video_id)
    yt_url = f"https://www.youtube.com/watch?v={video_id}"
    try:
        logger.info("[Step2:yt-dlp字幕] %s: 字幕ファイルDL中...", video_id)
        subprocess.run(
            ["yt-dlp", "--skip-download",
             "--write-subs", "--write-auto-subs",
             "--sub-langs", "ja,ja-JP,en",
             "--sub-format", "json3",
             "--no-abort-on-error",
             "--socket-timeout", "15",
             "-o", out_path, yt_url],
            capture_output=True, text=True, timeout=30,
        )
    except Exception as e:
        logger.warning("[Step2:yt-dlp字幕] %s: DLエラー: %s", video_id, e)
        return None

    # ダウンロードされた字幕ファイルを探す（優先順: ja > en）
    import json as json_mod
    for lang in ["ja", "ja-JP", "en"]:
        sub_file = f"{out_path}.{lang}.json3"
        if os.path.isfile(sub_file) and os.path.getsize(sub_file) > 100:
            try:
                with open(sub_file, "r", encoding="utf-8") as f:
                    data = json_mod.load(f)
                texts = []
                for ev in data.get("events", []):
                    for seg in ev.get("segs", []):
                        t = seg.get("utf8", "").strip()
                        if t and t != "\n":
                            texts.append(t)
                if texts:
                    combined = " ".join(texts)
                    logger.info("[Step2:yt-dlp字幕] %s: 成功 lang=%s 文字数=%d", video_id, lang, len(combined))
                    return {"text": combined, "lang": lang, "source": "yt-dlp字幕"}
            except Exception as e:
                logger.warning("[Step2:yt-dlp字幕] %s: 解析エラー: %s", video_id, e)
            finally:
                try:
                    os.remove(sub_file)
                except OSError:
                    pass
    # 見つからなかったファイルのクリーンアップ
    for ext in [".ja.json3", ".ja-JP.json3", ".en.json3"]:
        try:
            os.remove(out_path + ext)
        except OSError:
            pass
    logger.warning("[Step2:yt-dlp字幕] %s: 字幕ファイルなし", video_id)
    return None


def get_youtube_transcript(video_id: str, tmp_dir: str = None, allow_whisper: bool = False) -> dict:
    """YouTube字幕取得（3段階フォールバック）:
    1. youtube-transcript-api（数秒）
    2. yt-dlp 字幕ファイルDL（数秒）
    3. yt-dlp 音声DL + Whisper（数分）— allow_whisper=True の場合のみ
    """
    if not validate_youtube_id(video_id):
        return {"title": f"YouTube_{video_id[:20]}", "text": None, "lang": "", "error": "不正な動画IDです"}
    title = get_youtube_title(video_id)
    if tmp_dir is None:
        tmp_dir = os.path.join(os.path.dirname(__file__), "tmp_audio")

    # --- Step 1: youtube-transcript-api ---
    result = _try_subtitle_api(video_id)
    if result:
        return {"title": title, "text": result["text"], "lang": result["lang"],
                "error": None, "source": result["source"]}

    # --- Step 2: yt-dlp 字幕ファイル ---
    result = _try_yt_dlp_subtitles(video_id, tmp_dir)
    if result:
        return {"title": title, "text": result["text"], "lang": result["lang"],
                "error": None, "source": result["source"]}

    # --- Step 3: yt-dlp 音声 + Whisper（明示的に許可された場合のみ） ---
    if not allow_whisper:
        logger.info("[字幕取得失敗] %s: 字幕が取得できませんでした（Whisperは未許可）", video_id)
        return {"title": title, "text": None, "lang": "",
                "error": "字幕を取得できませんでした（YouTubeのIP制限の可能性があります）。音声認識で文字起こしするには「音声認識を許可」をONにしてください",
                "needs_whisper": True}

    logger.info("[Step3:Whisper] %s: 字幕取得不可のため音声文字起こしに切替", video_id)
    yt_url = f"https://www.youtube.com/watch?v={video_id}"
    tr = transcribe_audio(yt_url, tmp_dir)
    if tr["text"]:
        logger.info("[Step3:Whisper] %s: 成功 lang=%s 文字数=%d", video_id, tr.get("lang", ""), len(tr["text"]))
        return {"title": title, "text": tr["text"], "lang": tr.get("lang", ""),
                "error": None, "source": "Whisper音声認識"}
    else:
        logger.warning("[Step3:Whisper] %s: 失敗: %s", video_id, tr.get("error", ""))
        return {"title": title, "text": None, "lang": "",
                "error": f"字幕取得・音声文字起こしともに失敗: {tr.get('error', '不明')}"}


VIDEO_EXTENSIONS = {'.mp4', '.webm', '.mkv', '.avi', '.mov', '.wmv', '.m4v', '.flv', '.ts', '.mts', '.m2ts'}


def get_media_duration(filepath: str) -> Optional[float]:
    """ffprobeで動画の長さ（秒）を取得"""
    import subprocess
    try:
        result = subprocess.run(
            ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", filepath],
            capture_output=True, text=True, timeout=30
        )
        info = json.loads(result.stdout)
        return float(info.get("format", {}).get("duration", 0))
    except Exception:
        return None


def format_file_size(size_bytes: int) -> str:
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.0f}KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f}MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f}GB"


def format_duration_hms(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    if h > 0:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"


def scan_video_files(folder: str) -> list[dict]:
    folder = os.path.normpath(folder)
    results = []
    try:
        entries = sorted(os.listdir(folder))
    except PermissionError:
        return []
    count = 0
    for entry in entries:
        if count >= MAX_SCAN_FILES:
            break
        ext = os.path.splitext(entry)[1].lower()
        if ext in VIDEO_EXTENSIONS:
            full_path = os.path.join(folder, entry)
            if os.path.islink(full_path):
                continue
            if not os.path.isfile(full_path):
                continue
            file_size = os.path.getsize(full_path)
            duration = get_media_duration(full_path)
            item = {
                "filename": entry,
                "path": full_path,
                "title": os.path.splitext(entry)[0],
                "size_bytes": file_size,
                "size_display": format_file_size(file_size),
                "needs_split": file_size > CHUNK_THRESHOLD_BYTES,
            }
            if duration:
                item["duration"] = duration
                item["duration_display"] = format_duration_hms(duration)
            results.append(item)
            count += 1
    return results


def split_media_to_chunks(filepath: str, chunk_dir: str, chunk_sec: int = CHUNK_DURATION_SEC) -> list[str]:
    """ffmpegで動画を一定時間ごとのチャンクに分割し、チャンクファイルのリストを返す"""
    import subprocess
    os.makedirs(chunk_dir, exist_ok=True)
    base = sanitize_filename(os.path.splitext(os.path.basename(filepath))[0])
    pattern = os.path.join(chunk_dir, f"{base}_chunk_%03d.wav")
    try:
        subprocess.run(
            ["ffmpeg", "-i", filepath, "-vn", "-acodec", "pcm_s16le", "-ar", "16000", "-ac", "1",
             "-f", "segment", "-segment_time", str(chunk_sec), pattern],
            capture_output=True, text=True, timeout=600
        )
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []
    chunks = sorted([
        os.path.join(chunk_dir, f)
        for f in os.listdir(chunk_dir)
        if f.startswith(f"{base}_chunk_") and f.endswith(".wav")
    ])
    return chunks


def transcribe_single_chunk(filepath: str) -> dict:
    """1つの音声ファイルを文字起こし（分割チャンク用）"""
    try:
        from faster_whisper import WhisperModel
        model = WhisperModel("base", device="cpu", compute_type="int8")
        segments, info = model.transcribe(filepath, beam_size=5)
        text = " ".join(seg.text for seg in segments)
        return {"text": text.strip(), "lang": info.language, "error": None}
    except Exception as e:
        logger.warning("Chunk transcribe error for %s: %s", filepath, e)
        return {"text": None, "lang": "", "error": f"チャンク文字起こしエラー"}


def transcribe_local_file(filepath: str) -> dict:
    """ローカルファイルの文字起こし。大きいファイルは自動分割。"""
    file_size = os.path.getsize(filepath)

    # 小さいファイルはそのまま処理
    if file_size <= CHUNK_THRESHOLD_BYTES:
        try:
            from faster_whisper import WhisperModel
            model = WhisperModel("base", device="cpu", compute_type="int8")
            segments, info = model.transcribe(filepath, beam_size=5)
            text = " ".join(seg.text for seg in segments)
            lang = info.language
            return {"text": text.strip(), "lang": lang, "error": None}
        except Exception as e:
            logger.warning("Local transcribe error for %s: %s", filepath, e)
            size_str = format_file_size(file_size)
            return {"text": None, "lang": "", "error": f"文字起こしエラー: 処理に失敗しました（ファイルサイズ: {size_str}）"}

    # 大きいファイルは分割処理
    tmp_dir = os.path.join(os.path.dirname(__file__), "tmp_audio")
    chunk_dir = os.path.join(tmp_dir, f"chunks_{os.getpid()}_{int(time.time())}")
    try:
        chunks = split_media_to_chunks(filepath, chunk_dir)
        if not chunks:
            size_str = format_file_size(file_size)
            return {
                "text": None, "lang": "",
                "error": f"分割エラー: ffmpegによるファイル分割に失敗しました（ファイルサイズ: {size_str}）。ffmpegがインストールされているか確認してください。"
            }

        all_texts = []
        lang = ""
        chunk_errors = []
        for i, chunk_path in enumerate(chunks):
            result = transcribe_single_chunk(chunk_path)
            if result["text"]:
                all_texts.append(result["text"])
                if not lang and result["lang"]:
                    lang = result["lang"]
            else:
                chunk_errors.append(f"チャンク{i+1}/{len(chunks)}")

        if not all_texts:
            return {"text": None, "lang": "", "error": f"文字起こしエラー: 全{len(chunks)}チャンクの処理に失敗しました"}

        combined = " ".join(all_texts)
        error = None
        if chunk_errors:
            error = f"一部チャンクでエラー（{', '.join(chunk_errors)}）。残りは正常に処理されました。"
        return {
            "text": combined, "lang": lang, "error": error,
            "chunks_total": len(chunks),
            "chunks_success": len(all_texts),
        }
    finally:
        # チャンクファイルを削除
        try:
            import shutil
            shutil.rmtree(chunk_dir, ignore_errors=True)
        except Exception:
            pass


def transcribe_audio(url: str, tmp_dir: str) -> dict:
    import subprocess
    os.makedirs(tmp_dir, exist_ok=True)
    out_template = os.path.join(tmp_dir, "%(title)s.%(ext)s")
    try:
        result = subprocess.run(
            ["yt-dlp", "--no-playlist", "-x", "--audio-format", "wav",
             "--socket-timeout", "30",
             "-o", out_template, "--print", "after_move:filepath", url],
            capture_output=True, text=True, timeout=120
        )
        filepath = result.stdout.strip().split('\n')[-1]
        if not os.path.isfile(filepath):
            wavs = [f for f in os.listdir(tmp_dir) if f.endswith('.wav')]
            if wavs:
                filepath = os.path.join(tmp_dir, wavs[0])
            else:
                all_files = os.listdir(tmp_dir)
                if all_files:
                    filepath = os.path.join(tmp_dir, all_files[0])
                else:
                    return {"text": None, "lang": "", "error": "ダウンロード失敗: 音声ファイルを取得できませんでした"}
    except subprocess.TimeoutExpired:
        return {"text": None, "lang": "", "error": "ダウンロードエラー: タイムアウトしました（2分超過）"}
    except Exception as e:
        logger.warning("Audio download error: %s", e)
        return {"text": None, "lang": "", "error": "ダウンロードエラー: 音声の取得に失敗しました"}

    try:
        file_size = os.path.getsize(filepath)
        # 大きいファイルは分割処理
        if file_size > CHUNK_THRESHOLD_BYTES:
            chunk_dir = os.path.join(tmp_dir, f"chunks_{os.getpid()}_{int(time.time())}")
            try:
                chunks = split_media_to_chunks(filepath, chunk_dir)
                if not chunks:
                    return {"text": None, "lang": "", "error": f"分割エラー: ダウンロードした音声（{format_file_size(file_size)}）の分割に失敗しました"}
                all_texts = []
                lang = ""
                for i, chunk_path in enumerate(chunks):
                    r = transcribe_single_chunk(chunk_path)
                    if r["text"]:
                        all_texts.append(r["text"])
                        if not lang and r["lang"]:
                            lang = r["lang"]
                if not all_texts:
                    return {"text": None, "lang": "", "error": f"文字起こしエラー: 全{len(chunks)}チャンクの処理に失敗しました"}
                return {"text": " ".join(all_texts), "lang": lang, "error": None,
                        "chunks_total": len(chunks), "chunks_success": len(all_texts)}
            finally:
                import shutil
                shutil.rmtree(chunk_dir, ignore_errors=True)
        else:
            from faster_whisper import WhisperModel
            model = WhisperModel("base", device="cpu", compute_type="int8")
            segments, info = model.transcribe(filepath, beam_size=5)
            text = " ".join(seg.text for seg in segments)
            return {"text": text.strip(), "lang": info.language, "error": None}
    except Exception as e:
        logger.warning("Audio transcribe error: %s", e)
        return {"text": None, "lang": "", "error": "文字起こしエラー: 処理に失敗しました"}
    finally:
        try:
            os.remove(filepath)
        except Exception:
            pass


def save_result_file(result: dict, save_dir: str) -> str:
    save_dir = os.path.normpath(save_dir)
    os.makedirs(save_dir, exist_ok=True)
    now = datetime.datetime.now()
    title = sanitize_filename(result.get("title", "untitled"))
    if not title:
        title = "untitled"
    lang_ja = get_language_name_ja(result.get("lang", ""))
    date_str = now.strftime("%Y%m%d")
    filename = f"{title}_{lang_ja}_{date_str}.txt"
    if len(filename) > 200:
        filename = filename[:196] + ".txt"
    filepath = os.path.join(save_dir, filename)

    url = result.get("url", "")
    content = f"""=== {result.get('title', 'untitled')} ===
取得日時：{now.strftime('%Y/%m/%d %H:%M')}
URL：{url}
言語：{lang_ja}（自動検出）

【文字起こし全文】
{result.get('text', '')}

---
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath


def search_youtube(query: str, max_results: int = 20) -> list[dict]:
    import subprocess
    try:
        result = subprocess.run(
            ["yt-dlp", f"ytsearch{max_results}:{query}",
             "--flat-playlist", "--dump-json", "--no-download"],
            capture_output=True, text=True, timeout=60
        )
        items = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                info = json.loads(line)
                items.append({
                    "video_id": info.get("id", ""),
                    "title": info.get("title", "不明"),
                    "url": info.get("url", f"https://www.youtube.com/watch?v={info.get('id', '')}"),
                    "duration": info.get("duration"),
                    "channel": info.get("channel", info.get("uploader", "")),
                    "thumbnail": info.get("thumbnail", info.get("thumbnails", [{}])[-1].get("url", "") if info.get("thumbnails") else ""),
                })
            except json.JSONDecodeError:
                continue
        return items
    except Exception as e:
        logger.warning("YouTube search error: %s", e)
        return []


# 1件あたりの処理タイムアウト（秒）— Whisperフォールバック時は数分かかるため余裕を持つ
PER_ITEM_TIMEOUT = 600


async def run_with_timeout(func, *args, timeout=PER_ITEM_TIMEOUT):
    """run_in_executor にタイムアウトを付けて実行する"""
    loop = asyncio.get_event_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(None, func),
        timeout=timeout,
    )


# ============================================================
# ルート
# ============================================================

@app.get("/")
async def index():
    return FileResponse("static/index.html")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    global active_ws_connections

    # 同時接続数チェック
    if active_ws_connections >= MAX_WS_CONNECTIONS:
        await websocket.close(code=1013, reason="サーバーが混雑しています。しばらくしてから再接続してください。")
        return

    await websocket.accept()
    active_ws_connections += 1
    rate_limiter = RateLimiter(WS_RATE_LIMIT, WS_RATE_WINDOW)

    try:
        while True:
            data = await websocket.receive_json()

            # レート制限チェック
            if not rate_limiter.allow():
                await websocket.send_json({"type": "error", "message": "リクエストが多すぎます。少し待ってから再試行してください。"})
                continue

            action = data.get("action")

            if action == "search":
                query = data.get("query", "").strip()
                valid, err = validate_query(query)
                if not valid:
                    await websocket.send_json({"type": "error", "message": err})
                    continue
                await websocket.send_json({"type": "status", "message": f"「{query}」を検索中..."})
                loop = asyncio.get_event_loop()
                results = await loop.run_in_executor(None, search_youtube, query)
                if not results:
                    await websocket.send_json({"type": "error", "message": "検索結果が見つかりませんでした"})
                    continue
                await websocket.send_json({"type": "search_results", "data": results})

            elif action == "transcribe_selected":
                items = data.get("items", [])
                save_dir = data.get("save_dir", "").strip()
                allow_whisper = data.get("allow_whisper", False)
                if not items:
                    await websocket.send_json({"type": "error", "message": "文字起こしする項目を選択してください"})
                    continue
                valid, err = validate_save_dir(save_dir)
                if not valid:
                    await websocket.send_json({"type": "error", "message": err})
                    continue
                total = len(items)
                # バッチ自動分割
                batch_count = (total + BATCH_SIZE - 1) // BATCH_SIZE
                if batch_count > 1:
                    await websocket.send_json({"type": "status", "message": f"{total}件を{batch_count}バッチに分割して順番に処理します（1バッチ={BATCH_SIZE}件）"})
                results = []
                saved_count = 0
                tmp_dir = os.path.join(os.path.dirname(__file__), "tmp_audio")
                for i, item in enumerate(items):
                    if i > 0 and item.get("type", "youtube") == "youtube":
                        await asyncio.sleep(2.0)
                    batch_num = i // BATCH_SIZE + 1
                    batch_label = f"[{batch_num}/{batch_count}] " if batch_count > 1 else ""
                    progress_msg = f"{batch_label}{i+1}/{total}件 処理中..."
                    await websocket.send_json({"type": "progress", "current": i+1, "total": total, "message": progress_msg})
                    vid = item.get("video_id", "")
                    title = item.get("title", "不明")
                    item_type = item.get("type", "youtube")
                    result = None
                    try:
                        if item_type == "youtube" and vid:
                            if not validate_youtube_id(vid):
                                result = {"index": i, "type": "youtube", "title": title, "url": "", "lang": "", "lang_ja": "", "text": None, "error": "不正な動画IDです"}
                            else:
                                yt_url = f"https://www.youtube.com/watch?v={vid}"
                                tr = await run_with_timeout(partial(get_youtube_transcript, vid, tmp_dir=tmp_dir, allow_whisper=allow_whisper))
                                result = {
                                    "index": i, "type": "youtube",
                                    "title": tr["title"], "url": yt_url,
                                    "lang": tr["lang"], "lang_ja": get_language_name_ja(tr["lang"]),
                                    "text": tr["text"], "error": tr["error"], "source": tr.get("source", ""),
                                }
                        else:
                            media_url = item.get("url", "")
                            url_valid, url_err = validate_url(media_url)
                            if not url_valid:
                                result = {"index": i, "type": item_type, "title": title, "url": media_url, "lang": "", "lang_ja": "", "text": None, "error": url_err}
                            else:
                                tr = await run_with_timeout(partial(transcribe_audio, media_url, tmp_dir))
                                result = {
                                    "index": i, "type": item_type,
                                    "title": title, "url": media_url,
                                    "lang": tr["lang"], "lang_ja": get_language_name_ja(tr.get("lang", "")),
                                    "text": tr["text"], "error": tr["error"], "source": tr.get("source", ""),
                                }
                    except asyncio.TimeoutError:
                        logger.warning("Timeout processing item %d: %s", i, title)
                        result = {"index": i, "type": item_type, "title": title, "url": item.get("url", ""), "lang": "", "lang_ja": "", "text": None, "error": f"タイムアウト: 処理が{PER_ITEM_TIMEOUT}秒以内に完了しませんでした"}
                    except Exception as e:
                        logger.error("Unexpected error processing item %d: %s", i, e)
                        result = {"index": i, "type": item_type, "title": title, "url": item.get("url", ""), "lang": "", "lang_ja": "", "text": None, "error": "予期しないエラーが発生しました"}
                    if result and result.get("chunks_total"):
                        result["chunk_info"] = f"分割処理: {result.get('chunks_success', 0)}/{result['chunks_total']}チャンク成功"
                    if result and result.get("text") and save_dir:
                        try:
                            saved_path = await run_with_timeout(partial(save_result_file, result, save_dir), timeout=30)
                            result["saved_path"] = saved_path
                            saved_count += 1
                        except Exception as e:
                            logger.warning("Save error: %s", e)
                            result["save_error"] = "保存エラー: ファイルの保存に失敗しました"
                    results.append(result)
                    await websocket.send_json({"type": "result", "data": result})
                summary = {"type": "complete", "total": total, "success": sum(1 for r in results if r.get("text")),
                           "failed": sum(1 for r in results if not r.get("text"))}
                if save_dir and saved_count > 0:
                    summary["saved_count"] = saved_count
                    summary["save_dir"] = save_dir
                await websocket.send_json(summary)

            elif action == "scan_folder":
                folder = data.get("folder", "").strip()
                valid, err = validate_folder_path(folder)
                if not valid:
                    await websocket.send_json({"type": "error", "message": err})
                    continue
                folder = os.path.normpath(folder)
                loop = asyncio.get_event_loop()
                files = await loop.run_in_executor(None, scan_video_files, folder)
                if not files:
                    await websocket.send_json({"type": "error", "message": "動画ファイルが見つかりませんでした"})
                    continue
                await websocket.send_json({"type": "folder_scan_results", "data": files, "folder": folder})

            elif action == "transcribe_folder":
                items = data.get("items", [])
                save_dir = data.get("save_dir", "").strip()
                if not items:
                    await websocket.send_json({"type": "error", "message": "文字起こしするファイルを選択してください"})
                    continue
                valid, err = validate_save_dir(save_dir)
                if not valid:
                    await websocket.send_json({"type": "error", "message": err})
                    continue
                total = len(items)
                batch_count = (total + BATCH_SIZE - 1) // BATCH_SIZE
                if batch_count > 1:
                    await websocket.send_json({"type": "status", "message": f"{total}件を{batch_count}バッチに分割して順番に処理します（1バッチ={BATCH_SIZE}件）"})
                results = []
                saved_count = 0
                for i, item in enumerate(items):
                    filepath = item.get("path", "")
                    title = item.get("title", os.path.basename(filepath))
                    filename = item.get("filename", os.path.basename(filepath))
                    size_display = item.get("size_display", "")
                    needs_split = item.get("needs_split", False)
                    # ファイルパスのバリデーション
                    file_valid, file_err = validate_file_path(filepath)
                    if not file_valid:
                        result = {
                            "index": i, "type": "local_video",
                            "title": title, "url": filepath,
                            "lang": "", "lang_ja": "",
                            "text": None, "error": file_err,
                        }
                        results.append(result)
                        await websocket.send_json({"type": "result", "data": result})
                        continue
                    batch_num = i // BATCH_SIZE + 1
                    batch_label = f"[バッチ{batch_num}/{batch_count}] " if batch_count > 1 else ""
                    split_label = " (自動分割処理)" if needs_split else ""
                    progress_msg = f"{batch_label}{i+1}件目/{total}件を処理中: {filename} ({size_display}){split_label}"
                    await websocket.send_json({"type": "progress", "current": i+1, "total": total, "message": progress_msg})
                    loop = asyncio.get_event_loop()
                    tr = await loop.run_in_executor(None, transcribe_local_file, filepath)
                    result = {
                        "index": i, "type": "local_video",
                        "title": title, "url": filepath,
                        "lang": tr["lang"], "lang_ja": get_language_name_ja(tr.get("lang", "")),
                        "text": tr["text"], "error": tr["error"],
                    }
                    if tr.get("chunks_total"):
                        result["chunk_info"] = f"分割処理: {tr.get('chunks_success', 0)}/{tr['chunks_total']}チャンク成功"
                    if result["text"] and save_dir:
                        try:
                            saved_path = await asyncio.get_event_loop().run_in_executor(
                                None, save_result_file, result, save_dir
                            )
                            result["saved_path"] = saved_path
                            saved_count += 1
                        except Exception as e:
                            logger.warning("Save error: %s", e)
                            result["save_error"] = "保存エラー: ファイルの保存に失敗しました"
                    results.append(result)
                    await websocket.send_json({"type": "result", "data": result})
                summary = {"type": "complete", "total": total,
                           "success": sum(1 for r in results if r.get("text")),
                           "failed": sum(1 for r in results if not r.get("text"))}
                if save_dir and saved_count > 0:
                    summary["saved_count"] = saved_count
                    summary["save_dir"] = save_dir
                await websocket.send_json(summary)

            elif action == "transcribe_url":
                urls = data.get("urls", [])
                save_dir = data.get("save_dir", "").strip()
                allow_whisper = data.get("allow_whisper", False)
                valid, err = validate_save_dir(save_dir)
                if not valid:
                    await websocket.send_json({"type": "error", "message": err})
                    continue
                if not urls or not isinstance(urls, list):
                    await websocket.send_json({"type": "error", "message": "URLが指定されていません"})
                    continue
                # 各URLをYouTube動画IDまたはメディアURLとして分類
                items = []
                for u in urls:
                    u = u.strip()
                    if not u:
                        continue
                    vid = None
                    m = re.search(r'(?:youtube\.com/watch\?v=|youtu\.be/|youtube\.com/embed/|youtube\.com/v/)([a-zA-Z0-9_-]{11})', u)
                    if m:
                        vid = m.group(1)
                    if vid:
                        items.append({"type": "youtube", "video_id": vid, "title": "", "url": u})
                    else:
                        items.append({"type": "media", "url": u, "title": os.path.basename(urlparse(u).path) or "media"})
                if not items:
                    await websocket.send_json({"type": "error", "message": "有効なURLがありませ���"})
                    continue
                total = len(items)
                results = []
                saved_count = 0
                tmp_dir = os.path.join(os.path.dirname(__file__), "tmp_audio")
                for i, item in enumerate(items):
                    if i > 0 and item["type"] == "youtube":
                        await asyncio.sleep(2.0)
                    await websocket.send_json({"type": "progress", "current": i+1, "total": total, "message": f"{i+1}/{total}件 処理中..."})
                    result = None
                    try:
                        if item["type"] == "youtube":
                            tr = await run_with_timeout(partial(get_youtube_transcript, item["video_id"], tmp_dir=tmp_dir, allow_whisper=allow_whisper))
                            result = {
                                "index": i, "type": "youtube",
                                "title": tr["title"], "url": item["url"],
                                "lang": tr["lang"], "lang_ja": get_language_name_ja(tr["lang"]),
                                "text": tr["text"], "error": tr["error"], "source": tr.get("source", ""),
                            }
                        else:
                            media_url = item["url"]
                            url_valid, url_err = validate_url(media_url)
                            if not url_valid:
                                result = {"index": i, "type": "media", "title": item.get("title", "media"), "url": media_url, "lang": "", "lang_ja": "", "text": None, "error": url_err}
                            else:
                                tr = await run_with_timeout(partial(transcribe_audio, media_url, tmp_dir))
                                result = {
                                    "index": i, "type": item.get("type", "media"),
                                    "title": item.get("title", "media"), "url": media_url,
                                    "lang": tr["lang"], "lang_ja": get_language_name_ja(tr.get("lang", "")),
                                    "text": tr["text"], "error": tr["error"], "source": tr.get("source", ""),
                                }
                    except asyncio.TimeoutError:
                        logger.warning("Timeout processing URL item %d", i)
                        result = {"index": i, "type": item.get("type", "media"), "title": item.get("title", ""), "url": item.get("url", ""), "lang": "", "lang_ja": "", "text": None, "error": f"タイムアウト: 処理が{PER_ITEM_TIMEOUT}秒以内に完了しませんでした"}
                    except Exception as e:
                        logger.error("Unexpected error processing URL item %d: %s", i, e)
                        result = {"index": i, "type": item.get("type", "media"), "title": item.get("title", ""), "url": item.get("url", ""), "lang": "", "lang_ja": "", "text": None, "error": "予期しないエラーが発生しました"}
                    if result and result.get("text") and save_dir:
                        try:
                            saved_path = await run_with_timeout(partial(save_result_file, result, save_dir), timeout=30)
                            result["saved_path"] = saved_path
                            saved_count += 1
                        except Exception as e:
                            logger.warning("Save error: %s", e)
                            result["save_error"] = "保存エラー: ファイルの保存に失敗しました"
                    results.append(result)
                    await websocket.send_json({"type": "result", "data": result})
                summary = {"type": "complete", "total": total,
                           "success": sum(1 for r in results if r.get("text")),
                           "failed": sum(1 for r in results if not r.get("text"))}
                if save_dir and saved_count > 0:
                    summary["saved_count"] = saved_count
                    summary["save_dir"] = save_dir
                await websocket.send_json(summary)

            elif action == "analyze":
                url = data.get("url", "").strip()
                save_dir = data.get("save_dir", "").strip()
                allow_whisper = data.get("allow_whisper", False)

                url_valid, url_err = validate_url(url)
                if not url_valid:
                    await websocket.send_json({"type": "error", "message": url_err})
                    continue
                valid, err = validate_save_dir(save_dir)
                if not valid:
                    await websocket.send_json({"type": "error", "message": err})
                    continue

                await websocket.send_json({"type": "status", "message": "ページを取得中（ブラウザでレンダリング中）..."})

                try:
                    async with async_playwright() as p:
                        browser = await p.chromium.launch(headless=True)
                        page = await browser.new_page()
                        await page.goto(url, wait_until="networkidle", timeout=60000)
                        await page.wait_for_timeout(3000)
                        html = await page.content()
                        await browser.close()
                except Exception as e:
                    logger.warning("Page fetch error for %s: %s", url, e)
                    await websocket.send_json({"type": "error", "message": "ページ取得エラー: ページの読み込みに失敗しました"})
                    continue

                youtube_items = extract_youtube_ids(html, url)
                audio_items = extract_audio_urls(html, url)
                video_items = extract_video_urls(html, url)
                all_items = youtube_items + video_items + audio_items
                total = len(all_items)

                if total == 0:
                    await websocket.send_json({"type": "error", "message": "YouTube動画・動画ファイル・音声ファイルが見つかりませんでした"})
                    continue

                batch_count = (total + BATCH_SIZE - 1) // BATCH_SIZE
                if batch_count > 1:
                    await websocket.send_json({"type": "status", "message": f"{total}件のコンテンツを検出しました。{batch_count}バッチに分割して順番に処理します"})
                else:
                    await websocket.send_json({"type": "status", "message": f"{total}件のコンテンツを検出しました"})

                results = []
                saved_count = 0
                tmp_dir = os.path.join(os.path.dirname(__file__), "tmp_audio")

                for i, item in enumerate(all_items):
                    if i > 0 and item["type"] == "youtube":
                        await asyncio.sleep(2.0)
                    batch_num = i // BATCH_SIZE + 1
                    batch_label = f"[{batch_num}/{batch_count}] " if batch_count > 1 else ""
                    progress_msg = f"{batch_label}{i+1}/{total}件 処理中..."
                    await websocket.send_json({"type": "progress", "current": i+1, "total": total, "message": progress_msg})

                    result = None
                    try:
                        if item["type"] == "youtube":
                            vid = item["video_id"]
                            yt_url = f"https://www.youtube.com/watch?v={vid}"
                            tr = await run_with_timeout(partial(get_youtube_transcript, vid, tmp_dir=tmp_dir, allow_whisper=allow_whisper))
                            result = {
                                "index": i, "type": "youtube",
                                "title": tr["title"], "url": yt_url,
                                "lang": tr["lang"], "lang_ja": get_language_name_ja(tr["lang"]),
                                "text": tr["text"], "error": tr["error"], "source": tr.get("source", ""),
                            }
                        elif item["type"] in ("audio", "video"):
                            media_url = item["url"]
                            media_title = item.get("title", item["type"])
                            tr = await run_with_timeout(partial(transcribe_audio, media_url, tmp_dir))
                            result = {
                                "index": i, "type": item["type"],
                                "title": media_title, "url": media_url,
                                "lang": tr["lang"], "lang_ja": get_language_name_ja(tr.get("lang", "")),
                                "text": tr["text"], "error": tr["error"], "source": tr.get("source", ""),
                            }
                    except asyncio.TimeoutError:
                        logger.warning("Timeout processing analyze item %d", i)
                        result = {"index": i, "type": item.get("type", ""), "title": item.get("title", ""), "url": item.get("url", ""), "lang": "", "lang_ja": "", "text": None, "error": f"タイムアウト: 処理が{PER_ITEM_TIMEOUT}秒以内に完了しませんでした"}
                    except Exception as e:
                        logger.error("Unexpected error in analyze item %d: %s", i, e)
                        result = {"index": i, "type": item.get("type", ""), "title": item.get("title", ""), "url": item.get("url", ""), "lang": "", "lang_ja": "", "text": None, "error": "予期しないエラーが発生しました"}

                    if result is None:
                        result = {"index": i, "type": item.get("type", ""), "title": item.get("title", ""), "url": item.get("url", ""), "lang": "", "lang_ja": "", "text": None, "error": "不明なエラー"}

                    if result.get("text") and save_dir:
                        try:
                            saved_path = await run_with_timeout(partial(save_result_file, result, save_dir), timeout=30)
                            result["saved_path"] = saved_path
                            saved_count += 1
                        except Exception as e:
                            logger.warning("Save error: %s", e)
                            result["save_error"] = "保存エラー: ファイルの保存に失敗しました"

                    results.append(result)
                    await websocket.send_json({"type": "result", "data": result})

                summary = {"type": "complete", "total": total,
                           "success": sum(1 for r in results if r.get("text")),
                           "failed": sum(1 for r in results if not r.get("text"))}
                if save_dir and saved_count > 0:
                    summary["saved_count"] = saved_count
                    summary["save_dir"] = save_dir
                await websocket.send_json(summary)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WebSocket error: %s", e)
        try:
            await websocket.send_json({"type": "error", "message": "サーバーエラーが発生しました"})
        except Exception:
            pass
    finally:
        active_ws_connections -= 1
