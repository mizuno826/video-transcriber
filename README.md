# 動画文字起こしツール

WebページのURL、YouTube検索、ローカルフォルダの動画ファイルから文字起こしテキストを取得するWebアプリです。

## 機能

- **URL解析** - WebページからYouTube動画・音声・動画ファイルを自動検出して文字起こし
- **キーワード検索** - YouTubeを検索して選択した動画を文字起こし
- **フォルダ指定** - ローカルPC内の動画ファイルを一括で文字起こし
- 結果のTXTファイル保存（保存先指定可能）
- ブラウザ上でのテキスト表示・ダウンロード

## セットアップ

### 方法1: Python（直接実行）

**必要な環境:**
- Python 3.9以上
- FFmpeg

**Windowsの場合:**
```
winget install FFmpeg
```

**インストール:**
```bash
pip install -r requirements.txt
playwright install chromium
```

> **注意:** `faster-whisper` は初回実行時にモデルファイル（約150MB）を自動ダウンロードします。

**起動:**
```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

Windowsでは `start.bat` をダブルクリックでも起動できます。

ブラウザで http://localhost:8000 にアクセスしてください。

### 方法2: Docker

```bash
docker compose up --build
```

フォルダ指定機能でホスト側のフォルダにアクセスするには、環境変数でマウントパスを指定します：

```bash
# Windows (PowerShell)
$env:VIDEO_DIR="C:\Users\Owner\Videos"; $env:OUTPUT_DIR="C:\Users\Owner\Documents\transcripts"; docker compose up --build

# Linux / macOS
VIDEO_DIR=~/Videos OUTPUT_DIR=~/transcripts docker compose up --build
```

コンテナ内では `/videos`（動画フォルダ）と `/output`（保存先）としてアクセスできます。

## 使い方

### URL解析
1. YouTube動画や音声ファイルが埋め込まれたWebページのURLを入力
2. 保存先フォルダ（任意）を指定
3. 「解析開始」をクリック

### キーワード検索
1. 検索キーワードを入力してYouTube動画を検索
2. 文字起こししたい動画を選択
3. 「選択した動画を文字起こし」をクリック

### フォルダ指定
1. 動画が入っているフォルダのパスを入力
2. 「スキャン」で動画ファイルを検出
3. 文字起こししたいファイルを選択
4. 保存先フォルダ（任意）を指定
5. 「選択した動画を文字起こし」をクリック

対応動画形式: mp4, webm, mkv, avi, mov, wmv, m4v, flv, ts, mts, m2ts

## 保存ファイル

- ファイル名: `動画タイトル_言語名_YYYYMMDD.txt`
- 例: `Introduction_to_Yoga_英語_20260327.txt`

## 技術スタック

| 機能 | ライブラリ |
|------|-----------|
| バックエンド | FastAPI + uvicorn |
| YouTube字幕取得 | youtube-transcript-api |
| 音声ダウンロード | yt-dlp |
| 音声文字起こし | faster-whisper（ローカル動作） |
| ページ解析 | Playwright + BeautifulSoup4 |

## 注意事項

- 外部APIキーは不要です（完全無料で動作します）
- 音声の文字起こしにはCPUを使用するため、長い動画の処理には時間がかかります
- YouTube字幕が無効な動画はスキップされます
- 本ツールは個人利用を目的としています

## ライセンス

MIT License
