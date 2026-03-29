@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "PATH=%PATH%;C:\Program Files\nodejs"

echo ========================================
echo   動画文字起こしツール
echo ========================================
echo.

REM --- Python チェック ---
python --version >nul 2>&1
if errorlevel 1 (
    echo [エラー] Python が見つかりません。
    echo https://www.python.org/downloads/ からインストールしてください。
    pause
    exit /b 1
)

REM --- FFmpeg チェック ---
ffmpeg -version >nul 2>&1
if errorlevel 1 (
    echo [セットアップ] FFmpeg をインストールしています...
    winget install FFmpeg --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo [エラー] FFmpeg のインストールに失敗しました。
        echo 手動でインストールしてください: winget install FFmpeg
        pause
        exit /b 1
    )
)

REM --- pip パッケージチェック ---
python -c "import fastapi" >nul 2>&1
if errorlevel 1 (
    echo [セットアップ] 必要なパッケージをインストールしています...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [エラー] パッケージのインストールに失敗しました。
        pause
        exit /b 1
    )
)

REM --- Playwright チェック ---
python -c "from playwright.sync_api import sync_playwright" >nul 2>&1
if errorlevel 1 (
    echo [セットアップ] Playwright をインストールしています...
    pip install playwright
    playwright install chromium
) else (
    if not exist "%LOCALAPPDATA%\ms-playwright" (
        echo [セットアップ] Chromium をインストールしています...
        playwright install chromium
    )
)

echo.
echo 起動中... ブラウザが自動で開きます。
echo 終了するにはこのウィンドウを閉じてください。
echo.
start http://localhost:8000
timeout /t 2 /nobreak >nul
python -m uvicorn main:app --host 0.0.0.0 --port 8000
pause
