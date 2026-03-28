@echo off
echo 動画文字起こしツールを起動中...
echo ブラウザで http://localhost:8000 にアクセスしてください
echo 終了するにはこのウィンドウを閉じてください
echo.
cd /d "%~dp0"
start http://localhost:8000
timeout /t 2 /nobreak >nul
python -m uvicorn main:app --host 0.0.0.0 --port 8000
pause
