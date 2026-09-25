@echo off
echo ========================================================
echo   Starting PhishingGuard FastAPI Backend Server...
echo ========================================================
cd /d "%~dp0backend"
if exist "venv\Scripts\python.exe" (
    echo Starting server on http://127.0.0.1:8000 ...
    ".\venv\Scripts\python.exe" -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
) else (
    echo [ERROR] Virtual environment not found in backend\venv.
    pause
)
