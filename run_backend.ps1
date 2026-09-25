Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  Starting PhishingGuard FastAPI Backend Server...    " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$backendDir = Join-Path $PSScriptRoot "backend"
Set-Location $backendDir

if (Test-Path ".\venv\Scripts\python.exe") {
    Write-Host "Starting server on http://127.0.0.1:8000 ..." -ForegroundColor Green
    & ".\venv\Scripts\python.exe" -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
} else {
    Write-Host "[ERROR] Virtual environment not found in backend\venv." -ForegroundColor Red
}
