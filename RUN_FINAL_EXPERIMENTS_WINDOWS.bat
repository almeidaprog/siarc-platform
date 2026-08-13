@echo off
setlocal
if not exist .env copy .env.example .env

echo [1/4] Starting PostgreSQL, SIARC API and n8n...
docker compose up -d --build
if errorlevel 1 goto :fail

echo [2/4] Waiting 15 seconds for services...
timeout /t 15 /nobreak >nul

echo [3/4] Running automated tests...
set PYTHONPATH=.
pytest -q
if errorlevel 1 goto :fail

echo [4/4] Open Locust after running: locust -f experiments\locustfile.py --host=http://localhost:8080
start http://localhost:8089
locust -f experiments\locustfile.py --host=http://localhost:8080
exit /b 0
:fail
echo Experiment setup failed. Check Docker Desktop and .env.
exit /b 1
