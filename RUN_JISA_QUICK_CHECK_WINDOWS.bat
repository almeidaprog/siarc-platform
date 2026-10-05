@echo off
setlocal EnableExtensions
cd /d "%~dp0"
if not exist .env copy .env.example .env >nul
if not exist .venv python -m venv .venv
call .venv\Scripts\activate.bat
pip install -r requirements.txt
docker compose up -d --build
pytest -q
python experiments\pii_effectiveness.py
python experiments\score_policy_validation.py
python experiments\verify_postgres.py --api-key siarc-benchmark-key
python experiments\run_locust_matrix.py --users 10,200 --repeats 1 --run-time 15s --api-key siarc-benchmark-key
python experiments\summarize_locust_matrix.py
python experiments\collect_environment.py
python experiments\pack_jisa_results.py
pause
