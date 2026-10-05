@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================================
echo SIARC - BATERIA FINAL DE TESTES PARA REVISAO JISA
echo ============================================================

if not exist .env (
  copy .env.example .env >nul
  echo [OK] .env criado a partir de .env.example
)

set "PYCMD="
for %%V in (3.13 3.12 3.11) do (
  if not defined PYCMD (
    py -%%V -c "" >nul 2>nul && set "PYCMD=py -%%V"
  )
)
if not defined PYCMD set "PYCMD=python"

if not exist .venv (
  echo [1/12] Criando ambiente Python ^(%PYCMD%^)...
  %PYCMD% -m venv .venv || goto :error
)
call .venv\Scripts\activate.bat || goto :error

echo [2/12] Instalando dependencias...
python -m pip install --upgrade pip >nul || goto :error
pip install -r requirements.txt || goto :error

set "DOCKER=docker"
where docker >nul 2>nul
if errorlevel 1 (
  wsl.exe -- docker version >nul 2>nul
  if errorlevel 1 (
    echo [ERRO] Docker nao encontrado no Windows nem no WSL.
    goto :error
  )
  set "DOCKER=wsl.exe -- docker"
)

echo [3/12] Subindo Docker/PostgreSQL/n8n/FastAPI ^(%DOCKER%^)...
%DOCKER% compose up -d --build || goto :error
powershell -NoProfile -Command "$deadline=(Get-Date).AddMinutes(2); do { try { $r=Invoke-WebRequest http://localhost:8080/health -UseBasicParsing -TimeoutSec 3; if($r.StatusCode -eq 200){exit 0} } catch {}; Start-Sleep 2 } while((Get-Date)-lt $deadline); exit 1" || goto :error

echo [4/12] Coletando hardware e ambiente...
python experiments\collect_environment.py || goto :error

echo [5/12] Rodando testes de regressao...
pytest -q || goto :error

echo [6/12] Validando eficacia da sanitizacao...
python experiments\pii_effectiveness.py || goto :error

echo [7/12] Validando score contra politica explicita...
python experiments\score_policy_validation.py || goto :error

echo [8/12] Confirmando PostgreSQL pela API...
python experiments\verify_postgres.py --api-key siarc-benchmark-key || goto :error

echo [9/12] Rodando matriz Locust repetida - esta etapa demora...
python experiments\run_locust_matrix.py --repeats 3 --run-time 45s --api-key siarc-benchmark-key || goto :error
python experiments\summarize_locust_matrix.py || goto :error

echo [10/12] Medindo overhead LGPD OFF x ON em PostgreSQL...
python experiments\run_privacy_overhead_docker.py --users 25 --repeats 3 --run-time 45s --api-key siarc-benchmark-key || goto :error

echo [11/12] Testes UNSW-NB15...
if exist data\UNSW_NB15_testing-set.csv (
  python experiments\score_unsw_blind_validation.py --csv data\UNSW_NB15_testing-set.csv --rows 10000 || goto :error
) else (
  echo [AVISO] data\UNSW_NB15_testing-set.csv nao encontrado. Score externo foi pulado.
)
if exist data\UNSW_NB15_training-set.csv (
  python experiments\replay_unsw_nb15_http.py --csv data\UNSW_NB15_training-set.csv --rows 1500 --concurrency 20 --api-key siarc-benchmark-key || goto :error
) else (
  echo [AVISO] data\UNSW_NB15_training-set.csv nao encontrado. Replay foi pulado.
)

echo [12/12] Gerando figuras e pacote final...
python experiments\generate_jisa_figures.py || goto :error
python experiments\pack_jisa_results.py || goto :error

echo.
echo ============================================================
echo CONCLUIDO.
echo Envie o ZIP criado dentro da pasta results para os autores.
echo ============================================================
pause
exit /b 0

:error
echo.
echo ============================================================
echo O TESTE PAROU COM ERRO.
echo Tire um print desta tela e envie junto.
echo ============================================================
pause
exit /b 1
