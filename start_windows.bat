@echo off
setlocal
cd /d %~dp0

if not exist .venv (
  echo L'environnement virtuel n'existe pas.
  echo Lancez d'abord setup_windows.bat
  pause
  exit /b 1
)

call .venv\Scripts\activate
python run.py
pause
