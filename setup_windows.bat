@echo off
setlocal
cd /d %~dp0

REM 1) Creer un environnement virtuel
if not exist .venv (
  echo [1/3] Creation de l'environnement virtuel...
  py -m venv .venv
)

REM 2) Activer l'environnement virtuel
call .venv\Scripts\activate

REM 3) Installer les dependances
echo [2/3] Installation des dependances...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo OK. Vous pouvez maintenant lancer l'application.
echo Double-cliquez sur start_windows.bat
pause
