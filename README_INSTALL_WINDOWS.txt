INSTALLATION (Windows)

Option A (recommandee):
1) Double-cliquez sur setup_windows.bat (une seule fois)
2) Double-cliquez sur start_windows.bat pour lancer l'application

Option B (manuelle, si vous prefere):
1) Ouvrez un terminal dans le dossier du projet
2) py -m venv .venv
3) .venv\Scripts\activate
4) python -m pip install -r requirements.txt
5) python run.py

Si vous voyez "No module named 'flask'", c'est que les dependances ne sont pas installees dans votre environnement Python.
