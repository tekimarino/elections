HOTFIX - Erreur /admin/users (NameError: station_codes_scope)

Si vous voyez l'erreur:
  NameError: name 'station_codes_scope' is not defined
sur la page /admin/users, c'est que votre fichier app/app.py ne contient pas
la variable station_codes_scope dans la fonction admin_users().

Correctif intégré dans cette archive.

Procédure:
1) Remplacez votre dossier C:\elections par le contenu de cette archive (ou au minimum app\app.py).
2) Redémarrez l'application:
   - stop: Ctrl+C
   - start: python run.py

Après redémarrage, la création de représentants et superviseurs fonctionne.
