import sys
import json
import psycopg2
import pyotp
from datetime import datetime, timedelta
from config import cipher, DB_CONFIG

def handle(event):
    
    try:
        data = json.loads(event)
        username = data.get("username")
        password_input = data.get("password")
        totp_input = data.get("totp")

        if not username or not password_input or not totp_input:
            raise ValueError("Les champs 'username', 'password' et 'totp' sont requis.")

        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute(
            "SELECT password, mfa_secret, gendate, expired FROM users WHERE username = %s",
            (username,)
        )
        user = cur.fetchone()

        if not user:
            return json.dumps({"message": "Utilisateur introuvable."})

        encrypted_pwd, encrypted_mfa, gendate, expired = user

        # Si expired déjà à True, ou si plus de 6 mois depuis gendate :
        if expired or (datetime.now() - gendate > timedelta(days=180)):
            cur.execute("UPDATE users SET expired = TRUE WHERE username = %s", (username,))
            conn.commit()
            cur.close()
            conn.close()
            return json.dumps({"message": "Identifiants expirés. Veuillez les régénérer."})

        # Déchiffrer mot de passe stocké
        decrypted_pwd = cipher.decrypt(encrypted_pwd.encode()).decode()
        # Déchiffrer secret 2FA stocké
        decrypted_mfa = cipher.decrypt(encrypted_mfa.encode()).decode()

        # Vérifier la correspondance du mot de passe
        if password_input != decrypted_pwd:
            return json.dumps({"message": "Mot de passe incorrect."})

        # Vérifier le code TOTP 
        totp = pyotp.TOTP(decrypted_mfa)
        if not totp.verify(totp_input, valid_window=1):
            return json.dumps({"message": "Code 2FA invalide."})

        cur.close()
        conn.close()
        return json.dumps({"message": f"Authentification réussie pour {username}."})

    except Exception as e:
        return json.dumps({"error": str(e)})

def main():
    event = sys.stdin.read()
    result = handle(event)
    sys.stdout.write(result)

if __name__ == "__main__":
    main()
