import sys
import json
import random
import string
import qrcode
import psycopg2
from datetime import datetime, timedelta
from config import cipher, DB_CONFIG
import base64
from io import BytesIO

def generate_secure_password(length=24):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

def generate_qr_code_base64(data):
    img = qrcode.make(data)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def handle(event):
    
    try:
        data = json.loads(event)
        username = data.get("username")
        if not username:
            raise ValueError("Le champ 'username' est requis.")

        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # 1) Vérifier si l'utilisateur existe déjà
        cur.execute("SELECT password, mfa, gendate, expired FROM users WHERE username = %s", (username,))
        row = cur.fetchone()

        # *** UTILISATEUR N'EXISTE PAS : création ***
        if row is None:
            # Générer le mot de passe
            password_plain = generate_secure_password()
            encrypted_password = cipher.encrypt(password_plain.encode()).decode()
            # Placeholder pour mfa_secret
            mfa_placeholder = cipher.encrypt(b"pending").decode()
            gendate = datetime.now()
            expired_flag = False
            cur.execute("""
                INSERT INTO users (username, password, mfa, gendate, expired)
                VALUES (%s, %s, %s, %s, %s)
            """, (username, encrypted_password, mfa_placeholder, gendate, expired_flag))
            conn.commit()

            # Générer le QR code du mot de passe
            qr_base64 = generate_qr_code_base64(password_plain)
            cur.close()
            conn.close()
            return json.dumps({
                "message": f"Utilisateur {username} créé.",
                "password": f"Mot de passe : {password_plain}",
                "qrcode": f"data:image/png;base64,{qr_base64}"
            })

        # *** UTILISATEUR EXISTE ***
        encrypted_pwd, encrypted_mfa, gendate, expired = row
        now = datetime.now()

        # 2) Si expiré réellement (expired True ou gendate > 6 mois)
        if expired or (now - gendate > timedelta(days=180)):
            # Régénérer un nouveau mot de passe
            password_plain = generate_secure_password()
            encrypted_password = cipher.encrypt(password_plain.encode()).decode()
            # Réinitialiser le TOTP à "pending"
            mfa_placeholder = cipher.encrypt(b"pending").decode()
            # Mettre expired à False et gendate=NOW()
            new_gendate = now
            cur.execute("""
                UPDATE users
                SET password = %s,
                    mfa = %s,
                    gendate = %s,
                    expired = FALSE
                WHERE username = %s
            """, (encrypted_password, mfa_placeholder, new_gendate, username))
            conn.commit()

            qr_base64 = generate_qr_code_base64(password_plain)
            cur.close()
            conn.close()
            return json.dumps({
                "message": f"Nouveau mot de passe généré pour {username}.",
                "qrcode": f"data:image/png;base64,{qr_base64}"
            })

        # 3) Si existant ET non expiré
        cur.close()
        conn.close()
        return json.dumps({
            "message": "Utilisateur existant. Veuillez vous authentifier ou réinitialiser si oublié."
        })

    except Exception as e:
        return json.dumps({"error": str(e)})

def main():
    event = sys.stdin.read()
    result = handle(event)
    sys.stdout.write(result)

if __name__ == "__main__":
    main()
