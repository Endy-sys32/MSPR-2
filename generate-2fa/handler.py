import sys
import json
import pyotp
import qrcode
import psycopg2
from config import cipher, DB_CONFIG
import base64
from io import BytesIO

def generate_totp_secret(username):

    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="COFRAP Serverless Auth"
    )
    return secret, uri

def generate_qr_code_base64(data):

    img = qrcode.make(data)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

def update_user_mfa(username, mfa_secret):
    """
    Chiffre le secret TOTP et met à jour la colonne `mfa_secret` de l'utilisateur en base.
    """
    encrypted_mfa = cipher.encrypt(mfa_secret.encode()).decode()
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET mfa = %s WHERE username = %s",
        (encrypted_mfa, username)
    )
    conn.commit()
    cur.close()
    conn.close()

def handle(event):

    try:
        data = json.loads(event)
        username = data.get("username")
        if not username:
            raise ValueError("Le champ 'username' est requis.")

        # 1) Génération du secret et de l'URI TOTP
        secret, uri = generate_totp_secret(username)

        # 2) Stockage chiffré du secret en base
        update_user_mfa(username, secret)

        # 3) Génération du QR code
        qr_base64 = generate_qr_code_base64(uri)

        # 4) Réponse JSON
        return json.dumps({
            "message": f"2FA généré pour {username}.",
            "qrcode": f"data:image/png;base64,{qr_base64}"
        })

    except Exception as e:
        return json.dumps({"error": str(e)})

def main():
    event = sys.stdin.read()
    result = handle(event)
    sys.stdout.write(result)

if __name__ == "__main__":
    main()
