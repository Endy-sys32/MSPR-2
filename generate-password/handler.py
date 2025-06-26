import json
import random
import string
import qrcode
import base64
import io

def generate_complex_password(length=24):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")

def handle(event, context):
    try:
        body = json.loads(event.body)
        username = body.get("username")
        if not username:
            return {
                "statusCode": 400,
                "body": "Missing 'username' in request"
            }

        password = generate_complex_password()
        qrcode_b64 = generate_qr_code(password)

        return {
            "statusCode": 200,
            "body": json.dumps({
                "username": username,
                "password": password,
                "qrcode": qrcode_b64
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": str(e)
        }
