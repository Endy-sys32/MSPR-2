from cryptography.fernet import Fernet

# Clé fixe utilisée par tous les scripts
SECRET_KEY = b'n2-0WvRYYa1lyoynnKRS6EIXvlshkHpLJ0UX3vOgklk='
cipher = Fernet(SECRET_KEY)

# Configuration base de données
DB_CONFIG = {
    "dbname": "cofrap_db",
    "user": "admin",
    "password": "admin123",
    "host": "postgres",
    "port": 5432
}