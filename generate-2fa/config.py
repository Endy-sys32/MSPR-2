from cryptography.fernet import Fernet

# Clé fixe utilisée par tous les scripts
SECRET_KEY = b'n2-0WvRYYa1lyoynnKRS6EIXvlshkHpLJ0UX3vOgklk='
cipher = Fernet(SECRET_KEY)

# Configuration base de données
DB_CONFIG = {
    "dbname": "mspr-2",
    "user": "postgres",
    "password": "test",
    "host": "my-postgres-postgresql.database.svc.cluster.local",
    "port": 5432
}