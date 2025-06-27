
# récupérer fwatchdog depuis l'image officielle
FROM ghcr.io/openfaas/classic-watchdog:0.2.1 AS watchdog


# base Python
FROM python:3.10-slim

WORKDIR /home/app

# Copier le binaire fwatchdog depuis l'étape "watchdog"
COPY --from=watchdog /fwatchdog /usr/bin/fwatchdog
RUN chmod +x /usr/bin/fwatchdog

# Copier les sources de la fonction
COPY handler.py .
COPY config.py .
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Indiquer à fwatchdog de lancer python handler.py sur chaque requête
ENV fprocess="python handler.py"

# Route de healthcheck
HEALTHCHECK --interval=3s CMD ["wget", "-qO-", "http://127.0.0.1:8080/_/health"] || exit 1

# Au lancement, exécuter fwatchdog
CMD ["fwatchdog"]