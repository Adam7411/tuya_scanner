FROM python:3.11-alpine

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev && \
    pip install --no-cache-dir tinytuya flask flask-cors

COPY run.sh /run.sh
COPY scanner.py /scanner.py
COPY www/ /var/www/

# Folder na persystentne dane — HA montuje /data do tego volumenu
VOLUME ["/data"]

RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
