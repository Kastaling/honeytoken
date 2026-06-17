FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask werkzeug requests sqlalchemy geoip2

COPY trap_app.py admin_app.py admin_final_actions.py visitor_fingerprint.py store.py fingerprint.py alerts.py hit_notifications.py config_store.py geo.py geoip2_lookup.py models.py db.py run.py ./
COPY templates ./templates

ENV PYTHONUNBUFFERED=1
EXPOSE 4040 4090

CMD ["python", "-u", "run.py"]
