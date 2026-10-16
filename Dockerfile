FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

WORKDIR /app

RUN groupadd --gid 1000 app \
    && useradd --uid 1000 --gid app --shell /bin/false --home-dir /app app

COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

COPY trap_app.py admin_app.py admin_final_actions.py visitor_fingerprint.py notification_batch.py background_tasks.py maintenance.py analyze_spam.py spam_analysis.py spam_summary_scheduler.py proxy_trust.py store.py fingerprint.py alerts.py hit_notifications.py config_store.py geoip2_lookup.py models.py db.py run.py ./
COPY templates ./templates

RUN chown -R app:app /app

ENV PYTHONUNBUFFERED=1
EXPOSE 4040 4090

USER app

CMD ["python", "-u", "run.py"]
