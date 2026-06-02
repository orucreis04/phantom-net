FROM python:3.13-slim

LABEL org.opencontainers.image.title="Phantom-Net"
LABEL org.opencontainers.image.description="Defensive deception and honeypot analysis platform"

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PHANTOM_HOST=0.0.0.0

RUN addgroup --system phantom && adduser --system --ingroup phantom phantom

COPY main.py hash_password.py simulate_attack.py requirements.txt /app/
COPY phantom_net /app/phantom_net
COPY static /app/static
COPY docs /app/docs
COPY config.yaml /app/config.yaml

RUN mkdir -p /app/data && chown -R phantom:phantom /app

USER phantom

EXPOSE 8080 8081 8082 2222 3306 5432

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"

CMD ["python3", "main.py", "--host", "0.0.0.0"]
