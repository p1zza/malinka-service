FROM python:3.9-bookworm

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        g++ \
        python3-dev && \
    apt-key adv --refresh-keys --keyserver keyserver.ubuntu.com || true && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

COPY requirements.txt .

RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install \
    greenlet \
    wheel \
    -r requirements.txt \
    --no-binary :all:

RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app

USER app

COPY --chown=app:app . .

EXPOSE 8080

CMD ["python", "app.py"]
