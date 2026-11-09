FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 1000 vulnscope
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

USER vulnscope
WORKDIR /workspace
ENTRYPOINT ["vulnscope"]
CMD ["--help"]
