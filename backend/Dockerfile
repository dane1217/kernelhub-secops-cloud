FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
COPY logging.json .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home secops
COPY secops ./secops
COPY migrations ./migrations
COPY tests ./tests
COPY integration ./integration
USER secops
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health/live',timeout=3)" || exit 1
CMD ["uvicorn", "secops.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-server-header", "--log-config", "logging.json"]
