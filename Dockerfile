FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir ".[chat,slack]"
# Pick the adapter at deploy time: --set-env-vars=APP=examples.slack_adapter:api
ENV APP=examples.google_chat_adapter:app
CMD exec uvicorn "$APP" --host 0.0.0.0 --port "${PORT:-8080}"
