FROM python:3.12-slim
LABEL org.opencontainers.image.title="cognis-sigsleuth"
LABEL org.opencontainers.image.source="https://github.com/cognis-digital/sigsleuth"
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
ENTRYPOINT ["sigsleuth"]
