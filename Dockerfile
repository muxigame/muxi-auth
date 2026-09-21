FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY web ./web
COPY scripts ./scripts
RUN mkdir -p /app/data && useradd --system --uid 10001 --home-dir /app muxi && chown -R muxi:muxi /app/data
USER muxi
EXPOSE 9000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000", "--proxy-headers", "--forwarded-allow-ips=*"]

