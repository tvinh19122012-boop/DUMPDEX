FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    unzip file binutils && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py dexdump_core.py ./

ENV PORT=10000
EXPOSE 10000
CMD ["gunicorn","app:app","--bind","0.0.0.0:10000","--timeout","300","--workers","2"]