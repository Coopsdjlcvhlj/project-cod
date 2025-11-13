FROM python:3.11-slim
WORKDIR /app

# Системні залежності (libpcap для scapy та базові інструменти збірки)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

ENV PYTHONUNBUFFERED=1
EXPOSE 5000

CMD ["python", "-u", "main.py"]
