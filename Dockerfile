# Imagen base ligera y estable de Python
FROM python:3.12-slim

# Variables de entorno para Python en contenedores
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# Puerto por defecto; Fly.io sobreescribe esta variable en runtime
ENV PORT=8080

# Directorio de trabajo en el contenedor
WORKDIR /app

# Instalar dependencias del sistema mínimas
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copiar e instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar el código del proyecto (sin venv, .env, etc. — ver .dockerignore)
COPY . .

# Exponer el puerto dinámico
EXPOSE 8080

# Gunicorn lee $PORT en runtime; Fly.io lo inyecta automáticamente
CMD gunicorn --bind "0.0.0.0:${PORT}" --workers 2 --threads 4 --timeout 120 src.app:app

