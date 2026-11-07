# API REST - Backend para Aplicación Android

API REST desarrollada con **Python**, **Flask**, **SQLAlchemy** y **PostgreSQL**, diseñada para servir como backend de una aplicación móvil en Android. Incluye autenticación con **JWT**, documentación interactiva con **Swagger UI (Flasgger)** y protección de seguridad para despliegue en la nube.

---

## 🚀 Características
- **Autenticación Segura**: Registro y login con JSON Web Tokens (JWT) y contraseñas hasheadas (`PBKDF2:SHA256`).
- **Seguridad en la Nube**: Cabeceras HTTP de seguridad (OWASP), limitador de tasa de peticiones (Rate-limiting contra fuerza bruta) y soporte CORS.
- **Documentación Interactiva**: Swagger UI disponible en `/apidocs/` con soporte para probar tokens JWT (`Authorize`).
- **Control de Transacciones**: Actualización atómica de saldo en billeteras y validación de fondos.

---

## 🛠️ Instalación Local

1. **Clonar repositorio**:
   ```bash
   git clone <URL_DEL_REPOSITORIO>
   cd Proyecto_API
   ```

2. **Crear y activar entorno virtual**:
   ```bash
   python -m venv venv
   # En Windows PowerShell:
   .\venv\Scripts\Activate.ps1
   # En Linux / Mac:
   source venv/bin/activate
   ```

3. **Instalar dependencias**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configurar variables de entorno**:
   Copia el archivo `.env.example` a `.env` y coloca tus credenciales:
   ```bash
   cp .env.example .env
   ```

5. **Iniciar el servidor**:
   ```bash
   python src/app.py
   ```
   Accede a la documentación interactiva en: [http://localhost:5000/apidocs/](http://localhost:5000/apidocs/)

---

## ☁️ Despliegue en la Nube (Render / Railway)

1. Sube tu código a un repositorio en **GitHub**.
2. Conecta tu repositorio en **[Render.com](https://render.com/)** o **[Railway.app](https://railway.app/)**.
3. Configuración del servicio web:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn src.app:app` (o el `Procfile` incluido)
4. Configura las siguientes **Variables de Entorno** en el panel de tu host:
   - `DATABASE_URL`: La URL de tu base de datos PostgreSQL de Aiven.
   - `SECRET_KEY`: Una cadena segura y aleatoria.
   - `FLASK_ENV`: `production`
   - `FLASK_DEBUG`: `False`
   - `JWT_EXPIRATION_HOURS`: `24`

