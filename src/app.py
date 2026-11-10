import os
from datetime import datetime, date, time, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flasgger import Swagger
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import jwt

# Cargar variables de entorno desde el archivo .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("ERROR DE SEGURIDAD: La variable SECRET_KEY no está definida en el entorno (.env).")

# 1. Habilitar CORS para permitir peticiones seguras desde Android y navegadores
CORS(app)

# 2. Protección de Cabeceras HTTP de Seguridad (Security Headers para Cloud/OWASP)
@app.after_request
def agregar_headers_seguridad(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# 3. Rate Limiter (Control de tráfico y mitigación de ataques de fuerza bruta / DoS)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["500 per day", "100 per hour"],
        storage_uri="memory://"
    )
except ImportError:
    class LimiterDummy:
        def limit(self, *args, **kwargs):
            return lambda f: f
    limiter = LimiterDummy()

# 4. Configuración de Base de Datos PostgreSQL (con compatibilidad psycopg3 y psycopg2)
DB_URI = os.getenv("DATABASE_URL")
if not DB_URI:
    raise RuntimeError("ERROR DE SEGURIDAD: La variable DATABASE_URL no está configurada en las variables de entorno (.env).")

try:
    import psycopg2
except ImportError:
    try:
        import psycopg
        if DB_URI.startswith("postgresql://"):
            DB_URI = DB_URI.replace("postgresql://", "postgresql+psycopg://", 1)
    except ImportError:
        pass

app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 5. Configuración de Swagger UI con Autenticación JWT (Candado "Authorize")
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec_1',
            "route": '/apispec_1.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/"
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "API Backend Segura - Aplicación Android",
        "description": "API REST conectada a base de datos PostgreSQL, protegida con JWT, CORS y validaciones de integridad referencial.",
        "version": "2.1.0",
        "contact": {
            "name": "Equipo de Desarrollo"
        }
    },
    "schemes": ["http", "https"],
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Introduce tu token en el formato: Bearer <tu_token_jwt>"
        }
    },
    "consumes": ["application/json"],
    "produces": ["application/json"]
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)

# ==========================================
# UTILIDADES Y SEGURIDAD (JWT & DECORADORES)
# ==========================================

def generar_token(usuario_id, rol):
    """Genera un JSON Web Token firmado con expiración configurable."""
    exp_hours = int(os.getenv('JWT_EXPIRATION_HOURS', '24'))
    payload = {
        'usuario_id': usuario_id,
        'rol': rol,
        'exp': datetime.utcnow() + timedelta(hours=exp_hours),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, app.secret_key, algorithm='HS256')

def token_requerido(f):
    """Decorador para proteger rutas y exigir un token JWT válido."""
    @wraps(f)
    def decorador(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header:
            partes = auth_header.split()
            if len(partes) == 2 and partes[0].lower() == 'bearer':
                token = partes[1]
            else:
                token = auth_header
        
        if not token:
            return jsonify({'error': 'Token de autorización requerido. Usa el encabezado: Authorization: Bearer <token>'}), 401
        
        try:
            datos = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            usuario_actual = Usuario.query.get(datos['usuario_id'])
            if not usuario_actual:
                return jsonify({'error': 'Usuario no válido o eliminado'}), 401
            if usuario_actual.estado_cuenta and usuario_actual.estado_cuenta.upper() in ('SUSPENDIDO', 'SUSPENDIDA', 'INACTIVA'):
                return jsonify({'error': 'Tu cuenta se encuentra inactiva o suspendida'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'El token ha expirado. Inicia sesión nuevamente'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido o alterado'}), 401

        return f(usuario_actual, *args, **kwargs)
    return decorador

def rol_requerido(*roles_permitidos):
    """Decorador para control de acceso basado en roles (RBAC)."""
    roles_upper = [r.upper() for r in roles_permitidos] + ['ADMIN']
    def decorador_externo(f):
        @wraps(f)
        def decorador(usuario_actual, *args, **kwargs):
            rol_actual = (usuario_actual.rol or '').upper()
            if rol_actual not in roles_upper:
                return jsonify({'error': f'Acceso denegado. Se requiere rol: {", ".join(roles_permitidos)}'}), 403
            return f(usuario_actual, *args, **kwargs)
        return decorador
    return decorador_externo

def get_request_data():
    """Obtiene datos de forma segura tanto si vienen en JSON como en formulario."""
    if request.is_json:
        return request.get_json(silent=True) or {}
    return request.form.to_dict() or {}

def parse_date(val):
    if not val:
        return None
    if isinstance(val, (date, datetime)):
        return val if isinstance(val, date) else val.date()
    try:
        return datetime.strptime(str(val), '%Y-%m-%d').date()
    except Exception:
        return None

def parse_time(val):
    if not val:
        return None
    if isinstance(val, time):
        return val
    for fmt in ('%H:%M:%S', '%H:%M'):
        try:
            return datetime.strptime(str(val), fmt).time()
        except Exception:
            continue
    return None

# ==========================================
# MODELOS DE LA BASE DE DATOS (ESQUEMA POSTGRESQL EXACTO)
# ==========================================

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    usuario_id = db.Column(db.BigInteger, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    correo = db.Column(db.String(150), unique=True, nullable=False)
    telefono = db.Column(db.String(20), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(50), nullable=False, default='CLIENTE')
    foto_perfil = db.Column(db.String(255), nullable=True)
    estado_cuenta = db.Column(db.String(50), nullable=False, default='ACTIVA')
    fecha_registro = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'usuario_id': self.usuario_id,
            'nombre': self.nombre,
            'correo': self.correo,
            'telefono': self.telefono,
            'rol': self.rol,
            'foto_perfil': self.foto_perfil,
            'estado_cuenta': self.estado_cuenta,
            'fecha_registro': self.fecha_registro.isoformat() if self.fecha_registro else None
        }

class Billetera(db.Model):
    __tablename__ = 'billeteras'
    billetera_id = db.Column(db.BigInteger, primary_key=True)
    usuario_id = db.Column(db.BigInteger, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    saldo = db.Column(db.Numeric(10, 2), nullable=False, default=0.00)
    moneda = db.Column(db.String(10), nullable=False, default='USD')
    estado = db.Column(db.String(20), nullable=False, default='activo')
    fecha_creacion = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'billetera_id': self.billetera_id,
            'usuario_id': self.usuario_id,
            'saldo': float(self.saldo) if self.saldo is not None else 0.0,
            'moneda': self.moneda,
            'estado': self.estado,
            'fecha_creacion': self.fecha_creacion.isoformat() if self.fecha_creacion else None
        }

class Categoria(db.Model):
    __tablename__ = 'categorias'
    categoria_id = db.Column(db.BigInteger, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=True)
    icono = db.Column(db.String(100), nullable=True)
    activo = db.Column(db.Boolean, nullable=False, default=True)

    def to_dict(self):
        return {
            'categoria_id': self.categoria_id,
            'nombre': self.nombre,
            'descripcion': self.descripcion,
            'icono': self.icono,
            'activo': self.activo
        }

class PerfilColaborador(db.Model):
    __tablename__ = 'perfiles_colaborador'
    perfil_id = db.Column(db.BigInteger, primary_key=True)
    usuario_id = db.Column(db.BigInteger, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    descripcion = db.Column(db.Text, nullable=True)
    experiencia_anios = db.Column(db.Integer, nullable=False, default=0)
    zona = db.Column(db.String(100), nullable=True)
    disponible = db.Column(db.Boolean, nullable=False, default=True)
    identidad_verificada = db.Column(db.Boolean, nullable=False, default=False)
    calificacion_promedio = db.Column(db.Numeric(3, 2), nullable=False, default=0.00)
    trabajos_realizados = db.Column(db.Integer, nullable=False, default=0)

    def to_dict(self):
        return {
            'perfil_id': self.perfil_id,
            'usuario_id': self.usuario_id,
            'descripcion': self.descripcion,
            'experiencia_anios': self.experiencia_anios,
            'zona': self.zona,
            'disponible': self.disponible,
            'identidad_verificada': self.identidad_verificada,
            'calificacion_promedio': float(self.calificacion_promedio) if self.calificacion_promedio is not None else 0.0,
            'trabajos_realizados': self.trabajos_realizados
        }

class ColaboradorCategoria(db.Model):
    __tablename__ = 'colaborador_categoria'
    perfil_id = db.Column(db.BigInteger, db.ForeignKey('perfiles_colaborador.perfil_id'), primary_key=True)
    categoria_id = db.Column(db.BigInteger, db.ForeignKey('categorias.categoria_id'), primary_key=True)

    def to_dict(self):
        return {
            'perfil_id': self.perfil_id,
            'categoria_id': self.categoria_id
        }

class Solicitud(db.Model):
    __tablename__ = 'solicitudes'
    solicitud_id = db.Column(db.BigInteger, primary_key=True)
    cliente_id = db.Column(db.BigInteger, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    colaborador_id = db.Column(db.BigInteger, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    categoria_id = db.Column(db.BigInteger, db.ForeignKey('categorias.categoria_id'), nullable=False)
    titulo = db.Column(db.String(150), nullable=False)
    descripcion = db.Column(db.Text, nullable=True)
    direccion = db.Column(db.Text, nullable=False)
    fecha_servicio = db.Column(db.Date, nullable=False)
    hora_servicio = db.Column(db.Time, nullable=False)
    estado = db.Column(db.String(50), nullable=False, default='PENDIENTE')
    fecha_solicitud = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'solicitud_id': self.solicitud_id,
            'cliente_id': self.cliente_id,
            'colaborador_id': self.colaborador_id,
            'categoria_id': self.categoria_id,
            'titulo': self.titulo,
            'descripcion': self.descripcion,
            'direccion': self.direccion,
            'fecha_servicio': self.fecha_servicio.isoformat() if self.fecha_servicio else None,
            'hora_servicio': self.hora_servicio.strftime('%H:%M:%S') if self.hora_servicio else None,
            'estado': self.estado,
            'fecha_solicitud': self.fecha_solicitud.isoformat() if self.fecha_solicitud else None
        }

class Movimiento(db.Model):
    __tablename__ = 'movimientos'
    movimiento_id = db.Column(db.BigInteger, primary_key=True)
    billetera_id = db.Column(db.BigInteger, db.ForeignKey('billeteras.billetera_id'), nullable=False)
    usuario_id = db.Column(db.BigInteger, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    solicitud_id = db.Column(db.BigInteger, db.ForeignKey('solicitudes.solicitud_id'), nullable=True)
    tipo = db.Column(db.String(50), nullable=False)
    monto = db.Column(db.Numeric(10, 2), nullable=False)
    comision = db.Column(db.Numeric(10, 2), nullable=False, default=0.00)
    monto_neto = db.Column(db.Numeric(10, 2), nullable=False)
    estado = db.Column(db.String(50), nullable=False, default='completado')
    fecha = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'movimiento_id': self.movimiento_id,
            'billetera_id': self.billetera_id,
            'usuario_id': self.usuario_id,
            'solicitud_id': self.solicitud_id,
            'tipo': self.tipo,
            'monto': float(self.monto) if self.monto is not None else 0.0,
            'comision': float(self.comision) if self.comision is not None else 0.0,
            'monto_neto': float(self.monto_neto) if self.monto_neto is not None else 0.0,
            'estado': self.estado,
            'fecha': self.fecha.isoformat() if self.fecha else None
        }

class Mensaje(db.Model):
    __tablename__ = 'mensajes'
    mensaje_id = db.Column(db.BigInteger, primary_key=True)
    solicitud_id = db.Column(db.BigInteger, db.ForeignKey('solicitudes.solicitud_id'), nullable=False)
    emisor_id = db.Column(db.BigInteger, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    receptor_id = db.Column(db.BigInteger, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    tipo = db.Column(db.String(50), nullable=False, default='texto')
    contenido = db.Column(db.Text, nullable=True)
    archivo_url = db.Column(db.String(255), nullable=True)
    leido = db.Column(db.Boolean, nullable=False, default=False)
    fecha_envio = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'mensaje_id': self.mensaje_id,
            'solicitud_id': self.solicitud_id,
            'emisor_id': self.emisor_id,
            'receptor_id': self.receptor_id,
            'tipo': self.tipo,
            'contenido': self.contenido,
            'archivo_url': self.archivo_url,
            'leido': self.leido,
            'fecha_envio': self.fecha_envio.isoformat() if self.fecha_envio else None
        }

class Incidencia(db.Model):
    __tablename__ = 'incidencias'
    incidencia_id = db.Column(db.BigInteger, primary_key=True)
    usuario_id = db.Column(db.BigInteger, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    solicitud_id = db.Column(db.BigInteger, db.ForeignKey('solicitudes.solicitud_id'), nullable=True)
    soporte_id = db.Column(db.BigInteger, db.ForeignKey('usuarios.usuario_id'), nullable=True)
    tipo = db.Column(db.String(50), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    estado = db.Column(db.String(50), nullable=False, default='abierto')
    fecha_reporte = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'incidencia_id': self.incidencia_id,
            'usuario_id': self.usuario_id,
            'solicitud_id': self.solicitud_id,
            'soporte_id': self.soporte_id,
            'tipo': self.tipo,
            'descripcion': self.descripcion,
            'estado': self.estado,
            'fecha_reporte': self.fecha_reporte.isoformat() if self.fecha_reporte else None
        }

class Resena(db.Model):
    __tablename__ = 'resenas'
    resena_id = db.Column(db.BigInteger, primary_key=True)
    solicitud_id = db.Column(db.BigInteger, db.ForeignKey('solicitudes.solicitud_id'), nullable=False)
    cliente_id = db.Column(db.BigInteger, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    colaborador_id = db.Column(db.BigInteger, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    calificacion = db.Column(db.Integer, nullable=False)
    comentario = db.Column(db.Text, nullable=True)
    fecha = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'resena_id': self.resena_id,
            'solicitud_id': self.solicitud_id,
            'cliente_id': self.cliente_id,
            'colaborador_id': self.colaborador_id,
            'calificacion': self.calificacion,
            'comentario': self.comentario,
            'fecha': self.fecha.isoformat() if self.fecha else None
        }

class Registro(db.Model):
    __tablename__ = 'registros'
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(150), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'titulo': self.titulo,
            'descripcion': self.descripcion
        }

# ==========================================
# HEALTH CHECK — requerido por Fly.io
# ==========================================

@app.route('/health', methods=['GET'])
def health_check():
    """
    Endpoint de salud para Fly.io y monitores de uptime
    ---
    tags:
      - Sistema
    responses:
      200:
        description: Servicio operativo
    """
    return jsonify({'status': 'ok', 'service': 'proyecto-api'}), 200

# ==========================================
# ENDPOINTS DE AUTENTICACIÓN (JWT & SEGURIDAD)
# ==========================================

@app.route('/api/auth/registro', methods=['POST'])
def api_auth_registro():
    """
    Registro seguro de nuevo usuario (Crea Usuario y Billetera)
    ---
    tags:
      - Autenticación
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - nombre
            - correo
            - password
          properties:
            nombre:
              type: string
              example: "Juan Pérez"
            correo:
              type: string
              example: "juan.perez@example.com"
            telefono:
              type: string
              example: "7441234567"
            password:
              type: string
              example: "MiClaveSegura#2026"
            rol:
              type: string
              enum: [CLIENTE, COLABORADOR, ADMIN]
              example: "CLIENTE"
            foto_perfil:
              type: string
              example: "https://ejemplo.com/avatar.jpg"
    responses:
      201:
        description: Usuario registrado y token generado con éxito
      400:
        description: Datos faltantes o contraseña muy corta
      409:
        description: Correo o teléfono ya registrado
    """
    data = get_request_data()
    nombre = (data.get('nombre') or '').strip()
    correo = (data.get('correo') or '').strip().lower()
    telefono = (data.get('telefono') or '').strip() or None
    password = data.get('password') or data.get('password_hash')
    rol = (data.get('rol') or 'CLIENTE').upper()

    if not nombre or not correo or not password:
        return jsonify({'error': 'Los campos nombre, correo y password son obligatorios'}), 400

    if len(password) < 6:
        return jsonify({'error': 'La contraseña debe tener al menos 6 caracteres'}), 400

    if Usuario.query.filter_by(correo=correo).first():
        return jsonify({'error': f'El correo {correo} ya se encuentra registrado'}), 409

    if telefono and Usuario.query.filter_by(telefono=telefono).first():
        return jsonify({'error': f'El teléfono {telefono} ya se encuentra registrado'}), 409

    hash_seguro = generate_password_hash(password, method='pbkdf2:sha256')

    nuevo_usuario = Usuario(
        nombre=nombre,
        correo=correo,
        telefono=telefono,
        password_hash=hash_seguro,
        rol=rol,
        foto_perfil=data.get('foto_perfil'),
        estado_cuenta='ACTIVA'
    )
    db.session.add(nuevo_usuario)
    db.session.flush()

    # Billetera inicial obligatoria para cada usuario
    billetera_inicial = Billetera(
        usuario_id=nuevo_usuario.usuario_id,
        saldo=0.00,
        moneda='USD',
        estado='activo'
    )
    db.session.add(billetera_inicial)
    db.session.commit()

    token = generar_token(nuevo_usuario.usuario_id, nuevo_usuario.rol)
    return jsonify({
        'mensaje': 'Usuario registrado exitosamente',
        'token': token,
        'usuario': nuevo_usuario.to_dict(),
        'billetera': billetera_inicial.to_dict()
    }), 201


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def api_auth_login():
    """
    Inicio de sesión seguro para Android (por correo o teléfono)
    ---
    tags:
      - Autenticación
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - identificador
            - password
          properties:
            identificador:
              type: string
              description: Correo electrónico o número de teléfono registrado
              example: "juan.perez@example.com"
            password:
              type: string
              example: "MiClaveSegura#2026"
    responses:
      200:
        description: Login exitoso, entrega el token Bearer
      401:
        description: Credenciales incorrectas
      429:
        description: Demasiados intentos fallidos (Rate limit)
    """
    data = get_request_data()
    identificador = (data.get('identificador') or data.get('correo') or data.get('telefono') or '').strip()
    password = data.get('password') or data.get('password_hash')

    if not identificador or not password:
        return jsonify({'error': 'Introduce tu correo o teléfono y tu contraseña'}), 400

    usuario = Usuario.query.filter(
        (Usuario.correo == identificador.lower()) | (Usuario.telefono == identificador)
    ).first()

    if not usuario or not check_password_hash(usuario.password_hash, password):
        if usuario and usuario.password_hash == password:
            usuario.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            db.session.commit()
        else:
            return jsonify({'error': 'Credenciales incorrectas'}), 401

    if usuario.estado_cuenta and usuario.estado_cuenta.upper() in ('SUSPENDIDO', 'SUSPENDIDA', 'INACTIVA'):
        return jsonify({'error': 'Tu cuenta está suspendida'}), 403

    token = generar_token(usuario.usuario_id, usuario.rol)
    billetera = Billetera.query.filter_by(usuario_id=usuario.usuario_id).first()

    return jsonify({
        'mensaje': 'Inicio de sesión exitoso',
        'token': token,
        'usuario': usuario.to_dict(),
        'billetera': billetera.to_dict() if billetera else None
    }), 200


@app.route('/api/auth/perfil', methods=['GET'])
@token_requerido
def api_auth_perfil(usuario_actual):
    """
    Obtener perfil del usuario autenticado actualmente
    ---
    tags:
      - Autenticación
    security:
      - Bearer: []
    responses:
      200:
        description: Perfil y billetera del usuario
    """
    billetera = Billetera.query.filter_by(usuario_id=usuario_actual.usuario_id).first()
    return jsonify({
        'usuario': usuario_actual.to_dict(),
        'billetera': billetera.to_dict() if billetera else None
    }), 200


# ==========================================
# ENDPOINTS REST DE LA BASE DE DATOS
# ==========================================

# --- API USUARIOS ---
@app.route('/api/usuarios', methods=['GET'])
@token_requerido
def api_listar_usuarios(usuario_actual):
    """Listar usuarios registrados"""
    usuarios = Usuario.query.all()
    return jsonify([u.to_dict() for u in usuarios]), 200

@app.route('/api/usuarios/<int:id>', methods=['GET'])
@token_requerido
def api_obtener_usuario(usuario_actual, id):
    """Obtener un usuario por su ID"""
    usuario = Usuario.query.get_or_404(id)
    return jsonify(usuario.to_dict()), 200


# --- API BILLETERAS ---
@app.route('/api/billeteras/mi_billetera', methods=['GET'])
@token_requerido
def api_mi_billetera(usuario_actual):
    """Consultar saldo de la billetera propia"""
    billetera = Billetera.query.filter_by(usuario_id=usuario_actual.usuario_id).first()
    if not billetera:
        billetera = Billetera(usuario_id=usuario_actual.usuario_id, saldo=0.00, moneda='USD', estado='activo')
        db.session.add(billetera)
        db.session.commit()
    return jsonify(billetera.to_dict()), 200

@app.route('/api/billeteras', methods=['GET'])
@token_requerido
@rol_requerido('admin')
def api_listar_billeteras(usuario_actual):
    """Listar todas las billeteras (Solo Administrador)"""
    billeteras = Billetera.query.all()
    return jsonify([b.to_dict() for b in billeteras]), 200


# --- API CATEGORÍAS ---
@app.route('/api/categorias', methods=['GET'])
def api_listar_categorias():
    """
    Listar catálogo de categorías de servicio activas
    ---
    tags:
      - API Categorías
    responses:
      200:
        description: Lista de categorías
    """
    items = Categoria.query.filter_by(activo=True).all()
    return jsonify([c.to_dict() for c in items]), 200

@app.route('/api/categorias', methods=['POST'])
@token_requerido
@rol_requerido('admin')
def api_crear_categoria(usuario_actual):
    """
    Crear una nueva categoría de servicio (Solo Administrador)
    ---
    tags:
      - API Categorías
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - nombre
          properties:
            nombre:
              type: string
              example: "Plomería"
            descripcion:
              type: string
              example: "Instalación y reparación de tuberías"
            icono:
              type: string
              example: "pipe-wrench"
            activo:
              type: boolean
              example: true
    responses:
      201:
        description: Categoría creada
    """
    data = get_request_data()
    nombre = (data.get('nombre') or '').strip()
    if not nombre:
        return jsonify({'error': 'El nombre de la categoría es obligatorio'}), 400
    item = Categoria(
        nombre=nombre,
        descripcion=data.get('descripcion'),
        icono=data.get('icono'),
        activo=bool(data.get('activo', True))
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(item.to_dict()), 201


# --- API SOLICITUDES DE SERVICIO ---
@app.route('/api/solicitudes', methods=['GET'])
def api_listar_solicitudes():
    """
    Listar solicitudes de servicio
    ---
    tags:
      - API Solicitudes
    responses:
      200:
        description: Lista de solicitudes
    """
    solicitudes = Solicitud.query.order_by(Solicitud.fecha_solicitud.desc()).all()
    return jsonify([s.to_dict() for s in solicitudes]), 200

@app.route('/api/solicitudes', methods=['POST'])
@token_requerido
def api_crear_solicitud(usuario_actual):
    """
    Crear una solicitud de servicio vinculando cliente, colaborador y categoría
    ---
    tags:
      - API Solicitudes
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - categoria_id
            - colaborador_id
            - titulo
            - direccion
            - fecha_servicio
            - hora_servicio
          properties:
            categoria_id:
              type: integer
              example: 1
            colaborador_id:
              type: integer
              example: 4
            titulo:
              type: string
              example: "Reparación de fuga de agua"
            descripcion:
              type: string
              example: "Fuga debajo del lavamanos en baño principal"
            direccion:
              type: string
              example: "Av. Costera 123, Acapulco"
            fecha_servicio:
              type: string
              example: "2026-11-20"
            hora_servicio:
              type: string
              example: "15:00:00"
    responses:
      201:
        description: Solicitud creada con éxito
      400:
        description: Datos faltantes o IDs inválidos
    """
    data = get_request_data()
    categoria_id = data.get('categoria_id')
    colaborador_id = data.get('colaborador_id')
    titulo = (data.get('titulo') or '').strip()
    direccion = (data.get('direccion') or '').strip()
    fecha_servicio = parse_date(data.get('fecha_servicio'))
    hora_servicio = parse_time(data.get('hora_servicio'))

    if not categoria_id or not colaborador_id or not titulo or not direccion or not fecha_servicio or not hora_servicio:
        return jsonify({'error': 'categoria_id, colaborador_id, titulo, direccion, fecha_servicio y hora_servicio son obligatorios'}), 400

    # Verificar que el colaborador y la categoría existan
    if not Usuario.query.get(colaborador_id):
        return jsonify({'error': f'El colaborador con ID {colaborador_id} no existe'}), 404

    if not Categoria.query.get(categoria_id):
        return jsonify({'error': f'La categoría con ID {categoria_id} no existe'}), 404

    item = Solicitud(
        cliente_id=usuario_actual.usuario_id,
        colaborador_id=colaborador_id,
        categoria_id=categoria_id,
        titulo=titulo,
        descripcion=data.get('descripcion'),
        direccion=direccion,
        fecha_servicio=fecha_servicio,
        hora_servicio=hora_servicio,
        estado=data.get('estado', 'PENDIENTE')
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(item.to_dict()), 201

@app.route('/api/solicitudes/<int:id>', methods=['GET'])
def api_obtener_solicitud(id):
    """Obtener detalle de una solicitud por su ID"""
    solicitud = Solicitud.query.get_or_404(id)
    return jsonify(solicitud.to_dict()), 200

@app.route('/api/solicitudes/<int:id>', methods=['PUT'])
@token_requerido
def api_actualizar_solicitud(usuario_actual, id):
    """Actualizar estado o datos de una solicitud"""
    solicitud = Solicitud.query.get_or_404(id)
    data = get_request_data()
    if 'titulo' in data: solicitud.titulo = data['titulo']
    if 'descripcion' in data: solicitud.descripcion = data['descripcion']
    if 'direccion' in data: solicitud.direccion = data['direccion']
    if 'colaborador_id' in data: solicitud.colaborador_id = data['colaborador_id']
    if 'categoria_id' in data: solicitud.categoria_id = data['categoria_id']
    if 'fecha_servicio' in data: solicitud.fecha_servicio = parse_date(data['fecha_servicio'])
    if 'hora_servicio' in data: solicitud.hora_servicio = parse_time(data['hora_servicio'])
    if 'estado' in data: solicitud.estado = data['estado']
    db.session.commit()
    return jsonify(solicitud.to_dict()), 200

@app.route('/api/solicitudes/<int:id>', methods=['DELETE'])
@token_requerido
@rol_requerido('admin')
def api_eliminar_solicitud(usuario_actual, id):
    """Eliminar una solicitud (Solo Administrador)"""
    solicitud = Solicitud.query.get_or_404(id)
    db.session.delete(solicitud)
    db.session.commit()
    return jsonify({'mensaje': f'Solicitud {id} eliminada'}), 200


# --- API MOVIMIENTOS FINANCIEROS ---
@app.route('/api/movimientos', methods=['GET'])
@token_requerido
def api_listar_movimientos(usuario_actual):
    """Listar movimientos del usuario actual (o todos si es admin)"""
    if (usuario_actual.rol or '').upper() == 'ADMIN':
        movs = Movimiento.query.order_by(Movimiento.fecha.desc()).all()
    else:
        movs = Movimiento.query.filter_by(usuario_id=usuario_actual.usuario_id).order_by(Movimiento.fecha.desc()).all()
    return jsonify([m.to_dict() for m in movs]), 200

@app.route('/api/movimientos', methods=['POST'])
@token_requerido
def api_crear_movimiento_seguro(usuario_actual):
    """
    Registrar un movimiento financiero con actualización atómica de la billetera
    ---
    tags:
      - API Movimientos
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - tipo
            - monto
          properties:
            tipo:
              type: string
              enum: [ingreso, egreso, pago_servicio, retiro]
              example: "ingreso"
            monto:
              type: number
              example: 250.00
            comision:
              type: number
              example: 10.00
            solicitud_id:
              type: integer
              example: 1
    responses:
      201:
        description: Transacción registrada y saldo actualizado
    """
    data = get_request_data()
    tipo = data.get('tipo')
    try:
        monto = float(data.get('monto') or 0.0)
        comision = float(data.get('comision') or 0.0)
    except ValueError:
        return jsonify({'error': 'El monto y la comisión deben ser numéricos'}), 400

    if monto <= 0:
        return jsonify({'error': 'El monto debe ser estrictamente mayor a 0'}), 400

    billetera = Billetera.query.filter_by(usuario_id=usuario_actual.usuario_id).first()
    if not billetera:
        billetera = Billetera(usuario_id=usuario_actual.usuario_id, saldo=0.00, moneda='USD', estado='activo')
        db.session.add(billetera)
        db.session.flush()

    monto_neto = monto - comision

    if tipo in ('egreso', 'retiro', 'pago_servicio'):
        if float(billetera.saldo) < monto:
            return jsonify({'error': 'Saldo insuficiente en tu billetera'}), 400
        billetera.saldo = float(billetera.saldo) - monto
    elif tipo in ('ingreso', 'recarga'):
        billetera.saldo = float(billetera.saldo) + monto_neto

    solicitud_id = data.get('solicitud_id')
    if solicitud_id and not Solicitud.query.get(solicitud_id):
        return jsonify({'error': f'La solicitud {solicitud_id} no existe'}), 404

    movimiento = Movimiento(
        billetera_id=billetera.billetera_id,
        usuario_id=usuario_actual.usuario_id,
        solicitud_id=solicitud_id,
        tipo=tipo,
        monto=monto,
        comision=comision,
        monto_neto=monto_neto,
        estado='completado'
    )

    try:
        db.session.add(movimiento)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error al procesar la transacción: {str(e)}'}), 500

    return jsonify({
        'mensaje': 'Transacción completada',
        'movimiento': movimiento.to_dict(),
        'nuevo_saldo': float(billetera.saldo)
    }), 201


# --- API MENSAJES ---
@app.route('/api/mensajes', methods=['POST'])
@token_requerido
def api_enviar_mensaje(usuario_actual):
    """
    Enviar un mensaje vinculado a una solicitud
    ---
    tags:
      - API Mensajes
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - solicitud_id
            - receptor_id
            - contenido
          properties:
            solicitud_id:
              type: integer
              example: 1
            receptor_id:
              type: integer
              example: 4
            tipo:
              type: string
              example: "texto"
            contenido:
              type: string
              example: "Hola, ¿en cuánto tiempo llegas?"
            archivo_url:
              type: string
    responses:
      201:
        description: Mensaje enviado
    """
    data = get_request_data()
    solicitud_id = data.get('solicitud_id')
    receptor_id = data.get('receptor_id')
    contenido = (data.get('contenido') or '').strip()

    if not solicitud_id or not receptor_id:
        return jsonify({'error': 'solicitud_id y receptor_id son obligatorios'}), 400

    if not Solicitud.query.get(solicitud_id):
        return jsonify({'error': f'La solicitud {solicitud_id} no existe'}), 404

    if not Usuario.query.get(receptor_id):
        return jsonify({'error': f'El usuario receptor {receptor_id} no existe'}), 404

    item = Mensaje(
        solicitud_id=solicitud_id,
        emisor_id=usuario_actual.usuario_id,
        receptor_id=receptor_id,
        tipo=data.get('tipo', 'texto'),
        contenido=contenido,
        archivo_url=data.get('archivo_url'),
        leido=False
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(item.to_dict()), 201

@app.route('/api/mensajes/mis_mensajes', methods=['GET'])
@token_requerido
def api_mis_mensajes(usuario_actual):
    """Listar mensajes enviados o recibidos por el usuario en sesión"""
    mensajes = Mensaje.query.filter(
        (Mensaje.emisor_id == usuario_actual.usuario_id) | 
        (Mensaje.receptor_id == usuario_actual.usuario_id)
    ).order_by(Mensaje.fecha_envio.desc()).all()
    return jsonify([m.to_dict() for m in mensajes]), 200


# --- API RESEÑAS ---
@app.route('/api/resenas', methods=['GET'])
def api_listar_resenas():
    """Listar todas las reseñas"""
    resenas = Resena.query.order_by(Resena.fecha.desc()).all()
    return jsonify([r.to_dict() for r in resenas]), 200

@app.route('/api/resenas', methods=['POST'])
@token_requerido
def api_crear_resena(usuario_actual):
    """
    Calificar y reseñar el trabajo de un colaborador
    ---
    tags:
      - API Reseñas
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - solicitud_id
            - colaborador_id
            - calificacion
          properties:
            solicitud_id:
              type: integer
              example: 1
            colaborador_id:
              type: integer
              example: 4
            calificacion:
              type: integer
              example: 5
            comentario:
              type: string
              example: "Excelente trabajo, puntual y profesional."
    responses:
      201:
        description: Reseña guardada
    """
    data = get_request_data()
    solicitud_id = data.get('solicitud_id')
    colaborador_id = data.get('colaborador_id')
    try:
        calif = int(data.get('calificacion', 5))
    except ValueError:
        return jsonify({'error': 'La calificación debe ser un entero entre 1 y 5'}), 400

    if not solicitud_id or not colaborador_id:
        return jsonify({'error': 'solicitud_id y colaborador_id son obligatorios'}), 400

    if not Solicitud.query.get(solicitud_id):
        return jsonify({'error': f'La solicitud {solicitud_id} no existe'}), 404

    if not Usuario.query.get(colaborador_id):
        return jsonify({'error': f'El colaborador {colaborador_id} no existe'}), 404

    item = Resena(
        solicitud_id=solicitud_id,
        cliente_id=usuario_actual.usuario_id,
        colaborador_id=colaborador_id,
        calificacion=calif,
        comentario=data.get('comentario')
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(item.to_dict()), 201


# --- API PERFILES COLABORADOR ---
@app.route('/api/perfiles_colaborador', methods=['GET'])
def api_listar_perfiles_colaborador():
    """Listar perfiles de colaboradores"""
    items = PerfilColaborador.query.all()
    return jsonify([p.to_dict() for p in items]), 200

@app.route('/api/perfiles_colaborador', methods=['POST'])
@token_requerido
def api_crear_perfil_colaborador(usuario_actual):
    """
    Crear o actualizar perfil del colaborador
    ---
    tags:
      - API Perfiles Colaborador
    security:
      - Bearer: []
    """
    data = get_request_data()
    user_id = data.get('usuario_id') or usuario_actual.usuario_id

    if not Usuario.query.get(user_id):
        return jsonify({'error': f'El usuario con ID {user_id} no existe'}), 404

    perfil = PerfilColaborador(
        usuario_id=user_id,
        descripcion=data.get('descripcion'),
        experiencia_anios=int(data.get('experiencia_anios') or 0),
        zona=data.get('zona'),
        disponible=bool(data.get('disponible', True)),
        identidad_verificada=bool(data.get('identidad_verificada', False)),
        calificacion_promedio=float(data.get('calificacion_promedio') or 0.0),
        trabajos_realizados=int(data.get('trabajos_realizados') or 0)
    )
    db.session.add(perfil)
    db.session.commit()
    return jsonify(perfil.to_dict()), 201


# --- API INCIDENCIAS ---
@app.route('/api/incidencias', methods=['POST'])
@token_requerido
def api_crear_incidencia(usuario_actual):
    """Reportar una incidencia de servicio"""
    data = get_request_data()
    tipo = data.get('tipo') or 'retraso'
    descripcion = (data.get('descripcion') or '').strip()

    if not descripcion:
        return jsonify({'error': 'La descripción de la incidencia es obligatoria'}), 400

    solicitud_id = data.get('solicitud_id')
    if solicitud_id and not Solicitud.query.get(solicitud_id):
        return jsonify({'error': f'La solicitud {solicitud_id} no existe'}), 404

    item = Incidencia(
        usuario_id=usuario_actual.usuario_id,
        solicitud_id=solicitud_id,
        soporte_id=data.get('soporte_id'),
        tipo=tipo,
        descripcion=descripcion,
        estado='abierto'
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(item.to_dict()), 201

@app.route('/api/incidencias/mis_incidencias', methods=['GET'])
@token_requerido
def api_mis_incidencias(usuario_actual):
    """Consultar las incidencias reportadas por el usuario"""
    items = Incidencia.query.filter_by(usuario_id=usuario_actual.usuario_id).all()
    return jsonify([i.to_dict() for i in items]), 200


# --- API REGISTROS ---
@app.route('/api/registros', methods=['GET'])
def api_listar_registros():
    """Listar registros generales"""
    items = Registro.query.all()
    return jsonify([r.to_dict() for r in items]), 200


# ==========================================
# RUTAS WEB (PANEL HTML ANTERIOR)
# ==========================================

@app.route('/')
def index():
    return redirect(url_for('listar_usuarios'))

@app.route('/usuarios')
def listar_usuarios():
    registros = Usuario.query.all()
    return render_template('usuarios.html', lista=registros)

@app.route('/usuarios/crear', methods=['POST'])
def crear_usuario():
    pwd = request.form.get('password_hash') or '123456'
    correo = request.form.get('correo') or f"user_{datetime.utcnow().timestamp()}@example.com"
    nombre = request.form.get('nombre') or 'Usuario'
    item = Usuario(
        nombre=nombre,
        correo=correo,
        telefono=request.form.get('telefono'),
        password_hash=generate_password_hash(pwd, method='pbkdf2:sha256'),
        rol=request.form.get('rol', 'CLIENTE'),
        foto_perfil=request.form.get('foto_perfil'),
        estado_cuenta=request.form.get('estado_cuenta', 'ACTIVA')
    )
    db.session.add(item)
    db.session.commit()
    flash('Usuario registrado exitosamente')
    return redirect(url_for('listar_usuarios'))

@app.route('/usuarios/eliminar/<int:id>')
def eliminar_usuario(id):
    item = Usuario.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Usuario eliminado')
    return redirect(url_for('listar_usuarios'))

@app.route('/billeteras')
def listar_billeteras():
    registros = Billetera.query.all()
    return render_template('billeteras.html', lista=registros)

@app.route('/billeteras/crear', methods=['POST'])
def crear_billetera():
    item = Billetera(
        usuario_id=request.form.get('usuario_id'),
        saldo=request.form.get('saldo') or 0.0,
        moneda=request.form.get('moneda', 'USD'),
        estado=request.form.get('estado', 'activo')
    )
    db.session.add(item)
    db.session.commit()
    flash('Billetera guardada')
    return redirect(url_for('listar_billeteras'))

@app.route('/billeteras/eliminar/<int:id>')
def eliminar_billetera(id):
    item = Billetera.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Billetera eliminada')
    return redirect(url_for('listar_billeteras'))

@app.route('/categorias')
def listar_categorias():
    registros = Categoria.query.all()
    return render_template('categorias.html', lista=registros)

@app.route('/categorias/crear', methods=['POST'])
def crear_categoria():
    item = Categoria(
        nombre=request.form.get('nombre'),
        descripcion=request.form.get('descripcion'),
        icono=request.form.get('icono'),
        activo=True if request.form.get('activo') == 'on' else False
    )
    db.session.add(item)
    db.session.commit()
    flash('Categoría creada')
    return redirect(url_for('listar_categorias'))

@app.route('/categorias/eliminar/<int:id>')
def eliminar_categoria(id):
    item = Categoria.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Categoría eliminada')
    return redirect(url_for('listar_categorias'))

@app.route('/colaborador_categoria')
def listar_colaborador_categoria():
    registros = ColaboradorCategoria.query.all()
    return render_template('colaborador_categoria.html', lista=registros)

@app.route('/colaborador_categoria/crear', methods=['POST'])
def crear_colaborador_categoria():
    item = ColaboradorCategoria(
        perfil_id=request.form.get('perfil_id'),
        categoria_id=request.form.get('categoria_id')
    )
    db.session.add(item)
    db.session.commit()
    flash('Asociación guardada')
    return redirect(url_for('listar_colaborador_categoria'))

@app.route('/colaborador_categoria/eliminar/<int:perfil_id>/<int:categoria_id>')
def eliminar_colaborador_categoria(perfil_id, categoria_id):
    item = ColaboradorCategoria.query.get_or_404((perfil_id, categoria_id))
    db.session.delete(item)
    db.session.commit()
    flash('Asociación eliminada')
    return redirect(url_for('listar_colaborador_categoria'))

@app.route('/incidencias')
def listar_incidencias():
    registros = Incidencia.query.all()
    return render_template('incidencias.html', lista=registros)

@app.route('/incidencias/crear', methods=['POST'])
def crear_incidencia():
    item = Incidencia(
        usuario_id=request.form.get('usuario_id'),
        solicitud_id=request.form.get('solicitud_id'),
        soporte_id=request.form.get('soporte_id'),
        tipo=request.form.get('tipo'),
        descripcion=request.form.get('descripcion'),
        estado=request.form.get('estado')
    )
    db.session.add(item)
    db.session.commit()
    flash('Incidencia registrada')
    return redirect(url_for('listar_incidencias'))

@app.route('/incidencias/eliminar/<int:id>')
def eliminar_incidencia(id):
    item = Incidencia.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Incidencia eliminada')
    return redirect(url_for('listar_incidencias'))

@app.route('/mensajes')
def listar_mensajes():
    registros = Mensaje.query.all()
    return render_template('mensajes.html', lista=registros)

@app.route('/mensajes/crear', methods=['POST'])
def crear_mensaje():
    item = Mensaje(
        solicitud_id=request.form.get('solicitud_id'),
        emisor_id=request.form.get('emisor_id'),
        receptor_id=request.form.get('receptor_id'),
        tipo=request.form.get('tipo'),
        contenido=request.form.get('contenido'),
        archivo_url=request.form.get('archivo_url'),
        leido=True if request.form.get('leido') == 'on' else False
    )
    db.session.add(item)
    db.session.commit()
    flash('Mensaje guardado')
    return redirect(url_for('listar_mensajes'))

@app.route('/mensajes/eliminar/<int:id>')
def eliminar_mensaje(id):
    item = Mensaje.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Mensaje eliminado')
    return redirect(url_for('listar_mensajes'))

@app.route('/movimientos')
def listar_movimientos():
    registros = Movimiento.query.all()
    return render_template('movimientos.html', lista=registros)

@app.route('/movimientos/crear', methods=['POST'])
def crear_movimiento():
    monto = float(request.form.get('monto') or 0.0)
    comision = float(request.form.get('comision') or 0.0)
    billetera_id = request.form.get('billetera_id')
    if not billetera_id:
        b = Billetera.query.filter_by(usuario_id=request.form.get('usuario_id')).first()
        billetera_id = b.billetera_id if b else 1

    item = Movimiento(
        billetera_id=billetera_id,
        usuario_id=request.form.get('usuario_id'),
        solicitud_id=request.form.get('solicitud_id'),
        tipo=request.form.get('tipo'),
        monto=monto,
        comision=comision,
        monto_neto=monto - comision,
        estado=request.form.get('estado', 'completado')
    )
    db.session.add(item)
    db.session.commit()
    flash('Movimiento registrado')
    return redirect(url_for('listar_movimientos'))

@app.route('/movimientos/eliminar/<int:id>')
def eliminar_movimiento(id):
    item = Movimiento.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Movimiento eliminado')
    return redirect(url_for('listar_movimientos'))

@app.route('/perfiles_colaborador')
def listar_perfiles_colaborador():
    registros = PerfilColaborador.query.all()
    return render_template('perfiles_colaborador.html', lista=registros)

@app.route('/perfiles_colaborador/crear', methods=['POST'])
def crear_perfil_colaborador():
    item = PerfilColaborador(
        usuario_id=request.form.get('usuario_id'),
        descripcion=request.form.get('descripcion'),
        experiencia_anios=int(request.form.get('experiencia_anios') or 0),
        zona=request.form.get('zona'),
        disponible=True if request.form.get('disponible') == 'on' else False,
        identidad_verificada=True if request.form.get('identidad_verificada') == 'on' else False,
        calificacion_promedio=request.form.get('calificacion_promedio') or 0.0,
        trabajos_realizados=int(request.form.get('trabajos_realizados') or 0)
    )
    db.session.add(item)
    db.session.commit()
    flash('Perfil guardado')
    return redirect(url_for('listar_perfiles_colaborador'))

@app.route('/perfiles_colaborador/eliminar/<int:id>')
def eliminar_perfil_colaborador(id):
    item = PerfilColaborador.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Perfil eliminado')
    return redirect(url_for('listar_perfiles_colaborador'))

@app.route('/registros')
def listar_registros():
    registros = Registro.query.all()
    return render_template('registros.html', lista=registros)

@app.route('/registros/crear', methods=['POST'])
def crear_registro():
    item = Registro(
        titulo=request.form.get('titulo'),
        descripcion=request.form.get('descripcion')
    )
    db.session.add(item)
    db.session.commit()
    flash('Registro guardado')
    return redirect(url_for('listar_registros'))

@app.route('/registros/eliminar/<int:id>')
def eliminar_registro(id):
    item = Registro.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Registro eliminado')
    return redirect(url_for('listar_registros'))

@app.route('/resenas')
def listar_resenas():
    registros = Resena.query.all()
    return render_template('resenas.html', lista=registros)

@app.route('/resenas/crear', methods=['POST'])
def crear_resena():
    item = Resena(
        solicitud_id=request.form.get('solicitud_id'),
        cliente_id=request.form.get('cliente_id'),
        colaborador_id=request.form.get('colaborador_id'),
        calificacion=int(request.form.get('calificacion') or 5),
        comentario=request.form.get('comentario')
    )
    db.session.add(item)
    db.session.commit()
    flash('Reseña agregada')
    return redirect(url_for('listar_resenas'))

@app.route('/resenas/eliminar/<int:id>')
def eliminar_resena(id):
    item = Resena.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Reseña eliminada')
    return redirect(url_for('listar_resenas'))

@app.route('/solicitudes')
def listar_solicitudes():
    registros = Solicitud.query.all()
    return render_template('solicitudes.html', lista=registros)

@app.route('/solicitudes/crear', methods=['POST'])
def crear_solicitud():
    f_serv = request.form.get('fecha_servicio')
    h_serv = request.form.get('hora_servicio')
    
    item = Solicitud(
        cliente_id=request.form.get('cliente_id'),
        colaborador_id=request.form.get('colaborador_id'),
        categoria_id=request.form.get('categoria_id'),
        titulo=request.form.get('titulo'),
        descripcion=request.form.get('descripcion'),
        direccion=request.form.get('direccion'),
        fecha_servicio=parse_date(f_serv),
        hora_servicio=parse_time(h_serv),
        estado=request.form.get('estado', 'PENDIENTE')
    )
    db.session.add(item)
    db.session.commit()
    flash('Solicitud guardada')
    return redirect(url_for('listar_solicitudes'))

@app.route('/solicitudes/eliminar/<int:id>')
def eliminar_solicitud(id):
    item = Solicitud.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash('Solicitud eliminada')
    return redirect(url_for('listar_solicitudes'))


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    app.run(debug=debug, host='0.0.0.0', port=port)
