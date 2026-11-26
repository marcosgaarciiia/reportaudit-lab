"""
ReportAudit — lógica de negocio del servicio de reportes de auditoría.

Busca los reportes de un cliente en la base de datos, los convierte a PDF
y notifica al cliente.

Auditoría de seguridad (Laboratorio 1, Parte M): se corrigen la inyección
SQL, la inyección de comandos, la deserialización YAML insegura, el hash
débil de contraseñas y las credenciales escritas en el código.
"""

import hashlib
import os
import re
import sqlite3
import subprocess

import yaml

# Las credenciales NO viven en el código: se leen del entorno (o de un gestor
# de secretos). Las que estuvieron escritas aquí se consideran comprometidas
# y se han rotado en sus proveedores.
NOTIFICATION_API_KEY = os.environ.get("REPORTAUDIT_NOTIFICATION_API_KEY", "")
SMTP_PASSWORD = os.environ.get("REPORTAUDIT_SMTP_PASSWORD", "")

RUTA_DB = os.path.join(os.path.dirname(__file__), "..", "reportes.db")

# Lista blanca de nombres de archivo: letras, dígitos, "_", "." y "-",
# sin empezar por "-" (no puede confundirse con una opción), sin "/" (no
# permite salir de la carpeta de reportes) y acabado en .html.
NOMBRE_HTML_VALIDO = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\.html$")

# Recomendación OWASP (2023) para PBKDF2-HMAC-SHA256.
ITERACIONES_PBKDF2 = 600_000


def cargar_configuracion(ruta_config):
    """Carga la configuración del servicio desde un archivo YAML."""
    with open(ruta_config, "r", encoding="utf-8") as f:
        # safe_load solo construye datos (dict, list, str, int...), nunca
        # objetos de Python: un YAML manipulado no puede ejecutar código.
        config = yaml.safe_load(f)
    return config


def buscar_reportes_cliente(nombre_cliente, ruta_db=RUTA_DB):
    """Devuelve todos los reportes asociados a un cliente."""
    conexion = sqlite3.connect(ruta_db)
    try:
        cursor = conexion.cursor()
        # Consulta parametrizada: el driver envía la orden y el dato por
        # separado, así que el dato nunca se interpreta como SQL.
        query = "SELECT * FROM reportes WHERE cliente = ?"
        cursor.execute(query, (nombre_cliente,))
        return cursor.fetchall()
    finally:
        conexion.close()


def convertir_a_pdf(nombre_archivo):
    """Convierte un reporte HTML a PDF usando la utilidad del sistema."""
    if not NOMBRE_HTML_VALIDO.fullmatch(nombre_archivo):
        raise ValueError("Nombre de archivo no válido")
    salida = nombre_archivo + ".pdf"
    try:
        # Lista de argumentos y sin shell: cada elemento llega a wkhtmltopdf
        # como un argumento literal; ";", "&" o "|" no se interpretan.
        subprocess.run(["wkhtmltopdf", nombre_archivo, salida], check=False)
    except FileNotFoundError:
        print("Aviso: wkhtmltopdf no está instalado; no se generó el PDF.")
    return salida


def hash_password_legacy(password):
    """Genera el hash de una contraseña con PBKDF2-HMAC-SHA256 y sal aleatoria.

    Devuelve "sal_hex:derivado_hex". La sal aleatoria hace que dos
    contraseñas iguales produzcan hashes distintos, y las iteraciones
    encarecen los ataques de fuerza bruta.
    """
    sal = os.urandom(16)
    derivado = hashlib.pbkdf2_hmac("sha256", password.encode(), sal, ITERACIONES_PBKDF2)
    return sal.hex() + ":" + derivado.hex()


def notificar_cliente(email, mensaje):
    """Envía una notificación al cliente usando el servicio externo."""
    # Nunca se escribe una credencial en un log, ni siquiera parcialmente.
    estado_clave = "configurada" if NOTIFICATION_API_KEY else "NO configurada"
    print(f"[NotifyAPI clave {estado_clave}] -> {email}: {mensaje}")
    return bool(NOTIFICATION_API_KEY)
