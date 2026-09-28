# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** Marcos García Arroyo
- **Repositorio:** https://github.com/marcosgaarciiia/reportaudit-lab
- **Sistema operativo y versión de Python usados:** Ubuntu 24.04.5 LTS (WSL2) + Python 3.12.3 (venv)

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | `buscar_reportes_cliente` | `app/reporte_auditoria.py:41-42` | Inyección SQL: concatena el nombre del cliente en el SQL. Síntoma verificado: `o'brien_ltd` → `sqlite3.OperationalError: near "brien_ltd": syntax error` + HTTP 500 | `request.args.get("cliente")` en `app/servicio.py:41` → parámetro `nombre_cliente` | `cursor.execute(query)` con `query = "...'" + nombre_cliente + "'"` |
| 2 | `convertir_a_pdf` | `app/reporte_auditoria.py:50-51` | Inyección de comandos OS: concatena `nombre_archivo` en shell (`;`, `&`, `$( )` se ejecutarían). Llamada sin validación ni allow-list | `request.args.get("archivo")` en `app/servicio.py:53` → parámetro `nombre_archivo` | `os.system(comando)` con `comando = "wkhtmltopdf " + nombre_archivo + ...` |
| 3 | `cargar_configuracion` | `app/reporte_auditoria.py:33` | Deserialización YAML insegura: `yaml.load(f, Loader=yaml.Loader)` (Loader completo, no `safe_load`) permite construir objetos arbitrarios | `Path(__file__).with_name("config.yaml")` leído en `app/servicio.py:22-23` → `ruta_config` | `yaml.load(..., Loader=yaml.Loader)` |
| 4 | `hash_password_legacy` | `app/reporte_auditoria.py:55-57` | Hash criptográficamente roto y sin sal: `hashlib.md5` (colisiones, rainbow tables, GPU). No apto para contraseñas | `password` (sistema legado de clientes) | `hashlib.md5(password.encode()).hexdigest()` |
| 5 | Constantes `NOTIFICATION_API_KEY` / `SMTP_PASSWORD` | `app/reporte_auditoria.py:21-22` | Secretos hardcoded en el repo: API key de notificaciones y contraseña SMTP en claro. Quedan en historial Git aunque se borren | Código fuente versionado (todo clon lo recibe) | Uso en `notificar_cliente` (`NOTIFICATION_API_KEY[:6]`) / envío SMTP |

**Impacto en el negocio:** para cada sospecha, explica en una frase qué
consecuencia tendría para ReportAudit y sus clientes si fuera real (qué datos,
qué sistema o qué credencial quedarían expuestos).
- 1 SQLi: exfiltración/modificación/borrado de `reportes.db` (montos y clientes de auditoría) y bypass de filtro por cliente.
- 2 CMDi: ejecución remota de comandos en el servidor con el usuario del servicio (lectura de ficheros, pivot, destrucción de PDFs/reportes).
- 3 YAML: RCE/deserialización al cargar un `config.yaml` manipulado (toma del host donde corre el servicio).
- 4 MD5: recuperación masiva de contraseñas de clientes legacy por fuerza bruta/diccionario.
- 5 Secretos: suplantación del servicio de avisos y de la cuenta SMTP (spam/phishing a clientes, coste y pérdida de confianza); rotar y sacar a gestor de secretos/`.env`.

---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` |  |  |  |  |  |  | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` |  |  |  |  |  |  | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` |  |  |  |  |  |  | n/a |
| H4 Hash MD5 en `hash_password_legacy` |  |  |  |  |  |  | n/a |
| H5 Clave de API escrita en el código |  |  |  |  |  |  |  |
| H6 Contraseña SMTP escrita en el código |  |  |  |  |  |  |  |

**Conclusión de la matriz** (Parte K): ¿alguna herramienta lo detectó todo? ¿Qué
te dice eso sobre depender de una sola herramienta?

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) |  |
| Componentes Python en el SBOM |  |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen |  |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) |  |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |  |

**Comparación con Dependabot** (Parte H): ¿las alertas coinciden con Grype? Explica
cualquier diferencia.

**Documento VEX:** copia `plantillas/reportaudit.openvex.json` a
`docs/evidencias/`, rellénalo, enlázalo aquí y resume en una frase la
justificación.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` |  |  |
| Alertas abiertas de CodeQL (Security → Code scanning) |  |  |
| Vulnerabilidades en SonarQube Cloud (rama main) |  |  |
| Security Hotspots por revisar en SonarQube Cloud |  |  |
| Vulnerabilidades de Grype sobre el SBOM |  |  |
| Alertas abiertas de Dependabot |  |  |

---

## Preguntas de comprobación (Sección 7 de la guía)

1.
2.
3.
4.
5.
6.
7.
8.
9.
10.
11.
12.
