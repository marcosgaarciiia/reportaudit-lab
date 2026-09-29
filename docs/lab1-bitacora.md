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
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ (Parte B, síntoma `o'brien_ltd` → 500) | pendiente de anotar por ti en VS Code (Parte E.1) | pendiente de anotar por ti tras vincular (F.6) | ✓ `pythonsecurity:S3649` en `app/reporte_auditoria.py:42` | ✓ `py/sql-injection` en `app/reporte_auditoria.py:42` (error) | pendiente Parte H | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ (Parte B) | pendiente de anotar por ti | pendiente de anotar por ti | ✓ `pythonsecurity:S2076` en `app/reporte_auditoria.py:51` | ✓ `py/command-line-injection` en `app/reporte_auditoria.py:51` (error) | pendiente Parte H | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ (Parte B, `yaml.Loader` completo) | pendiente de anotar por ti | pendiente de anotar por ti | ✗ (sin issue en `app/reporte_auditoria.py:33` en el análisis de `main` del 29-09) | ✗ (sin alerta CodeQL; 4 alertas totales y ninguna en línea 33) | pendiente Parte H | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ (Parte B) | pendiente de anotar por ti | pendiente de anotar por ti | ✓ `python:S4790` en `app/reporte_auditoria.py:57` (CRITICAL) | ✓ `py/weak-sensitive-data-hashing` en `app/reporte_auditoria.py:57` (warning) | pendiente Parte H | n/a |
| H5 Clave de API escrita en el código | ✓ (Parte B, `NOTIFICATION_API_KEY` línea 21) | pendiente de anotar por ti | pendiente de anotar por ti | ✗ directo en línea 21 (solo hay hallazgos en línea 22); indirecto: `py/clear-text-logging-sensitive-data` en línea 62 (CodeQL) | ✗ como secreto; indirecto ✓ `py/clear-text-logging-sensitive-data` en `app/reporte_auditoria.py:62` (usa la clave en `print`) | pendiente Parte H | pendiente Parte K |
| H6 Contraseña SMTP escrita en el código | ✓ (Parte B, `SMTP_PASSWORD` línea 22) | pendiente de anotar por ti | pendiente de anotar por ti | ✓ `python:S2068` (MAJOR) + `secrets:S7552` (BLOCKER) en `app/reporte_auditoria.py:22` | ✗ como secreto (misma nota indirecta línea 62 que H5) | pendiente Parte H | pendiente Parte K |

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
| Hallazgos de Semgrep en `app/` | pendiente Parte H |  |
| Alertas abiertas de CodeQL (Security → Code scanning) | 4 (29-09-2026, rama `main` tras PR #1): `py/sql-injection:42`, `py/command-line-injection:51`, `py/weak-sensitive-data-hashing:57`, `py/clear-text-logging-sensitive-data:62` |  |
| Vulnerabilidades en SonarQube Cloud (rama main) | 6 (29-09-2026): `python:S2068:22`, `secrets:S7552:22`, `pythonsecurity:S3649:42`, `pythonsecurity:S2076:51`, `python:S4790:57`, `python:S4502:app/servicio.py:25` |  |
| Security Hotspots por revisar en SonarQube Cloud | 0 (API `hotspots/search`, 29-09-2026) |  |
| Vulnerabilidades de Grype sobre el SBOM | pendiente Parte J/K |  |
| Alertas abiertas de Dependabot | pendiente Parte I (secret `SONAR_TOKEN` ya en Actions y Dependabot) |  |

### Evidencias Partes E–G (trazabilidad)
- PR #1 `ci(seguridad): activar pipeline SonarQube + CodeQL`: https://github.com/marcosgaarciiia/reportaudit-lab/pull/1 (squash `f7c2737`, 4 checks verdes).
- Run de `push` a `main` tras el merge: `36589995957` (success).
- Protección de `main`: requiere PR + 1 aprobación + checks `SAST - SonarQube Cloud` y `SAST - CodeQL` (`enforce_admins: true`).
- SonarCloud: proyecto `marcosgaarciiia_reportaudit-lab`, org `marcosgaarciiia`, `Automatic Analysis` desactivado, análisis vía `SonarSource/sonarqube-scan-action@v7`.
- Token `reportaudit-ci` original expuesto en chat → revocado por ti el 29-09; secreto `SONAR_TOKEN` rotado en Actions y Dependabot (verificado con `gh api .../actions/secrets` y `.../dependabot/secrets`).
- Nota: `python:S4502` en `app/servicio.py:25` (CSRF) es un hallazgo del framework, fuera de H1–H6; se valorará en la Parte M si se corrige o se justifica.

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
