# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** Marcos García Arroyo
- **Repositorio:** https://github.com/marcosgaarciiia/reportaudit-lab
- **Compañero revisor:** Tonsete (https://github.com/Tonsete)
- **Sistema operativo y versión de Python usados:** Ubuntu 24.04.5 LTS (WSL2) + Python 3.12.3 (venv) · VS Code conectado a WSL: Ubuntu-24.04
- **SonarQube Cloud:** Organization Key `marcosgaarciiia` · Project Key `marcosgaarciiia_reportaudit-lab`

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

> Nota: las credenciales encontradas se describen por archivo, línea y tipo. Su valor **nunca** se reproduce en esta bitácora: se muestra como `[REDACTED]`.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)

Recorrido de los datos: en `app/servicio.py` entran dos parámetros de la URL, `cliente` (`request.args.get("cliente")`, línea 41) y `archivo` (`request.args.get("archivo")`, línea 53), y se pasan sin filtrar a `reporte_auditoria.py`.

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | `buscar_reportes_cliente` | 41–42 | **Inyección SQL (CWE-89)**: el nombre del cliente se concatena dentro del texto de la consulta | `request.args["cliente"]` (`servicio.py:41`) → `nombre_cliente` | `cursor.execute(query)` (`reporte_auditoria.py:42`) |
| 2 | `convertir_a_pdf` | 50–51 | **Inyección de comandos del SO (CWE-78)**: el nombre de archivo se pega en una orden que ejecuta la shell; `;`, `&`, `|` o `$( )` encadenan órdenes | `request.args["archivo"]` (`servicio.py:53`) → `nombre_archivo` | `os.system(comando)` (`reporte_auditoria.py:51`) |
| 3 | `cargar_configuracion` | 33 | **Deserialización insegura (CWE-502)**: `yaml.load` con el `Loader` completo puede construir objetos Python arbitrarios (`!!python/object/apply:os.system`) | El archivo `config.yaml` (quien pueda modificarlo: despliegue, volumen compartido, PR malicioso) | `yaml.load(f, Loader=yaml.Loader)` (`reporte_auditoria.py:33`) |
| 4 | `hash_password_legacy` | 57 | **Hash débil de contraseñas (CWE-327/CWE-916/CWE-759)**: MD5, sin sal y en una sola pasada | El parámetro `password` | `hashlib.md5(password.encode()).hexdigest()` (`reporte_auditoria.py:57`) |
| 5 | Constantes del módulo (+ `notificar_cliente`) | 21–22 (y 62) | **Secretos escritos en el código (CWE-798)**: clave de la API de notificaciones (`NOTIFICATION_API_KEY = "[REDACTED]"`) y contraseña SMTP (`SMTP_PASSWORD = "[REDACTED]"`); además `notificar_cliente` imprime los 6 primeros caracteres de la clave en el log (CWE-532) | El propio código fuente (y el historial de Git) | Cualquiera que lea el repositorio, sus clones o los logs |

**Síntoma observado (Paso C.2):** `GET /reportes?cliente=o'brien_ltd` → **500 Internal Server Error**; en la terminal del servicio: `sqlite3.OperationalError: near "brien_ltd": syntax error` (traza en `reporte_auditoria.py`, línea 42). El apóstrofo del nombre cierra antes de tiempo la cadena SQL y el resto (`brien_ltd'`) se interpreta como parte de la orden. Comprobación adicional en mi propio servicio local: `cliente=x' OR '1'='1` devolvió **los 5 reportes de los 4 clientes**, y `archivo=informe.html;echo COMANDO-INYECTADO-EJECUTADO` ejecutó el `echo` en el servidor. Las dos inyecciones son reales, no teóricas.

**Impacto en el negocio:**

1. **Inyección SQL:** cualquier usuario de la API interna puede leer los reportes de auditoría de **todos** los clientes (montos, nombres), lo que rompe la confidencialidad pactada con ellos (RGPD y contratos); con otras consultas podría enumerar tablas o, en un motor con más privilegios, modificar datos.
2. **Inyección de comandos:** ejecución remota de código con los permisos del servicio: robo de `reportes.db` y de las credenciales del entorno, instalación de malware, uso del servidor como pivote en la red interna. Es el hallazgo más grave.
3. **YAML inseguro:** quien consiga modificar `config.yaml` (un despliegue comprometido o un PR no revisado) obtiene ejecución de código al arrancar el servicio.
4. **MD5 sin sal:** si se filtra la tabla de contraseñas del sistema legado, se recuperan en minutos con tablas *rainbow* o GPU; y contraseñas iguales dan el mismo hash, así que se reutilizan en otros servicios de los clientes.
5. **Secretos en el código:** cualquiera con acceso al repositorio (o a un clon antiguo) puede enviar notificaciones haciéndose pasar por la empresa (phishing a clientes) y usar el buzón SMTP; además la clave aparece parcialmente en los logs. Como están en el historial, hay que **rotarlas**: borrarlas del código no basta.

---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ (síntoma `o'brien_ltd` → 500) | ✗ (sin conexión no lo marca) | ✓ (aparece al vincular: *taint analysis* del servidor) | ✓ `pythonsecurity:S3649` en `app/reporte_auditoria.py:42` | ✓ `py/sql-injection` en `app/reporte_auditoria.py:42` (error) | ✗ (ninguna regla de `p/python` lo marca) | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ | ✗ (sin conexión no lo marca) | ✓ (aparece al vincular: *taint analysis* del servidor) | ✓ `pythonsecurity:S2076` en `app/reporte_auditoria.py:51` | ✓ `py/command-line-injection` en `app/reporte_auditoria.py:51` (error) | ✗ | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ (`yaml.Loader` completo) | ✗ | ✗ (ni conectado lo marca) | ✗ (ningún issue en la línea 33) | ✗ (ninguna alerta en la línea 33: el YAML viene de un archivo, no de la petición, y CodeQL solo lo marca si el dato es controlado por el usuario) | ✓ `python.lang.security.deserialization.avoid-pyyaml-load` (línea 33) | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ | ✓ | ✓ (se mantiene) | ✓ `python:S4790` en `app/reporte_auditoria.py:57` (CRITICAL) | ✓ `py/weak-sensitive-data-hashing` en `app/reporte_auditoria.py:57` (warning) | ✓ `insecure-hash-algorithm-md5` + `md5-used-as-password` (línea 57) | n/a |
| H5 Clave de API escrita en el código | ✓ (`NOTIFICATION_API_KEY`, línea 21) | ✗ | ✗ | ✗ en la línea 21 (el nombre no contiene «password» y el valor no tiene formato de proveedor) | ✗ como secreto; indirecto: `py/clear-text-logging-sensitive-data` en `app/reporte_auditoria.py:62` (la clave acaba en un `print`) | ✗ (`p/secrets` no la reconoce: no tiene formato de proveedor) | ✗ (`trivy fs --scanners vuln,secret`: ningún secreto; solo formatos de proveedores conocidos) |
| H6 Contraseña SMTP escrita en el código | ✓ (`SMTP_PASSWORD`, línea 22) | ✓ | ✓ (se mantiene) | ✓ `python:S2068` (MAJOR) + `secrets:S7552` (BLOCKER) en `app/reporte_auditoria.py:22` | ✗ | ✗ | ✗ (`trivy fs --scanners vuln,secret`: ningún secreto; solo formatos de proveedores conocidos) |
| *(extra)* Clave en el historial de Git | ✓ | n/a | n/a | n/a | n/a | n/a | n/a — Gitleaks (Parte O): reglas por defecto solo H5; regla propia H5 y H6 |

**Conclusión de la matriz** (Parte K): **ninguna herramienta lo detectó todo.** CodeQL y SonarQube Cloud encontraron las inyecciones (H1, H2) siguiendo el dato de `servicio.py` a `reporte_auditoria.py` (*taint analysis*, que el editor sin conexión no hace), pero ninguno marcó el YAML inseguro (H3), porque el YAML viene de un archivo y no de la petición. Semgrep fue el único que marcó H3, pero no vio ni las inyecciones ni los secretos con `p/python` + `p/secrets`. La contraseña SMTP (H6) la vio SonarQube por el nombre de la variable; la clave de API (H5) no la marcó ninguna herramienta SAST como secreto (CodeQL solo vio que acababa en un log) y Trivy no detectó ningún secreto. Solo la revisión manual encontró los seis. Depender de una sola herramienta habría dejado fuera al menos dos hallazgos: hacen falta varias capas y el criterio humano.

### Evidencias Partes E–G (trazabilidad)

- PR #1 `ci(seguridad): activar pipeline SonarQube + CodeQL`: https://github.com/marcosgaarciiia/reportaudit-lab/pull/1 (squash `f7c2737`, checks en verde). Se fusionó antes de existir la plantilla internacional y el backlog de Issues (versión anterior de la guía); el Issue «Run SAST…» se cierra a mano enlazando este PR.
- Primer análisis de `main` tras la fusión: ejecución de Actions `36589995957` (success).
- Protección de `main`: PR obligatorio + 1 aprobación + checks `SAST - SonarQube Cloud` y `SAST - CodeQL` (también para administradores).
- SonarQube Cloud: organización `marcosgaarciiia`, proyecto `marcosgaarciiia_reportaudit-lab`, *Automatic Analysis* desactivado, análisis con `SonarSource/sonarqube-scan-action@v7`. Editor en Connected Mode (`.vscode/settings.json`).
- Token: el primer `reportaudit-ci` quedó expuesto en un chat → **revocado** el 29-09 y `SONAR_TOKEN` rotado en los secretos de Actions y de Dependabot. Mismo principio que con las credenciales de ReportAudit: lo expuesto se rota.
- `python:S4502` (protección CSRF desactivada en `app/servicio.py:25`) queda fuera de H1–H6: se valora en la Parte M.

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | **2** — `flask==3.0.0` y `pyyaml==6.0.3` |
| Componentes Python en el SBOM | **9** (`pkg:pypi/…`; tras el PR #24 son 8: `colorama` desaparece porque `pip-compile` regeneró el lockfile en Linux y su marcador `platform_system == "Windows"` ya no la incluye): blinker 1.7.0, click 8.1.7, colorama 0.4.6, flask 3.0.0, itsdangerous 2.1.2, jinja2 3.1.2, markupsafe 3.0.3, pyyaml 6.0.3, werkzeug 3.0.1 → **7 transitivas** por cada 2 directas (×4,5) |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen | **4 de tipo `github-action`**: `actions/checkout@v6`, `SonarSource/sonarqube-scan-action@v7`, `github/codeql-action/init@v4` y `github/codeql-action/analyze@v4`. Syft los saca de `.github/workflows/cadena-suministro.yml`: las acciones también son código de terceros que se ejecuta en mi pipeline (recordar el caso Trivy 2026). Aparecen además 2 componentes `file` (los manifiestos analizados). |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) | `CycloneDX`, `specVersion` **1.7** (Syft 1.52.0) |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

13 avisos en 3 paquetes: **Grype** sobre el SBOM (`docs/evidencias/grype-antes.txt`: 1 High, 11 Medium, 1 Low), confirmados uno a uno por **Trivy** (`trivy-antes.txt`, mismo total y mismas versiones corregidas) y por `pip-audit`. Directa/transitiva según el `# via` de `requirements.txt`. Grype los identifica por GHSA; la tabla da también el CVE equivalente.

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-34069 / GHSA-2g68-c3qc-8985 | High | 3.0.3 | **No**: solo afecta al depurador interactivo de Werkzeug y el servicio arranca con `debug=False` (`servicio.py:64`); no hay `DebuggedApplication` | **VEX `not_affected`** + actualizar con el PR de Dependabot |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-49767 / GHSA-q34m-jh98-gwm2 | Medium | 3.0.6 | No: el agotamiento ocurre al parsear `multipart/form-data`, y Werkzeug solo parsea el cuerpo cuando se accede a `request.form`/`request.files`; ReportAudit solo lee `request.args` (`servicio.py:41` y `:53`) | Actualizar (PR de Dependabot) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-49766 / GHSA-f9vj-2wh5-fj8j | Medium | 3.0.6 | No: `safe_join` en Windows con Python < 3.11; ReportAudit no usa `safe_join` ni `send_from_directory` y corre en Linux con 3.12 | Actualizar (coste bajo) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2025-66221 / GHSA-hgf8-39gv-g3f2 | Medium | 3.1.4 | No: nombres de dispositivo de Windows en `safe_join`; no se usa y no corre en Windows | Actualizar |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2026-21860 / GHSA-87hc-h4r5-73f7 | Medium | 3.1.5 | No: misma familia (`safe_join` en Windows) | Actualizar |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2026-27199 / GHSA-29vq-49wr-vm6x | Medium | 3.1.6 | No: misma familia (`safe_join` en Windows) | Actualizar |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2026-102598 / GHSA-g6x2-hccm-hh4m | Medium | 3.1.9 | No: misma familia (`safe_join` + marcador ADS de NTFS) | Actualizar |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-56326 / GHSA-q2x7-8rv6-6q7h | Medium | 3.1.5 | No: escape del *sandbox* de plantillas; ReportAudit no renderiza plantillas, responde con `jsonify` | Actualizar (PR de Dependabot) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-56201 / GHSA-gmj6-6f8f-6699 | Medium | 3.1.5 | No: exige controlar contenido y nombre de una plantilla; no hay plantillas | Actualizar |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2025-27516 / GHSA-cpwx-vrp4-4pq7 | Medium | 3.1.6 | No: escape del *sandbox* vía filtro `attr`; no hay plantillas | Actualizar |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-22195 / GHSA-h5c8-rqwp-cp95 | Medium | 3.1.3 | No: XSS con el filtro `xmlattr`; no se usa | Actualizar |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-34064 / GHSA-h75v-3vvj-5mfj | Medium | 3.1.4 | No: misma familia (`xmlattr`) | Actualizar |
| flask | 3.0.0 | **Directa** (`# via -r requirements.in`) | CVE-2026-27205 / GHSA-68rp-wp8r-4726 | Low | 3.1.3 | No: falta la cabecera `Vary: Cookie` al acceder a `session`; ReportAudit no usa `session` | Actualizar (sube también `requirements.in`) |

**Prioridad (EPSS):** la de mayor probabilidad de explotación según Grype es precisamente GHSA-2g68-c3qc-8985 (EPSS 5,4 %, percentil 93), la del depurador de Werkzeug. El EPSS mide lo atractiva que es en general, no si lo es *en mi contexto*: en ReportAudit no es alcanzable (`debug=False`), y por eso es la que documento con el VEX. Prioridad ≠ explotabilidad.

**Lectura del iceberg:** 12 de los 13 avisos están en dependencias **transitivas** (werkzeug y jinja2 llegan «dentro» de Flask) y el único de una directa es el de menor gravedad. Lo que el equipo eligió conscientemente era casi lo de menos.

**Comparación con Dependabot** (Parte H): **no coinciden, y la diferencia es instructiva.** Con *Dependency graph*, *Dependabot alerts*, *security updates* y *grouped security updates* activados (Settings → Advanced Security) y `dependabot.yml` en `main` (PR #18), el grafo de dependencias sí detectó las 13 dependencias (9 de pip, con su etiqueta *Direct/Transitive*, y 4 acciones), pero en más de una hora **no generó ninguna alerta de pip ni su PR de seguridad**; solo abrió dos PR de *version updates* del ecosistema `github-actions` (#19 y #20). Grype, Trivy y pip-audit, en cambio, encontraron las 13 al momento. Lección: Dependabot es asíncrono y no da garantías de cuándo avisa; una alerta que todavía no ha llegado no significa que no exista vulnerabilidad. Por eso apliqué a mano la misma corrección que habría propuesto (PR #24, `pip-compile`, enlazado al Issue #8) y, en la Parte P, la comprobación se convierte en un check obligatorio (`SCA - pip-audit`) que no depende de que llegue una alerta.

**Documento VEX:** [`docs/evidencias/reportaudit.openvex.json`](evidencias/reportaudit.openvex.json) — declara `CVE-2024-34069` en `pkg:pypi/werkzeug@3.0.1` como `not_affected` con la justificación estándar `vulnerable_code_not_in_execute_path`: la vulnerabilidad está en el depurador interactivo de Werkzeug y ReportAudit lo tiene desactivado (`app.run(..., debug=False)` en `app/servicio.py:64`, sin `DebuggedApplication` en `app/`). Aun así se actualiza, porque la actualización es barata y el VEX no es una excusa para no hacerlo.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | **3** (`avoid-pyyaml-load`:33, `insecure-hash-algorithm-md5`:57, `md5-used-as-password`:57) | **0** (`pre-commit run --all-files` → Passed; el commit del PR #21 lo aceptó el guardián) |
| Alertas abiertas de CodeQL (Security → Code scanning) | **4** (29-09-2026, `main` tras PR #1): `py/sql-injection:42`, `py/command-line-injection:51`, `py/weak-sensitive-data-hashing:57`, `py/clear-text-logging-sensitive-data:62` | **0 abiertas** — las 4 pasan solas a *Closed → fixed* al reanalizar `main` tras el PR #21 |
| Vulnerabilidades en SonarQube Cloud (rama main) | **6** (29-09-2026): `python:S2068:22`, `secrets:S7552:22`, `pythonsecurity:S3649:42`, `pythonsecurity:S2076:51`, `python:S4790:57`, `python:S4502` en `app/servicio.py:25` | **0 abiertas** (Security A). Las 5 de H1–H6 desaparecen con el PR #21; `python:S4502` (CSRF) queda **Accepted** con justificación: solo hay endpoints GET sin estado ni cookies |
| Security Hotspots por revisar en SonarQube Cloud | 0 (29-09-2026) | **0** (el `subprocess.run` con lista y sin shell no genera hotspot) |
| Vulnerabilidades de Grype sobre el SBOM | **13** (1 High, 11 Medium, 1 Low) en werkzeug 3.0.1 (7), jinja2 3.1.2 (5) y flask 3.0.0 (1); Trivy confirma las mismas 13 | **0** (`grype-despues.txt`: *No vulnerabilities found*; Trivy 0; `pip-audit`: *No known vulnerabilities found*) con flask 3.1.3, werkzeug 3.1.9 y jinja2 3.1.6 (PR #24) |
| Alertas abiertas de Dependabot | **0** — Dependabot no llegó a generar ninguna alerta de pip (ver nota abajo) | **0** |

---

## Preguntas de comprobación (Sección 7 de la guía)

1. **Windows, Ubuntu (WSL2) y GitHub.** En Windows viven VS Code (el programa), el navegador, la descarga del zip y el Word de evidencias. En Ubuntu (WSL2) vive todo el proyecto: `~/reportaudit-lab`, Python y su `venv`, Git, pre-commit/Semgrep, Syft, Grype, Trivy, Gitleaks y `reportes.db`; ahí se ejecutan todos los comandos. En GitHub viven la copia pública del repositorio, los Issues y PRs, el pipeline de Actions, los secretos, la protección de `main`, Dependabot, CodeQL y las Releases (y en SonarQube Cloud, el proyecto y su panel). Se trabaja en Ubuntu porque las herramientas y los runners de GitHub Actions son Linux: lo que funciona en mi terminal funciona igual en el pipeline, y toda la clase sigue los mismos pasos sea cual sea su equipo.
2. **Directa vs. transitiva.** Una dependencia directa es la que el equipo eligió y declaró (`requirements.in`): en ReportAudit, `flask` y `pyyaml`, con `# via -r requirements.in`. Una transitiva llega arrastrada por otra sin que nadie la pidiera: `werkzeug 3.0.1` aparece en `sbom.cyclonedx.json` como `pkg:pypi/werkzeug@3.0.1` y en `requirements.txt` con `# via flask`. Dos directas se convierten en 9 componentes Python: el iceberg. Y 12 de las 13 vulnerabilidades estaban en la parte sumergida.
3. **Source y sink.** El *source* es el punto por donde entra un dato controlado por el usuario; el *sink*, el punto donde ese dato puede causar daño si llega sin filtrar. Ejemplo real: `cliente = request.args.get("cliente", "")` en `servicio.py:41` (source) → `buscar_reportes_cliente(cliente)` → concatenación en la `query` → `cursor.execute(query)` en `reporte_auditoria.py:42` (sink). Lo mismo con `archivo` (`servicio.py:53`) → `os.system(comando)` (`reporte_auditoria.py:51`).
4. **El caso `o'brien_ltd`.** La consulta se construía como `"... WHERE cliente = '" + nombre + "'"`. El apóstrofo del nombre cierra la cadena SQL antes de tiempo y `brien_ltd'` queda fuera, como si fuera parte de la orden: SQLite no la entiende y lanza `OperationalError`. Si un dato legítimo puede cambiar la *estructura* de la consulta, un dato malicioso también: con `x' OR '1'='1` obtuve todos los reportes. Esa mezcla de dato y orden es la inyección SQL. Se arregla con una consulta parametrizada (`?`), no prohibiendo apóstrofos.
5. **El hook de Semgrep.** Actúa en mi equipo, *antes* de que el commit exista: el código inseguro no llega a salir de la máquina y el aviso llega en segundos (shift-left). SonarQube Cloud y CodeQL actúan después del push, en el PR. Pero el hook solo no basta: vive en mi copia local (quien no ejecute `pre-commit install` no lo tiene), se puede saltar con `--no-verify` y su conjunto de reglas es limitado. Por eso el pipeline obligatorio en la nube sigue siendo necesario: defensa en profundidad.
6. **Las herramientas no coinciden.** No es un error de ninguna: cada motor razona distinto. CodeQL y SonarQube Cloud siguen el flujo del dato (taint) y por eso ven H1 y H2, pero no H3, porque el YAML no viene del usuario. Semgrep aplica patrones por archivo, y por eso ve `yaml.Loader` y `md5`, pero no las inyecciones con las reglas `p/python`. SonarQube detecta la contraseña por el nombre `PASSWORD` (H6) pero no la clave de API (H5). Trivy y las reglas por defecto de Gitleaks solo reconocen formatos de proveedores, así que no vieron las credenciales (Gitleaks solo vio la clave en el historial, por su entropía). La matriz muestra justo eso: cada herramienta cubre huecos de las otras y ninguna sustituye la auditoría manual.
7. **Por qué un PR no cierra las alertas del otro.** Porque son problemas distintos en sitios distintos. Las alertas de CodeQL (SAST) señalan líneas de *mi* código: se cierran cuando el análisis de `main` deja de encontrarlas, y eso lo consiguió el PR de corrección. Las de Dependabot (SCA) señalan *versiones de librerías* en `requirements.txt`: solo se cierran cuando cambia la versión, y eso lo hizo el PR de Dependabot. Corregir mi código no cambia Werkzeug, y actualizar Werkzeug no arregla mi `os.system`.
8. **Borrar un secreto vs. corregir el problema.** Borrar la línea solo limpia la versión actual: el valor sigue en el historial de Git, en cada clon y en cada fork de un repositorio público, y cualquiera lo ve con `git log -p`. Corregir de verdad es: (1) **rotar** la credencial en el proveedor para que la expuesta deje de servir; (2) sacarla del código a variables de entorno o un gestor de secretos; (3) añadir controles (regla de Gitleaks, push protection) para que no vuelva a entrar.
9. **VEX vs. ignorar la alerta.** Ignorar una alerta no deja rastro: reaparece, nadie recuerda por qué se descartó y se vuelve a descartar por costumbre. Un VEX convierte la decisión en un documento revisable y legible por máquinas: qué vulnerabilidad, qué componente exacto (purl), qué estado, con qué justificación estándar, quién y cuándo. El mío declara `CVE-2024-34069` (`pkg:pypi/werkzeug@3.0.1`) como `not_affected` / `vulnerable_code_not_in_execute_path`, porque afecta al depurador de Werkzeug y ReportAudit arranca con `debug=False` (`servicio.py:64`). Aun así actualicé.
10. **Qué comprueba el instalador.** Que el binario descargado tiene exactamente la huella SHA-256 publicada en el `checksums.txt` de esa versión *fijada* (nunca «la última»), y solo entonces lo extrae a `tools/`. Así detecta descargas corruptas o alteradas por el camino. Lo que no puede garantizar es que la publicación oficial sea legítima: en el caso Trivy de marzo de 2026 los atacantes reescribieron las etiquetas de versión, y una versión maliciosa publicada oficialmente trae una huella oficial que coincide. Contra eso ayudan fijar versiones revisadas y verificar firmas y procedencia (Sigstore).
11. **Gitleaks: código limpio, historial no.** `gitleaks dir app` analiza los archivos tal como están hoy, y el PR de corrección ya leía las credenciales de variables de entorno: limpio. `gitleaks git .` recorre todos los commits, y el commit de importación sigue conteniendo las dos credenciales. Lo que cierra el riesgo es la **rotación** declarada en la Parte M: los valores del historial ya no sirven. La regla propia y la baseline evitan que vuelvan a entrar sin ocultar nada nuevo.
12. **Por qué pip-audit no se exigió en la Parte G.** Porque `main` todavía tenía 13 vulnerabilidades conocidas: con pip-audit obligatorio, ningún PR (ni el de Semgrep, ni el de Dependabot, ni el de corrección) habría podido fusionarse. El *ratchet* (trinquete) consiste en llevar primero el sistema al nivel deseado y después prohibir que retroceda. En mi repositorio: PR + aprobación (G.2) → los dos checks SAST cuando ya existían (G.6) → corrección del código y de las dependencias (M) → pip-audit y Gitleaks obligatorios (P.4). La exigencia solo ha subido.
13. **Alerta de Dependabot vs. check `SCA - pip-audit`.** Una alerta de Dependabot informa y propone un PR, pero no impide fusionar nada: es asíncrona y vive en la pestaña Security. `SCA - pip-audit` es un check obligatorio de la protección de `main`: si un PR introduce o mantiene una dependencia con un aviso conocido, el PR no se puede fusionar (lo comprobé con el PR de prueba de Werkzeug 3.0.1).
14. **`gh attestation verify`.** Demuestra que `reportaudit-1.0.0.tar.gz` lo produjo mi workflow `publicar-version.yml`, desde mi repositorio y desde la etiqueta `v1.0.0`, y que no se ha modificado desde entonces (firma Sigstore con identidad OIDC del workflow y registro de transparencia). No demuestra que el código sea seguro: eso lo garantizan los checks de cada PR y el SBOM. `SHA256SUMS` no basta porque quien pueda sustituir el archivo en la Release o en un espejo también puede sustituir `SHA256SUMS`; la firma del workflow no se puede falsificar.
15. **Canal privado y SECURITY.md.** Un Issue es público: describir la vulnerabilidad ahí la divulga antes de que exista el parche, y regala a los atacantes una ventana de explotación. El canal privado (*private vulnerability reporting*) deja el informe visible solo para el responsable y el investigador, y permite el triage, un borrador de aviso (GHSA) y una corrección en privado hasta la divulgación coordinada. `SECURITY.md` dice cómo informar, qué versiones tienen soporte y hasta cuándo, qué plazos de respuesta se comprometen y que hay *safe harbour* para quien actúa de buena fe.
16. **Scorecard y el 0 en Maintained.** *(se responde en la Parte S, con los resultados reales de Scorecard)*
17. **Expediente vs. respuesta B5 de la Práctica 2.** *(se responde en la Parte T, al cerrar el expediente)*

---

## Backlog del laboratorio (Issues)

| Issue | Título | PR o evidencia de cierre |
|---|---|---|
| #3 | Adopt an international pull request template | PR #16 |
| #4 | Run SAST (SonarQube Cloud and CodeQL) on every pull request | PR #1 (fusionado antes de crear el backlog; cerrado a mano con comentario) |
| #5 | Block insecure commits with a Semgrep pre-commit hook | PR #17 |
| #6 | Enable Dependabot alerts and security updates | PR #18 (Refs) + cierre manual tras I.3 |
| #7 | Remediate the findings of the security audit | PR #21 |
| #8 | Upgrade the vulnerable dependencies | PR #24 (manual con pip-compile: Dependabot no generó alertas a tiempo) |
| #9 | Publish the audit log and the before/after evidence | este PR (Parte N) |
| #10 | Detect ReportAudit credentials in the whole Git history | PR #22 |
| #11 | Make SCA and secret scanning required checks on main | pendiente (Parte P) |
| #12 | Publish a security policy and a private vulnerability reporting channel | PR #23 (Refs) + cierre manual tras Q.3 |
| #13 | Release v1.0.0 with an SBOM and signed provenance | pendiente (Parte R) |
| #14 | Measure supply-chain maturity with OpenSSF Scorecard | pendiente (Parte S) |
| #15 | Build the CRA evidence index | pendiente (Parte T) |

