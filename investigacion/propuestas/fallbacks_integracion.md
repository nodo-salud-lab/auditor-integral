# Integración de los fallbacks estáticos (Decisión 6) — APLICADA el 2026-11-18, con excepciones

> **Estado (2026-11-18, integración):** §3, §4 y §5 aplicados a `catalogo/controles.toml`, `scripts/ejecutar_scanners.sh` y `scripts/doctor.sh` (tests: `tests/test_integracion_fallbacks.py`). **No se aplicaron** las opciones marcadas «decide el investigador»: los pases `check:sbom.ok_sbom_versionado` (SEG-SBOM) y `check:ux_estatico.ok_html_lang` (UX-LANG), el mapeo de `check:presupuesto_build.sin_cache_hash` a INF-CACHE-CDN y la eliminación de `radon` en COD-COMPLEJIDAD. `dep_no_declarada` quedó en COD-CICLOS-MUERTO, como propone la tabla. Detalle: `investigacion/10-f0-f1-resultados.md`, sección «Decisiones aplicadas (2026-11-18)». El texto que sigue es la propuesta original.

**Fecha:** 2026-11-18 · **Sello:** GUÍA (procedimiento) + ESTIMACIÓN (coberturas) · **Prevalece:** `DECISIONES.md` #6.
**Base:** `investigacion/13-fallbacks-herramientas.md` y `investigacion/13-propuesta-fallbacks.toml`.

Esta tarea **no editó** `catalogo/controles.toml`, `scripts/ejecutar_scanners.sh` ni `scripts/doctor.sh`. Aquí está exactamente lo que hay que agregar. Las decisiones marcadas «decide el investigador» quedan abiertas.

---

## 1. Qué se implementó

| Script (`scripts/checks/`) | Reemplaza a | Salida | Reglas propias |
|---|---|---|---|
| `fallback.py` | — (infraestructura común) | — | — |
| `duplicacion.py` | jscpd | `check_duplicacion.json` | — |
| `complejidad.py` | lizard | `check_complejidad.json` | — |
| `deps_muertas.py` | knip (y depcheck) | `check_deps_muertas.json` | — |
| `migraciones_sql.py` | squawk | `check_migraciones_sql.json` | — |
| `dockerfile.py` | hadolint | `check_dockerfile.json` | — |
| `iac.py` | checkov | `check_iac.json` | `reglas/semgrep/iac/` (7 reglas + 2 archivos de prueba para `semgrep --test`) |
| `sbom.py` | syft | `check_sbom.json` + `sbom.cdx.json` (CycloneDX 1.5 mínimo) | — |
| `workflows.py` | actionlint | `check_workflows.json` | — |
| `rls_estatico.py` | splinter | `check_rls_estatico.json` | — |
| `ux_estatico.py` | playwright (`playwright_ux`/axe) | `check_ux_estatico.json` | — |
| `presupuesto_build.py` | lhci (`lighthouse`) | `check_presupuesto_build.json` | — |

Tests: `tests/test_fallbacks.py` (55 tests: positivos y negativos por fallback, contrato común, omisión por `herramientas.json`, exclusión confidencial y de `node_modules`, `semgrep --test` de las reglas IaC, y contrato con `scripts/estado.py`). Suite completa: 521 tests OK al cierre (incluye tests agregados en paralelo por otros agentes).

Fuera del alcance (pendientes): fallbacks de red (`check_humo_http`, `check_exposicion_http`, `check_pasivo_http`); en `deps_muertas`, archivos inalcanzables y ciclos de imports (§4.3 del informe 13); en `migraciones_sql`, migraciones Alembic; en `complejidad`, las funciones flecha sin llaves; en `presupuesto_build`, scripts bloqueantes, imágenes sin dimensiones y `font-display`.

## 2. Contrato de salida (lo que cambia respecto de `comun.py`)

```json
{"check": "dockerfile", "version": "1", "estado": "ok", "motivo": null,
 "reemplaza": "hadolint", "cobertura": "parcial (fallback)",
 "hallazgos":   [{"regla": "check:dockerfile.tag_latest", "archivo": "Dockerfile", "linea": 1,
                  "mensaje": "...", "evidencia": "FROM node:latest", "severidad_sugerida": "media"}],
 "checks_pass": [{"regla": "check:dockerfile.ok_usuario_root", "archivo": "Dockerfile", "mensaje": "..."}]}
```

1. **`reemplaza` y `cobertura`** van a nivel raíz del JSON; la forma de cada hallazgo es idéntica a la de los checks existentes. `normalizar/checks.py` hoy los ignora (no rompe). Propuesta opcional: copiar `cobertura` a cada registro normalizado y al motivo del control en `estado.json` (`"… (cobertura parcial: fallback de hadolint)"`).
2. **Los pases llevan prefijo `ok_`** (`check:<n>.ok_<subregla>`). Motivo, verificado con un test contra `estado.py`: un `checks_pass` cuya regla coincide con `mapea_reglas` deja el control en `pass` **aunque la herramienta esté en `herramientas_parciales`** (`estado._regla_mapeada` no mira las parciales). Por eso:
   - `mapea_reglas` debe nombrar **subreglas de hallazgo explícitas**, nunca `check:<n>.*` (el comodín capturaría los `ok_` y daría pass; test `test_comodin_dejaria_pasar_un_parcial`).
   - Un `ok_…` se agrega a `mapea_reglas` **solo** en los controles que el fallback cubre por completo (§3, columna «Pase»).
3. **Omisión si la herramienta real está.** Cada fallback lee `DIR_CORRIDA/herramientas.json` (padre de `DIR_CRUDO`; o `AUDITOR_HERRAMIENTAS_JSON`). Si alguna de sus herramientas reales tiene `"disponible": true`, escribe `estado: "no_evaluado"`, `motivo: "omitido: la herramienta real (X) está disponible…"` y no analiza. Sin `herramientas.json` (p. ej. `auditar scan` sin `doctor`) se asume ausente y corre. **Advertencia:** hoy no existen adaptadores para jscpd, lizard, knip, squawk, hadolint, checkov, syft, actionlint ni lhci; si `doctor` los detecta, el fallback se omite y el control queda `no_evaluado` hasta que exista el adaptador. Es el comportamiento pedido (la herramienta real tiene prioridad); conviene crear los adaptadores antes de instalar esas herramientas.
4. **Estados.** `no_aplica` solo cuando no hay nada que analizar y eso implica que el control no aplica (sin Dockerfile, sin IaC, sin migraciones SQL, sin workflows, sin código). `no_evaluado` cuando la ausencia **no** implica no aplicabilidad: `rls_estatico` sin `supabase/migrations` (el esquema puede haberse hecho en el dashboard), `sbom` sin lockfiles, `deps_muertas` sin `package.json` (proyecto Python), `presupuesto_build` sin `dist/` (el auditor no construye). `parcial`: `iac` sin semgrep (solo reglas de contexto).
5. **Confidencialidad (Decisión 3).** `fallback.recorrer()` excluye `comun.DIRS_EXCLUIDOS`, los defaults `datos-reales/`, `datos-abiertos/`, `node_modules/`, `dist/`, y todo lo que `datos_confidenciales.es_confidencial()` marque según `config/confidencial.toml` (carpetas a cualquier profundidad y globs como `*.dcm`). `node_modules` se excluye siempre. `presupuesto_build` es la única excepción para `dist/` (solo tamaños y nombres; las carpetas confidenciales dentro de `dist/` se siguen excluyendo). `sbom` no lee `node_modules` (licencias solo desde `package-lock.json` v2/v3).

## 3. Cambios a `catalogo/controles.toml`

Regla general (pedida): **todo fallback agregado a `herramientas` se agrega también a `herramientas_parciales`**. Pueden dar `fail`; solo dan `pass` donde la columna «Pase» lo indica. El nombre en el catálogo es el del check sin prefijo (igual que `archivos_clave`, `env_publicas`): `utiles.canon_herramienta("check:duplicacion") == "duplicacion"`.

Limitación del catálogo: `catalogo.control_por_regla` asigna cada regla de hallazgo a **un solo** control (el patrón más específico). Por eso cada subregla aparece en una sola fila.

| Control | `herramientas` (+) | `herramientas_parciales` (+) | `mapea_reglas` (+) | Pase | Cobertura declarada (ESTIMACIÓN) |
|---|---|---|---|---|---|
| COD-DUPLICACION | `duplicacion` | `duplicacion` | `check:duplicacion.porcentaje_global` | No | Parcial: clones tipo 1-2, % global ±2 pp. `bloque_duplicado` queda sin mapear (es evidencia; mapearlo haría fallar el control con cualquier clon aunque el % esté bajo el umbral) |
| COD-COMPLEJIDAD | `complejidad` | `complejidad` | `check:complejidad.ccn_alta` | No | Parcial: Python (ast) ~95 %, JS/TS ~70 %. `funcion_larga` y `archivo_grande` sin mapear (umbrales 80/500 son ESTIMACIÓN, no están en `umbrales.toml`) |
| COD-CICLOS-MUERTO | `deps_muertas` | `deps_muertas` | `check:deps_muertas.dep_sin_uso`, `check:deps_muertas.dep_no_declarada` | No | Parcial: sin exports/archivos sin uso ni ciclos. `devdep_sin_uso` (info) sin mapear al inicio por falsos positivos de plugins. **Decide el investigador:** `dep_no_declarada` podría ir a SEG-DEPS-EXISTEN (N1) en vez de aquí; una dependencia fantasma no es necesariamente inexistente, por eso se propone COD-CICLOS-MUERTO |
| DAT-MIGRACIONES-SEGURAS | `migraciones_sql` | `migraciones_sql` | `check:migraciones_sql.index_sin_concurrently`, `…drop_index_sin_concurrently`, `…concurrently_en_transaccion`, `…not_null_sin_default`, `…set_not_null`, `…drop_column`, `…drop_table`, `…rename`, `…cambio_tipo`, `…fk_sin_not_valid`, `…check_sin_not_valid`, `…sin_lock_timeout` | No | Parcial ~60 %: sin parser de Postgres; SQL dinámico y `DO $$` no se analizan |
| DAT-TIPOS | `migraciones_sql` | `migraciones_sql` | `check:migraciones_sql.tipo_timestamp`, `…tipo_serial_int`, `…tipo_varchar` | No | Parcial: no revisa `numeric` para dinero, CHECK ni UNIQUE |
| INF-DOCKERFILE | `dockerfile` | `dockerfile` | `check:dockerfile.tag_latest`, `…usuario_root`, `…sudo`, `…add_vs_copy`, `…add_url`, `…cmd_shell_form`, `…apt_sin_pin`, `…apk_sin_pin`, `…pip_sin_pin`, `…curl_pipe_sh`, `…sin_multistage`, `…copy_todo_sin_dockerignore` | No | Parcial: ~80 % de la intención (latest, root, multi-stage), ~15 % de las reglas de hadolint (sin ShellCheck) |
| SEG-SECRETO-REPO | — | — | `check:dockerfile.secreto_en_env`, `check:iac.tf_secreto_literal` | No | Solo aporta fail (gitleaks sigue siendo la herramienta del control) |
| INF-IAC | `iac` | `iac` | `check:iac.tf_ingreso_abierto`, `…tf_bucket_publico`, `…tf_sin_cifrado`, `…tf_bd_publica`, `…k8s_privilegiado`, `…k8s_host`, `…k8s_sin_nonroot`, `…k8s_sin_limites`, `…k8s_latest`, `…compose_puerto_bd` | No | Parcial: ~5 % de los checks de checkov; ~50 % de los misconfigs críticos típicos |
| SEG-SBOM | `sbom` | `sbom` | `check:sbom.sbom_no_versionado`, **`check:sbom.ok_sbom_versionado`** | **Sí** | **Completa en el criterio verificable estáticamente** (hay SBOM versionado o un paso de CI que lo genera con syft/cdxgen/cyclonedx). Es más estricta que «syft corrió ok», que hoy bastaría para pass. «En cada release» no se verifica (habría que leer los disparadores del workflow). **Decide el investigador** |
| COD-LICENCIAS | `sbom` | `sbom` | `check:sbom.licencia_copyleft`, `…licencia_desconocida`, `…proyecto_sin_licencia` | No | Parcial: licencias solo desde `package-lock.json` v2/v3; sin assets ni código propio; la compatibilidad depende del modelo de distribución (entrevista) |
| SEG-CICD | `workflows` | `workflows` | `check:workflows.sin_on`, `…sin_jobs`, `…job_sin_runs_on`, `…tabulador`, `…expresion_mal_cerrada`, `…runner_obsoleto` | No | Parcial: la seguridad la cubre zizmor (~85 %); sintaxis de actionlint ~20 % |
| COD-CI-BASICO | `workflows` | `workflows` | `check:workflows.ci_sin_calidad` | No | Parcial: detecta que **algún** `run:` ejecuta lint/typecheck/tests; no exige los tres ni revisa que el disparador sea push/PR |
| DAT-RLS-ON | `rls_estatico` | `rls_estatico` | `check:rls_estatico.rls_deshabilitado`, `…vista_security_definer` | **Nunca** | Parcial ~40 %: el estado de la BD puede diferir de las migraciones (dashboard). `ok_rls_migraciones` no se mapea en ningún control DAT |
| DAT-RLS-PERMISIVA | `rls_estatico` | `rls_estatico` | `check:rls_estatico.rls_sin_politica`, `…politica_siempre_true` | **Nunca** | Ídem |
| DAT-RLS-METADATA | `rls_estatico` | `rls_estatico` | `check:rls_estatico.politica_user_metadata` | No | Ídem |
| DAT-SECDEF | `rls_estatico` | `rls_estatico` | `check:rls_estatico.secdef_sin_search_path`, `…secdef_ejecutable_anon` | No | Ídem |
| DAT-GRANTS | `rls_estatico` | `rls_estatico` | `check:rls_estatico.auth_users_expuesto`, `…grant_anon_amplio` | No | Ídem |
| DAT-PK-FK | `rls_estatico` | `rls_estatico` | `check:rls_estatico.sin_pk` | No | Ídem |
| DAT-FK-INDICE | `rls_estatico` | `rls_estatico` | `check:rls_estatico.fk_sin_indice` | No | Ídem |
| DAT-BUCKETS | — | — | `check:rls_estatico.bucket_publico` | No | Solo fail |
| UX-LANG | `ux_estatico` | `ux_estatico` | `check:ux_estatico.html_sin_lang`, **`check:ux_estatico.ok_html_lang`** | **Sí** (propuesta) | **Completa para SPA con `index.html` estático o layout JSX con `<html>`**: es el mismo dato que mide axe `html-has-lang`. No cubre HTML generado en el servidor por plantillas fuera del repo ni un `lang` cambiado en tiempo de ejecución. **Decide el investigador** |
| UX-REFLOW | `ux_estatico` | `ux_estatico` | `check:ux_estatico.sin_viewport` | No | Solo fail; el reflow real exige navegador |
| UX-AXE-CRIT | `ux_estatico` | `ux_estatico` | `check:ux_estatico.img_sin_alt` | No | Solo fail |
| UX-FORMULARIOS | `ux_estatico` | `ux_estatico` | `check:ux_estatico.input_sin_label` | No | Solo fail |
| UX-TECLADO | `ux_estatico` | `ux_estatico` | `check:ux_estatico.click_en_div`, `…tabindex_positivo`, `…outline_none` | No | Solo fail. `outline_none` no se mapea además a UX-FOCO-OCULTO (una regla → un control; WCAG 2.4.11 trata foco tapado por elementos fijos, no outline) |
| UX-LIGHTHOUSE | `presupuesto_build` | `presupuesto_build` | `check:presupuesto_build.chunk_grande`, `…imagen_grande` | No | Solo fail (~15 %). UX-LCP-LAB nunca pasa por fallback |
| INF-CACHE-CDN | — | — | `check:presupuesto_build.sin_cache_hash` | No | Solo fail (severidad info; **decide el investigador** si un asset sin hash debe hacer fallar el control) |

**Bloque TOML equivalente** (para aplicar a mano, control por control; se muestran solo los campos que cambian, conservando los valores actuales):

```toml
# COD-DUPLICACION
herramientas = ["jscpd", "duplicacion"]
herramientas_parciales = ["duplicacion"]
mapea_reglas = ["jscpd:*", "check:duplicacion.porcentaje_global"]

# COD-COMPLEJIDAD   (el informe 13 propone además quitar "radon": sin push desde 2024-10-20)
herramientas = ["lizard", "radon", "complejidad"]
herramientas_parciales = ["complejidad"]
mapea_reglas = ["lizard:*", "check:complejidad.ccn_alta"]

# COD-CICLOS-MUERTO
herramientas = ["knip", "madge", "vulture", "deps_muertas"]
herramientas_parciales = ["deps_muertas"]
mapea_reglas = ["knip:*", "madge:*", "check:deps_muertas.dep_sin_uso", "check:deps_muertas.dep_no_declarada"]

# DAT-MIGRACIONES-SEGURAS
herramientas = ["squawk", "migraciones_sql"]
herramientas_parciales = ["migraciones_sql"]
mapea_reglas = ["squawk:*", "check:migraciones_sql.index_sin_concurrently", "check:migraciones_sql.drop_index_sin_concurrently",
  "check:migraciones_sql.concurrently_en_transaccion", "check:migraciones_sql.not_null_sin_default",
  "check:migraciones_sql.set_not_null", "check:migraciones_sql.drop_column", "check:migraciones_sql.drop_table",
  "check:migraciones_sql.rename", "check:migraciones_sql.cambio_tipo", "check:migraciones_sql.fk_sin_not_valid",
  "check:migraciones_sql.check_sin_not_valid", "check:migraciones_sql.sin_lock_timeout"]

# DAT-TIPOS
herramientas = ["squawk", "migraciones_sql"]
herramientas_parciales = ["migraciones_sql"]
mapea_reglas = ["check:migraciones_sql.tipo_timestamp", "check:migraciones_sql.tipo_serial_int", "check:migraciones_sql.tipo_varchar"]

# INF-DOCKERFILE
herramientas = ["hadolint", "trivy", "dockerfile"]
herramientas_parciales = ["dockerfile"]
mapea_reglas = ["hadolint:*", "check:dockerfile.tag_latest", "check:dockerfile.usuario_root", "check:dockerfile.sudo",
  "check:dockerfile.add_vs_copy", "check:dockerfile.add_url", "check:dockerfile.cmd_shell_form", "check:dockerfile.apt_sin_pin",
  "check:dockerfile.apk_sin_pin", "check:dockerfile.pip_sin_pin", "check:dockerfile.curl_pipe_sh",
  "check:dockerfile.sin_multistage", "check:dockerfile.copy_todo_sin_dockerignore"]

# SEG-SECRETO-REPO (solo mapeo)
mapea_reglas = ["gitleaks:*", "semgrep:generic.secrets.*", "check:dockerfile.secreto_en_env", "check:iac.tf_secreto_literal"]

# INF-IAC
herramientas = ["trivy", "checkov", "iac"]
herramientas_parciales = ["iac"]
mapea_reglas = ["checkov:*", "trivy-config:*", "check:iac.tf_ingreso_abierto", "check:iac.tf_bucket_publico",
  "check:iac.tf_sin_cifrado", "check:iac.tf_bd_publica", "check:iac.k8s_privilegiado", "check:iac.k8s_host",
  "check:iac.k8s_sin_nonroot", "check:iac.k8s_sin_limites", "check:iac.k8s_latest", "check:iac.compose_puerto_bd"]

# SEG-SBOM (pase explícito: cobertura completa del criterio verificable)
herramientas = ["syft", "cdxgen", "sbom"]
herramientas_parciales = ["sbom"]
mapea_reglas = ["check:sbom.sbom_no_versionado", "check:sbom.ok_sbom_versionado"]

# COD-LICENCIAS
herramientas = ["syft", "cdxgen", "scancode", "sbom"]
herramientas_parciales = ["sbom"]
mapea_reglas = ["check:sbom.licencia_copyleft", "check:sbom.licencia_desconocida", "check:sbom.proyecto_sin_licencia"]

# SEG-CICD
herramientas = ["zizmor", "actionlint", "workflows"]
herramientas_parciales = ["workflows"]
mapea_reglas = ["zizmor:*", "actionlint:*", "semgrep:yaml.github-actions.*", "check:workflows.sin_on", "check:workflows.sin_jobs",
  "check:workflows.job_sin_runs_on", "check:workflows.tabulador", "check:workflows.expresion_mal_cerrada",
  "check:workflows.runner_obsoleto"]

# COD-CI-BASICO
herramientas = ["archivos_clave", "actionlint", "workflows"]
herramientas_parciales = ["workflows"]
mapea_reglas = ["check:archivos_clave.ci*", "check:workflows.ci_sin_calidad"]

# DAT-RLS-ON
herramientas = ["splinter", "esquema_resumen", "rls_estatico"]
herramientas_parciales = ["rls_estatico"]
mapea_reglas = ["splinter:0013*", "check:rls_estatico.rls_deshabilitado", "check:rls_estatico.vista_security_definer"]

# DAT-RLS-PERMISIVA
herramientas = ["splinter", "revisor-autorizacion", "rls_estatico"]
herramientas_parciales = ["rls_estatico"]
mapea_reglas = ["splinter:0008*", "splinter:0024*", "check:rls_estatico.rls_sin_politica", "check:rls_estatico.politica_siempre_true"]

# DAT-RLS-METADATA
herramientas = ["splinter", "rls_estatico"]
herramientas_parciales = ["rls_estatico"]
mapea_reglas = ["splinter:0015*", "check:rls_estatico.politica_user_metadata"]

# DAT-SECDEF
herramientas = ["splinter", "rls_estatico"]
herramientas_parciales = ["rls_estatico"]
mapea_reglas = ["splinter:0011*", "splinter:0028*", "splinter:0029*", "splinter:0031*",
  "check:rls_estatico.secdef_sin_search_path", "check:rls_estatico.secdef_ejecutable_anon"]

# DAT-GRANTS
herramientas = ["splinter", "esquema_resumen", "rls_estatico"]
herramientas_parciales = ["rls_estatico"]
mapea_reglas = ["splinter:0002*", "check:rls_estatico.auth_users_expuesto", "check:rls_estatico.grant_anon_amplio"]

# DAT-PK-FK
herramientas = ["splinter", "rls_estatico"]
herramientas_parciales = ["rls_estatico"]
mapea_reglas = ["splinter:0004*", "check:rls_estatico.sin_pk"]

# DAT-FK-INDICE
herramientas = ["splinter", "rls_estatico"]
herramientas_parciales = ["rls_estatico"]
mapea_reglas = ["splinter:0001*", "check:rls_estatico.fk_sin_indice"]

# DAT-BUCKETS (solo mapeo)
mapea_reglas = ["check:rls_estatico.bucket_publico"]

# UX-LANG (pase explícito propuesto; decide el investigador)
herramientas = ["axe", "ux_estatico"]
herramientas_parciales = ["ux_estatico"]
mapea_reglas = ["axe:*/html-has-lang", "check:ux_estatico.html_sin_lang", "check:ux_estatico.ok_html_lang"]

# UX-REFLOW
herramientas = ["playwright_ux", "ux_estatico"]
herramientas_parciales = ["ux_estatico"]
mapea_reglas = ["playwright:reflow*", "check:ux_estatico.sin_viewport"]

# UX-AXE-CRIT
herramientas = ["playwright_ux", "axe", "ux_estatico"]
herramientas_parciales = ["ux_estatico"]
mapea_reglas = ["axe:critical/*", "check:ux_estatico.img_sin_alt"]

# UX-FORMULARIOS
herramientas = ["axe", "playwright_ux", "revisor-ux", "ux_estatico"]
herramientas_parciales = ["ux_estatico"]
mapea_reglas = ["check:ux_estatico.input_sin_label"]

# UX-TECLADO
herramientas = ["playwright_ux", "revisor-ux", "ux_estatico"]
herramientas_parciales = ["ux_estatico"]
mapea_reglas = ["check:ux_estatico.click_en_div", "check:ux_estatico.tabindex_positivo", "check:ux_estatico.outline_none"]

# UX-LIGHTHOUSE
herramientas = ["lighthouse", "presupuesto_build"]
herramientas_parciales = ["presupuesto_build"]
mapea_reglas = ["lighthouse:*", "check:presupuesto_build.chunk_grande", "check:presupuesto_build.imagen_grande"]

# INF-CACHE-CDN (solo mapeo)
mapea_reglas = ["check:presupuesto_build.sin_cache_hash"]
```

Al aplicar, correr `python3 -m unittest tests.test_catalogo tests.test_criterios_f1 tests.test_fallbacks` (alineación de reglas y herramientas con el catálogo).

Nota sobre agentes LLM: en UX-FORMULARIOS y UX-TECLADO el control incluye `revisor-ux`; con la lógica actual de `estado.py`, un control mixto sin hallazgos queda `no_evaluado` («falta el juicio») aunque haya pase; con hallazgo del fallback queda `fail`. Es coherente con «solo fail».

## 4. Líneas para `scripts/ejecutar_scanners.sh` (variable `TAREAS`)

Agregar al final de `TAREAS` (formato `nombre|tipo|script|archivo_meta|herramienta`):

```text
duplicacion|check|checks/duplicacion.py|check_duplicacion|check:duplicacion
complejidad|check|checks/complejidad.py|check_complejidad|check:complejidad
deps_muertas|check|checks/deps_muertas.py|check_deps_muertas|check:deps_muertas
migraciones_sql|check|checks/migraciones_sql.py|check_migraciones_sql|check:migraciones_sql
dockerfile|check|checks/dockerfile.py|check_dockerfile|check:dockerfile
iac|check|checks/iac.py|check_iac|check:iac
sbom|check|checks/sbom.py|check_sbom|check:sbom
workflows|check|checks/workflows.py|check_workflows|check:workflows
rls_estatico|check|checks/rls_estatico.py|check_rls_estatico|check:rls_estatico
ux_estatico|check|checks/ux_estatico.py|check_ux_estatico|check:ux_estatico
presupuesto_build|check|checks/presupuesto_build.py|check_presupuesto_build|check:presupuesto_build
```

- No se necesita lógica nueva en el despachador: cada fallback decide por sí mismo si se omite (lee `herramientas.json` del directorio de la corrida, que `bin/auditar` escribe en la fase `doctor`).
- Recomendado: invocar los checks con `"$PY" -I` (aislado), como prescribe el informe 13 §3.2, para que un `json.py`/`re.py` plantado en el repo auditado no se importe. Los fallbacks funcionan con `-I` (probado en `tests/test_fallbacks.py`).
- Tiempos medidos sobre *kine us herramienta* (~11 000 líneas de código): todos < 0,4 s, salvo `iac`, que lanza semgrep solo si hay archivos IaC (timeout interno 120 s). Todos caben en los tres modos.
- Actualizar el comentario de cabecera («los cuatro chequeos») y `uso()`.
- `sbom.cdx.json` queda en `crudo/`; `normalizar/run.py` lo clasifica como `ignorado` (no rompe) y `estado.estado_herramientas` tampoco lo cuenta.

## 5. Líneas para `scripts/doctor.sh` (variable `CATALOGO`)

Formato: `nombre (binario que busca command -v)|comando de versión|instalación sugerida|¿npx? (s/n)`. El primer campo también es la clave en `herramientas.json` que leen los fallbacks.

**Corregir (reemplazar la línea existente):**

```text
lizard|lizard --version|pipx install lizard (NO usar brew install lizard: esa fórmula es un compresor distinto)|n
playwright|playwright --version|npm install -D @playwright/test && npx playwright install chromium|s
```

- lizard: `doctor.sh` ya decía `pipx install lizard` (correcto); se agrega la advertencia explícita porque `brew install lizard` instala el compresor inikep/lizard ([formulae.brew.sh/api/formula/lizard.json](https://formulae.brew.sh/api/formula/lizard.json)).
- playwright: la instrucción actual (`npm install -g playwright`) no es la de la documentación oficial ([playwright.dev/docs/intro](https://playwright.dev/docs/intro)).

**Agregar:**

```text
nuclei|nuclei -version|brew install nuclei|n
syft|syft version|brew install syft|n
zap.sh|zap.sh -version|brew install --cask zap (o Docker: ghcr.io/zaproxy/zaproxy:stable zap-baseline.py)|n
psql|psql --version|brew install libpq && brew link --force libpq (para correr splinter.sql con una conexión de solo lectura)|n
```

- `zap.sh`: el cask instala `ZAP.app`; `zap.sh` no queda en el PATH por defecto (queda en `/Applications/ZAP.app/Contents/Java/`). Con la línea propuesta `doctor` lo informará ausente salvo que el usuario lo agregue al PATH o use Docker. **NO VERIFICADO** el comportamiento exacto del cask en esta máquina (ZAP no está instalado). Alternativa: que `doctor` pruebe `docker image inspect ghcr.io/zaproxy/zaproxy:stable` (no descarga nada).
- `psql` presente **no** omite `rls_estatico`: el fallback solo se omite si `herramientas.json` declara `splinter` disponible (splinter no es un binario: requiere conexión a la base). Sugerencia: que la fase que ejecute splinter (o el uso del MCP de Supabase `get_advisors`, con confirmación del creador) escriba `"splinter": {"disponible": true}` en `herramientas.json`.
- Mensajes informativos sugeridos (informe 13 §1 y propuesta TOML, sección B): «trivy falta: la función de dependencias la cubre osv-scanner (instalado)»; «actionlint falta: la seguridad de workflows la cubre zizmor; fallback `workflows` para sintaxis mínima».
- `doctor.sh` sigue sin instalar nada: `instalacion_sugerida` es solo texto.

Mapa herramienta real → fallback (claves que cada fallback busca en `herramientas.json`):

| Fallback | Se omite si está disponible |
|---|---|
| duplicacion | `jscpd` |
| complejidad | `lizard` |
| deps_muertas | `knip`, `depcheck` |
| migraciones_sql | `squawk` |
| dockerfile | `hadolint` |
| iac | `checkov` |
| sbom | `syft` |
| workflows | `actionlint` |
| rls_estatico | `splinter` |
| ux_estatico | `playwright`, `playwright_ux` |
| presupuesto_build | `lhci`, `lighthouse` |

## 6. Prueba sobre el proyecto real del brazo C (solo metadatos agregados)

Corrida local de solo lectura sobre *kine us herramienta* (sin `herramientas.json`, así que corrieron todos). `datos-reales/`, `datos-abiertos/` y `node_modules/` no se recorrieron.

| Fallback | Estado | Hallazgos (subregla: n) |
|---|---|---|
| duplicacion | ok | porcentaje_global: 1 (8,1 % > 5 %); bloque_duplicado: 65 (incluye `e2e/` y `pruebas/`, igual que jscpd por defecto) |
| complejidad | ok | ccn_alta: 25; funcion_larga: 18; archivo_grande: 1 |
| deps_muertas | ok | devdep_sin_uso: 1 |
| sbom | ok | sbom_no_versionado: 1; licencia_copyleft: 1 (GPL-2.0-or-later en una dependencia de producción); proyecto_sin_licencia: 1 |
| ux_estatico | ok | 0 (pases: html_lang, viewport, img_alt, input_label) |
| presupuesto_build | ok | chunk_grande: 1 (716 kB) |
| migraciones_sql, dockerfile, iac, workflows | no_aplica | — |
| rls_estatico | no_evaluado | sin `supabase/migrations` |

Durante esta prueba se corrigieron tres fuentes de falsos positivos (con test de regresión cada una): clones repetidos por desfases internos (`duplicacion`), dependencias citadas solo en configuraciones o con archivo `rc` propio (`deps_muertas`) y hashes de Vite con `-`/`_` (`presupuesto_build`). Las coberturas siguen siendo ESTIMACIÓN hasta medirlas en F6 contra la herramienta real (informe 13 §5).
