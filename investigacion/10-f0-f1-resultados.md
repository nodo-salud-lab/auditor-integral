# 10 · Resultados de integración F0 + F1

Fecha: 2026-11-18 · auditor-integral 0.1.0 · máquina local (macOS, Python 3.14.6) · gitleaks 8.30.1, semgrep 1.181.0, osv-scanner 2.7.0, zizmor 1.32.0.
Objeto auditado: brazo A, `validacion/app-sembrada/` (AgendaKine), contra `validacion/verdad-terreno.toml` (67 defectos, 56 controles limpios; set reservado = n % 10 ∈ {3, 6, 9}).

Sellos: las métricas son **SÍNTESIS** de corridas reproducibles; las interpretaciones y decisiones pendientes son **ESTIMACIÓN**/**GUÍA**.

---

## 1. Criterios de aceptación (PLAN_MAESTRO §10)

| Criterio | Resultado | Evidencia (comando → salida) |
|---|---|---|
| **F0-1** El plugin carga y `/auditar`, `/auditar-doctor` aparecen | **Cumple** | `claude plugin validate .` → `✔ Validation passed` (avisos del directorio público: falta README, LICENSE e ícono; el README ya se agregó, la licencia la decide el investigador). `claude --plugin-dir . plugin details auditor-integral` → `Skills (2) auditar, auditar-doctor` · `Hooks (1) PreToolUse`. Frontmatter de `skills/auditar/SKILL.md` y `skills/auditar-doctor/SKILL.md` con `name`, `description`, `allowed-tools`. No se probó la aparición en el menú `/` de una sesión interactiva. |
| **F0-2** 0 IDs de 01-08 huérfanos y 0 IDs canónicos duplicados | **Cumple** | `python3 -m unittest -v tests.test_catalogo` → `test_alias_fuente_sin_huerfanos ... ok`, `test_ids_canonicos_unicos ... ok`, `test_alias_unicos_entre_controles ... ok`. |
| **F0-3** Todos los ejemplos validan contra los schemas | **Cumple** | `tests.test_esquemas` → `test_todos_los_ejemplos_validan ... ok` (13 tests ok). Además, salidas reales de la corrida: `validar_schema.py schemas/hallazgo.schema.json …/hallazgos_todos.jsonl` → rc 0; `estado.schema.json …/estado.json` → rc 0; `--def perfil_tecnico perfil.schema.json …/perfil_tecnico.json` → rc 0. |
| **F0-4** `detectar_stack.py` clasifica bien 5 repos de ejemplo | **Cumple** | `tests.test_detectar_stack` → `TestViteSupabase/TestNextPrisma/TestFastAPI/TestEstatico/TestDocker.test_clasificacion ... ok` (18 tests ok). |
| **F1-1** Sensibilidad ≥ 0,90 en defectos N1 de SEG | **Cumple** | `metricas.py --dominio SEG --gate N1 --solo-f1`: desarrollo 16/16 = 1,00 (IC95 % 0,81-1,00); reservado 7/7 = 1,00 (0,65-1,00); total 23/23 = 1,00 (0,86-1,00). Incluyendo el N1 de SEG no previsto para F1: 23/24 = 0,96 (0,80-0,99). |
| **F1-2** 0 secretos sin enmascarar en texto destinado al LLM (canarios) | **Cumple** | `tests.test_criterios_f1.TestCanarios` ok. En la corrida real: 9 canarios (todos los `Secret` de gitleaks + valores secretos de `.env`) buscados literalmente en los 14 archivos fuera de `crudo/` y `cache/` (`hallazgos*.jsonl`, `digest/triage.json`, `informe.md`, `merged.sarif`, `estado.json`, `gates.json`, …) → **0 coincidencias**. |
| **F1-3** Dos corridas → mismo nivel y mismos fingerprints | **Cumple** | Dos `bin/auditar all … --modo rapido` → `gates.json`, `score.json`, `hallazgos.jsonl`, `hallazgos_todos.jsonl`, `roadmap.json`, `merged.sarif` **idénticos byte a byte**; 62/62 fingerprints iguales. `estado.json` e `informe.md` difieren solo en el ID de corrida (marca de hora del nombre de carpeta). `tests.test_criterios_f1.TestDeterminismo` ok. |
| **F1-4** Herramienta ausente → `no_evaluado` | **Cumple** | Corrida con `PATH` reducido (solo python3 y osv-scanner + sistema): tabla del scan → `gitleaks ausente`, `semgrep ausente`, `zizmor ausente`; `estado.json` → `SEG-SECRETO-REPO no_evaluado (gitleaks: herramienta ausente)`, `SEG-SECRETO-BUNDLE no_evaluado`, `SEG-SAST-INY no_evaluado`; el pipeline termina con rc 0. Tests `test_estado.test_herramienta_ausente_no_evaluado`, `test_gitleaks_ausente`, `test_adaptadores.test_cada_adaptador_ausente_deja_meta` ok. |
| **F1-5** 0 tokens LLM en las fases deterministas | **Cumple** | Corrida completa con binarios trampa `claude`, `anthropic`, `openai`, `llm`, `gemini`, `ollama` al frente del `PATH` y sin `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` → ninguna trampa invocada; `gates.json` idéntico al de la corrida normal. `grep` en `bin/` y `scripts/`: la única llamada de red es `registro_deps.py` a registry.npmjs.org / pypi.org (existencia de paquetes), no a un LLM. |
| **F1-6** `--modo rapido` ≤ 5 min | **Cumple** | `bin/auditar all validacion/app-sembrada --modo rapido`: 10 s (primera, con red), 6 s y 7 s (repeticiones). Scan en paralelo 4, timeout por herramienta 300 s. |

Suite completa: `python3 -m unittest discover -s tests` → **335 tests OK** (329 previos + 6 nuevos de esta integración).

---

## 2. Métricas contra la verdad de terreno

Corrida: `validacion/app-sembrada/.auditoria/corrida-1/hallazgos_todos.jsonl` (62 hallazgos sin tope). Coincidencia: control + archivo + línea ±3; asignación uno a uno conjunta sobre todos los defectos (ver §4). IC95 % de Wilson.

### 2.1 Desarrollo (usado para ajustar)

| Métrica | x/n | Proporción | IC95 % |
|---|---|---|---|
| Sensibilidad SEG·N1·detectable F1 | 16/16 | 1,00 | 0,81-1,00 |
| Sensibilidad detectables en F1 (todos los gates) | 34/34 | 1,00 | 0,90-1,00 |
| Sensibilidad global (incluye lo previsto para F2-F3) | 37/47 | 0,79 | 0,65-0,88 |
| · gate N1 | 19/19 | 1,00 | 0,83-1,00 |
| · gate N2 | 12/19 | 0,63 | 0,41-0,81 |
| · gate N3 | 5/8 | 0,62 | 0,31-0,86 |
| · gate N4 | 1/1 | 1,00 | 0,21-1,00 |
| FP en controles limpios | 0/39 | 0,00 | 0,00-0,09 |

### 2.2 Reservado (medido una vez, sin ajustar reglas a él)

| Métrica | x/n | Proporción | IC95 % |
|---|---|---|---|
| Sensibilidad SEG·N1·detectable F1 | 7/7 | 1,00 | 0,65-1,00 |
| Sensibilidad detectables en F1 | 13/15 | 0,87 | 0,62-0,96 |
| Sensibilidad global | 14/20 | 0,70 | 0,48-0,85 |
| · gate N1 | 7/8 | 0,88 | 0,53-0,98 |
| · gate N2 | 4/8 | 0,50 | 0,22-0,78 |
| FP en controles limpios | 0/17 | 0,00 | 0,00-0,18 |

### 2.3 Conjunto completo

| Métrica | x/n | Proporción | IC95 % |
|---|---|---|---|
| Sensibilidad global | 51/67 | 0,76 | 0,65-0,85 |
| Sensibilidad N1 (todos los dominios) | 26/27 | 0,96 | 0,82-0,99 |
| Sensibilidad SEG·N1 (incluye no previstos en F1) | 23/24 | 0,96 | 0,80-0,99 |
| VPP (precisión) global, sin triage | 51/62 | 0,82 | 0,71-0,90 |
| VPP antes de las correcciones de esta integración | 51/65 | 0,78 | 0,67-0,87 |
| FP en controles limpios | 0/56 | 0,00 | 0,00-0,06 |

Nivel resultante de la app sembrada: **global N0** ("Ninguno: no apto para uso"), 12 bloqueos (3 por secreto presunto vivo: SEG-ENV-PUBLICAS, SEG-SECRETO-BUNDLE, SEG-SECRETO-REPO). Puntaje 22,5 en gris (cobertura 0,177 < 0,70).

---

## 3. Falsos negativos y falsos positivos

### 3.1 Falsos negativos (16)

Clasificación del plan (§10, F1.5): herramienta ausente / regla faltante / normalizador; se agrega "requiere juicio LLM (F3)" porque el plan lo asigna a esa fase.

| ID | Set | Control (gate) | Detectable en F1 según verdad | Clase | Detalle |
|---|---|---|---|---|---|
| D34 | desarrollo | SEG-SAST-INY (N2) | no | regla faltante | `p/owasp-top-ten` no cubre la construcción en `server/rutas/reportes.js:21`. |
| D41 | desarrollo | SEG-PAGOS-FIRMA (N2) | no | regla faltante | Webhook sin verificación de firma; sin regla en F1. |
| D48 | desarrollo | SEG-ERRORES (N3) | no | regla faltante | Stack trace en la respuesta. |
| D51 | desarrollo | SEG-CICD (N3) | no | herramienta (configuración) | zizmor solo lo informa con `--persona auditor`; el adaptador usa `regular`. |
| D57 | desarrollo | SEG-IDOR (N2) | no | juicio LLM (F3) | revisor-autorizacion. |
| D58 | desarrollo | SEG-BFLA (N2) | no | juicio LLM (F3) | revisor-autorizacion. |
| D60 | desarrollo | SEG-RATELIMIT (N2) | no | juicio LLM (F3) | rutas_inventario.py + juicio. |
| D61 | desarrollo | ESC-LLM-TOPE (N2) | no | regla faltante | Llamada al LLM sin `max_tokens`. |
| D62 | desarrollo | DAT-RLS-ON (N2) | no | herramienta ausente (F2) | splinter / esquema_resumen.py. |
| D64 | desarrollo | DAT-MIGRACIONES-SEGURAS (N3) | no | herramienta ausente (F2) | squawk. |
| D36 | reservado | SEG-LLM-SALIDA (N2) | no | regla faltante | HTML de salida LLM sin sanitizar. |
| D39 | reservado | SEG-AUTH-CLIENTE (N2) | **sí** | normalizador/catálogo | Sí se detecta (regla propia `service-role-cliente`), pero el catálogo la mapea a SEG-SECRETO-BUNDLE y la verdad la registra en SEG-AUTH-CLIENTE. Discrepancia de control, no de detección. |
| D46 | reservado | SEG-LLM-CLAVE (N1) | no | regla faltante | Llamada al LLM desde el navegador (la variable expuesta sí la cubre SEG-ENV-PUBLICAS). |
| D53 | reservado | SEG-CICD (N3) | **sí** | normalizador | zizmor `artipacked` y semgrep `pull-request-target-code-checkout` lo marcan en la línea 13 (inicio del paso), la verdad en la 15; además el normalizador fusiona por (control, archivo, línea) y lo une con `unpinned-uses` (D52) de la misma línea. |
| D59 | reservado | SEG-BFLA (N2) | no | juicio LLM (F3) | Cambio de rol sin control en servidor. |
| D63 | reservado | DAT-RLS-PERMISIVA (N2) | no | herramienta ausente (F2) | `USING(true)`. |

Todos los FN de desarrollo están fuera del alcance declarado de F1 (detectable_en_F1 = false). No se escribieron reglas nuevas para ellos: el criterio F1-1 ya se cumplía y una regla hecha a la medida del texto sembrado sería sobreajuste.

### 3.2 Falsos positivos frente a la verdad (11)

| Hallazgo | Control | Ubicación | Interpretación |
|---|---|---|---|
| H-69ea4743b120 | SEG-SECRETO-BUNDLE | src/lib/supabaseAdmin.js:7 | Es D39 con otro control (ver arriba). Verdadero en sustancia. |
| H-fffd0fe594dd | SEG-ENV-EJEMPLO | .env | `.env` no está en `.gitignore`: real, no sembrado como defecto. |
| H-f85cd06c22ba | SEG-AGENTES-IA | .mcp.json:5 | Servidor MCP con versión flotante: real, no sembrado. |
| H-f82aadce8b30 | SEG-CICD | .github/workflows/triage.yml:14 | Duplicado de D56 (semgrep marca la línea 14, zizmor la 15; la fusión exige la misma línea). |
| H-2bac8cdf21b9, H-ff7ec4d1f6ff, H-55eb4cca3398, H-2ad7244236f2, H-e7bff362fdf5 | SEG-DEPS-CVE-ALTO | package-lock.json:18-29 | Avisos reales de osv para versiones antiguas no sembrados como defectos (3 altos, 2 medios). Los 2 medios caen en "CVE altos" por el comodín `osv:*`. |
| H-dbaa7e4c9195 | COD-DOC-AGENTE | (ausencia) | No hay CLAUDE.md/AGENTS.md: real, no sembrado. |
| H-d8dff0713347 | OPS-ERROR-TRACKING | (ausencia) | Sin seguimiento de errores: real, no sembrado. |

Ningún control limpio se disparó (0/56). La VPP contra la verdad subestima la precisión real: 9 de los 11 FP son problemas reales de la app que no estaban registrados como defectos.

---

## 4. Cambios hechos en esta integración

La corrida de punta a punta terminó con rc 0 desde el primer intento: no había incompatibilidades que la bloquearan entre adaptadores, normalizador, estado, gates e informe. Se corrigió lo siguiente (TDD: cada test se vio fallar antes de implementar):

1. **`catalogo/controles.toml`**: SEG-CICD ahora mapea `semgrep:yaml.github-actions.*`. Antes, las reglas de workflows de `p/owasp-top-ten` caían en SEG-SAST-INY por el comodín `semgrep:*` y producían 4 FP en desarrollo (preview.yml 13/16/20, triage.yml 14). Ahora 3 de ellos se fusionan con los hallazgos de zizmor de la misma línea; el de triage.yml:14 queda como duplicado de D56 (ver §3.2). Test: `test_catalogo.test_semgrep_github_actions_va_a_cicd`.
2. **`scripts/normalizar/sarif.py` + `catalogo.normalizar_regla`**: la regla de semgrep se guarda sin la ruta absoluta del archivo de reglas (antes: `Users.<usuario>.Desktop.PROYECTOS.auditor-integral.reglas.semgrep.vibe-coding.…`). Efecto: el fingerprint ya no depende de dónde esté instalado el plugin y la ruta local del usuario no llega a los textos para el LLM. Test: `test_normalizar.test_regla_propia_sin_ruta_absoluta`.
3. **`validacion/metricas.py`**:
   - La asignación hallazgo↔defecto es conjunta sobre los defectos medidos y los excluidos del subconjunto. Antes, al medir "desarrollo", un hallazgo de un defecto reservado contaba como FP (y en un caso disparó un limpio: 1/39 → 0/39), o podía acreditarse a un defecto medido cercano. Tests: `test_hallazgo_de_defecto_fuera_del_subconjunto_no_es_fp`, `test_asignacion_conjunta_con_defectos_fuera`.
   - Filtros combinables `--dominio`, `--gate` y `--solo-f1`, y listado de FN por ID. Tests: `test_filtrar_dominio_gate_y_f1`, `test_cli_con_filtros`.

Comandos de medición usados (reproducibles):

```
bin/auditar all validacion/app-sembrada --modo rapido --salida validacion/app-sembrada/.auditoria/corrida-1
python3 validacion/metricas.py --hallazgos validacion/app-sembrada/.auditoria/corrida-1/hallazgos_todos.jsonl \
        --subconjunto desarrollo|reservado|todo [--dominio SEG] [--gate N1] [--solo-f1]
```

---

## 5. Limitaciones

- **Cegamiento parcial.** Quien sembró corrió las herramientas crudas sobre la app (declarado en la verdad de terreno). En esta integración se miraron los FN del set reservado (D36, D39, D46, D53, D59, D63) al listarlos. No se ajustó ninguna regla ni mapeo a ellos; el cambio de SEG-CICD se motivó por FP del set de desarrollo y no recupera D53. Aun así, el set reservado ya no es completamente ciego para F6.
- **n pequeños.** Los IC95 % de Wilson son amplios (p. ej. reservado SEG·N1: 0,65-1,00). La sensibilidad 1,00 no excluye valores cercanos a 0,8 en el reservado.
- **Una sola app sembrada (brazo A)** construida por el mismo equipo que el auditor: riesgo de que los defectos se parezcan a lo que las herramientas ya detectan. Los brazos B y C (§11) no se han corrido.
- **Dependencia de red.** `registro_deps` (SEG-DEPS-EXISTEN, N1) consulta registry.npmjs.org/pypi.org; sin red esos defectos quedan como FN (F1-B lo midió: 4 FN en N1 sin red). Las métricas de este informe son **con red**.
- **Verdad de terreno incompleta.** 9 de 11 FP son problemas reales no registrados; la VPP 0,82 es un límite inferior.
- **El puntaje sube cuando faltan herramientas** (44,0 sin gitleaks/semgrep/zizmor frente a 22,5 con todas) porque hay menos `fail`; se muestra en gris (cobertura < 70 %) y no decide el nivel, pero puede confundir a un lector apurado.
- **F0-1** se verificó con `claude plugin validate` y `claude plugin details`; no se abrió una sesión interactiva para ver el menú `/`.
- La medición de tiempo (F1-6) es en una app pequeña (43 archivos, sin node_modules); no extrapola a monorepos.

---

## 6. Decisiones pendientes del investigador (GUÍA; no se autoseleccionaron)

1. **D39 / service_role en el cliente:** ¿se mantiene en SEG-SECRETO-BUNDLE (catálogo actual, N1, bloquea global) o la verdad de terreno pasa a ese control? Hoy hay discrepancia y cuenta como 1 FN + 1 FP.
2. **Fusión de hallazgos:** la fusión por (control, archivo, línea) une reglas distintas en la misma línea (D52 + D53). Opciones: fusionar solo si coincide además la familia de regla; o tolerar ±2 líneas solo entre herramientas para la misma regla (resolvería el duplicado de triage.yml). Cualquiera de las dos cambia el reservado: decidir antes de F6.
3. **CVE medios:** el comodín `osv:*` envía avisos de severidad media a SEG-DEPS-CVE-ALTO (N4). Opciones: crear un control informativo para CVE medios/bajos, o descartarlos del gate.
4. **zizmor `--persona`:** pasar a `auditor` recuperaría D51 (permisos excesivos) a costa de más ruido.
5. **Licencia** del plugin (requisito del directorio de plugins): elegir SPDX.

---

## Correcciones post-verificación

Fecha: 2026-11-18. Origen: informe de verificadores independientes (9 criterios, 18 defectos). Cada defecto se validó antes de tocar código: se escribió un test que lo reproduce (`tests/test_post_verificacion.py`, 25 tests), se comprobó que fallaba, se corrigió y se comprobó que pasaba. Sellos: **SÍNTESIS** para los resultados medidos; **GUÍA** para las decisiones que siguen pendientes.

### Defectos corregidos (16)

| # | Severidad | Defecto | Corrección | Test |
|---|---|---|---|---|
| 1 | crítica | Python en línea (`-c`, `-`) con cwd en el proyecto importaba un `json.py` del repo auditado | Todo Python en línea de los adaptadores y de `bin/auditar` corre aislado (`python3 -I`, arreglo `PYI` en `_comun.sh`); los scripts propios se ejecutan por ruta | `TestPythonNoImportaDelProyecto` |
| 2 | alta | `git status` ejecutaba `core.fsmonitor` del `.git/config` del repo; `gitleaks git` podía ejecutar `diff.external`/textconv | Nuevo `scripts/git_seguro.py` (`-c core.fsmonitor=false -c core.hooksPath=/dev/null -c diff.external= -c core.untrackedCache=false`, `GIT_CONFIG_NOSYSTEM=1`); los adaptadores exportan lo mismo por `GIT_CONFIG_COUNT` (alcanza al git que lanza gitleaks); el historial usa `--no-ext-diff --no-textconv`. Se eliminó `git status`: `run.json.git_sucio` queda en `null` (podía ejecutar filtros clean del repo) | `TestConfigGitDelRepo` |
| 3 | alta | Fail-open: `gates`/`estado` sin `normalize` previo (o con normalize en error) daban todo en pass; un crudo sin meta contaba como "ok" | `estado.normalizacion_valida`: si falta `normalizacion.json` o `run.json.fases.normalize` no está en ok, ningún control determinista pasa (no_evaluado, motivo explícito). Crudo sin meta → `sin_meta`, salvo que el JSON del check declare ok | `TestGatesSinNormalize` |
| 4 | alta | `gitleaks --log-opts` partía por espacios la ruta del proyecto dentro del repo (0 hallazgos, meta ok) | Si el prefijo tiene caracteres fuera de `[A-Za-z0-9._/@+-]`, se escanea sin pathspec y se filtra después por `File`; meta `filtro_prefijo` = `pathspec`/`posterior`/`ninguno` | `test_historial_con_espacios_en_el_prefijo` |
| 5 | alta | `ultima()` elegía una corrida plantada por el repo (`.auditoria/9999-12-31_2359-x/`) | `ultima` solo acepta carpetas con nombre del formato propio, sin enlaces, con fecha no futura y cuyo `run.json` declare este proyecto, esta carpeta y este id | `test_ultima_ignora_corrida_plantada`, `…_de_otro_proyecto` |
| 6 | alta | `.auditoria` como enlace simbólico → escritura fuera del proyecto; el hook no resolvía enlaces | `corrida.crear` rechaza `.auditoria` enlace y verifica que la carpeta resuelta quede en el proyecto; `.git/info/exclude` se abre con `O_NOFOLLOW` y no se escribe si `info/` o `exclude` son enlaces. El hook exige que el primer `.auditoria` no sea enlace y que la ruta resuelta (`realpath`) siga conteniendo `.auditoria` | `test_auditoria_symlink_rechazada`, `test_hook_resuelve_symlinks` |
| 7 | alta | Pass falso con herramienta ausente: con gitleaks ausente y semgrep ok, SEG-SECRETO-BUNDLE quedaba en pass | Campo nuevo `herramientas_parciales` en el catálogo: sus hallazgos dan fail, pero no bastan para pass. Marcado en SEG-SECRETO-BUNDLE (`semgrep`) y SEG-JWT (`gitleaks`: detecta secretos JWT, no verifica firma). El resto de listas de herramientas siguen siendo alternativas reales (p. ej. osv-scanner/trivy) | `TestHerramientaParcialNoDaPass` |
| 8 | media | `.semgrepignore`/`.gitignore` del repo ocultaban archivos a semgrep | `--no-git-ignore --x-ignore-semgrepignore-files` y exclusiones fijas equivalentes al `.semgrepignore` por defecto de semgrep (node_modules, dist, build, .next, out, vendor, test/, tests/, *.min.js…). Meta `ignores_proyecto`. Nota: `--x-…` es opción experimental de semgrep 1.181; si desaparece, la ejecución falla y el meta queda en error, no en pass | `TestSemgrepIgnore` |
| 9 | media | `.gitleaksignore` de la raíz git y de los bundles silenciaba secretos sin registro | El meta lista todos en `gitleaksignore` [{archivo, entradas}]; si alguno tiene entradas, el estado baja a `parcial` (el control no puede pasar) | `test_gitleaksignore_en_raiz_git_y_bundle` |
| 10 | media | `osv-scanner.toml` del repo podía ignorar CVE | `--config reglas/osv/vacio.toml` (config propia vacía); el meta lista los `osv-scanner.toml` del proyecto en `config_proyecto`. Verificado con un binario falso (argumentos); el efecto real sobre osv-scanner no se probó porque requiere red | `TestOsvConfigPropia` |
| 11 | media | Solo 8 reglas semgrep propias (F1 exige 10) | Dos reglas nuevas, genéricas, con su archivo `ruleid`/`ok`: `jwt-sin-verificar` (SEG-JWT: `jwt.decode`, `algorithms` con `none`, `ignoreExpiration`) y `comando-concatenado` (SEG-SAST-INY: `exec`/`execSync` o `spawn` con `shell: true` y comando concatenado/interpolado, importando `child_process`). `semgrep --test`: 10/10 | `test_reglas_semgrep` |
| 12 | baja | NP ignoraba `manual_pendiente` (contra §4.2.3) | `BLOQUEA_POTENCIAL = {"fail", "manual_pendiente"}`; se corrigió el test previo que codificaba el desvío | `TestPotencialManualPendiente`, `test_gates` |
| 13 | baja | ID de corrida con resolución de minuto: dos corridas en el mismo minuto se pisaban | Cada `crear` hace una carpeta nueva (`mkdir` exclusivo; si existe, sufijo `-2`, `-3`…). Con `--salida` explícita se mantiene la reutilización | `test_misma_hora_no_reutiliza` |
| 14 | baja | Carrera en `registrar_fase` (un único `run.json.tmp`, sin bloqueo) | Temporal único (`mkstemp`) y `fcntl.flock` sobre `.run.lock` | `test_registrar_fase_concurrente` (30 hilos) |
| 15 | baja | Carpeta de bundle que empieza con `-` se leía como opción de gitleaks | Se pasa `./<ruta>` | `test_carpeta_bundle_que_empieza_con_guion` |
| 16 | baja | F1-3 nunca se ejercitó con un commit real ni con el escaneo del historial | Test de punta a punta: copia de la app sembrada en un repo git con commit, dos `auditar all --modo rapido` → carpetas distintas con el commit7, `gates.json`, `hallazgos.jsonl` y `hallazgos_todos.jsonl` idénticos byte a byte, `gitleaks-git.json` presente | `TestDeterminismoConCommit` |

### Defectos validados pero no corregidos, con su razón

- **Estado según el modo (scripts/estado.py:106-115), parcialmente falso positivo.** Que en `--modo rapido` un control N3 salga `fail` cuando la herramienta reportó es deliberado: ocultar un hallazgo existente sería peor que la inconsistencia (el nivel no cambia porque ya hay bloqueos en N1). Se corrigió la parte real: el motivo ahora dice "hallazgo incidental fuera del alcance del modo rapido". Test: `TestFueraDeModoConHallazgo`.
- **D39 / `service-role-cliente` mapeada a SEG-SECRETO-BUNDLE (controles.toml:58).** El defecto es real (1 FN + 1 FP de control), pero ya figuraba como decisión pendiente del investigador (§6.1). No se autoselecciona.
- **Fusión por (control, archivo, línea) (comun.py:198-205).** Real. Ya figura como decisión pendiente (§6.2) y cualquier opción cambia el set reservado. No se autoselecciona.
- **Pass del puntaje con menos herramientas.** No estaba en la lista; se mantiene en Limitaciones (§5).

### Resultados después de las correcciones (SÍNTESIS)

- Suite: `python3 -m unittest discover -s tests` → **360 tests OK** (antes 335; +25 de regresión). `semgrep --test` de las reglas propias: 10/10.
- `bin/auditar all validacion/app-sembrada --modo rapido` → rc 0, **7 s** de reloj; corrida `2026-11-18_0130-sin-git`.
- F1-1 (SEG · N1 · detectable en F1): desarrollo **16/16**, reservado **7/7**, total **23/23 = 1,00** (IC95 % 0,86-1,00). Sin cambios respecto a la corrida anterior.
- Global (todo): 63 hallazgos · VP 52 · FP 11 · FN 15 (antes 62 · 51 · 11 · 16). La diferencia es **D34** (inyección de comandos en `server/rutas/reportes.js:21`, set de desarrollo), que ahora detecta `comando-concatenado`. Transparencia: la regla se escribió sabiendo que D34 era FN (la verdad de terreno lo marcaba "candidata a regla propia"); es genérica (no fija literales de la app) y D34 pertenece al set de desarrollo, pero su `detectable_en_F1 = false` no se modificó. `jwt-sin-verificar` no produjo hallazgos en la app sembrada.
- Limpios disparados: 0/56. Nivel global: N0 (demostrado y potencial), 12 bloqueos. Estados: 20 fail, 9 pass, 131 no_evaluado, 10 no_aplica, 4 manual_pendiente. Puntaje 22,5 (gris, cobertura 17,7 %).

### Limitaciones de estas correcciones

- `--x-ignore-semgrepignore-files` no es API estable de semgrep.
- La neutralización de `osv-scanner.toml` se verificó por argumentos, no contra la API real (requiere red).
- `git_seguro` cubre fsmonitor, hooks, diff externo y textconv; el auditor ya no usa comandos que comparen el working tree (que podrían ejecutar filtros clean/smudge). Un comando git nuevo que se agregue debe pasar por `git_seguro`.
- La protección contra corridas plantadas valida formato, fecha, proyecto y carpeta; no usa firma criptográfica. Una carpeta plantada con fecha pasada y rutas absolutas correctas no puede ganarle a la corrida recién creada, pero sí podría ser elegida si el usuario ejecuta `scan`/`gates` sin haber corrido `stack` antes. `all` siempre usa la carpeta que acaba de crear.

---

## Decisiones aplicadas (2026-11-18)

Origen: `DECISIONES.md` (2026-11-17, prevalece sobre §13 del plan). Tres tareas en paralelo (A1: decisiones 1-2; A2: decisiones 4-5, pendientes de integración y confidencialidad; A3: decisión 6, fallbacks) y una tarea de integración que unió los cambios, resolvió conflictos y midió. Sellos: **SÍNTESIS** para lo medido; **GUÍA** para lo pendiente; las coberturas de los fallbacks son **ESTIMACIÓN**.

### Qué quedó aplicado

| # | Decisión | Dónde | Estado |
|---|---|---|---|
| 1 | Pesos con evidencia | `config/pesos.toml`, `scripts/score.py`, `scripts/iua.py` | Severidad 10 / 7,5 / 5 / 2,5 (info 0), origen `plataforma` (OpenSSF Scorecard). Global G1 = Σw·m·pass / Σw·m, con m = 1,5 en SEG/DAT si salud o pagos (CVSS v3.1 §7.4). Letra A-E por el peor fallo abierto (estilo SonarQube). IUA: accesibilidad con la fórmula de Lighthouse y rendimiento con el puntaje Performance. Los pesos entre componentes del IUA y la equivalencia de severidades siguen siendo **ESTIMACIÓN**. |
| 2 | Umbrales de industria | `config/umbrales.toml` | 45 umbrales con fuente: 11 norma, 16 default-herramienta, 18 propuesta. `iua_bandas = [50, 90]` (Lighthouse); aplicarlas al IUA es **ESTIMACIÓN**. `cobertura_controles_puntaje` (70 %) sigue como propuesta. |
| 3 | Brazo C y confidencialidad | `config/confidencial.toml`, `scripts/checks/datos_confidenciales.py`, adaptadores, normalizador, fallbacks | El chequeo `datos_confidenciales` (solo metadatos) ahora corre en el despachador. Ninguna herramienta ni fallback lee las carpetas o patrones confidenciales. El normalizador descarta, como defensa en profundidad, los hallazgos que caigan en esas rutas. El brazo C no se ha corrido. |
| 4 | Lo legal avisa y no bloquea | catálogo (`aviso_legal = true` en 10 controles), `estado.py`, `gates.py`, `render_informe.py` | Bloque «⚠ Aviso legal» al inicio del informe. Los controles legales quedan en `manual_pendiente` hasta que el creador confirme, o en `no_aplica` si declara que no usa datos personales (la declaración queda registrada con su fecha). No cuentan para ningún nivel. |
| 5 | SUS exigido en N4 | `UX-SUS-68` (`exigido_sin_condicion = true`), `hoja-de-ruta.md` | Sin SUS el control queda en `manual_pendiente` y N4 no se otorga. |
| 6 | Herramientas faltantes | 11 fallbacks en `scripts/checks/`, catálogo, despachador, `doctor.sh` | Ver «Integración» abajo. |
| 7-8 | Skills externas y metas piloto | — | Sin cambios en esta tanda. Las métricas se reportan con IC95 % y sin umbral duro de aprobación (#8). |

### Integración (esta tarea)

1. **Catálogo** (`catalogo/controles.toml`), según `investigacion/propuestas/fallbacks_integracion.md` §3:
   - 24 controles con el fallback en `herramientas` y en `herramientas_parciales`, más 2 de solo mapeo: SEG-SECRETO-REPO (`check:dockerfile.secreto_en_env`, `check:iac.tf_secreto_literal`) y DAT-BUCKETS (`check:rls_estatico.bucket_publico`).
   - Subreglas explícitas, sin comodín `check:<fallback>.*`.
   - Se conservan los valores previos de cada control.
2. **Despachador** (`scripts/ejecutar_scanners.sh`):
   - 12 tareas nuevas: los 11 fallbacks y `datos_confidenciales`, que estaba pendiente desde A2.
   - Todos los chequeos se invocan con `python3 -I`.
3. **Doctor** (`scripts/doctor.sh`):
   - `lizard` advierte que `brew install lizard` instala otro programa.
   - `playwright` usa la instalación oficial (`npm install -D @playwright/test && npx playwright install chromium`).
   - Se agregan `nuclei`, `syft`, `zap.sh` y `psql`.
   - Sigue sin instalar nada.
4. **Conflictos resueltos:**
   - **Informe, §5:** tomaba los controles legales de una lista fija de 9 que omitía OPS-RETENCION, mientras que el bloque de aviso inicial (A2) usaba la marca `aviso_legal` del catálogo, con 10. Ahora §5 usa la marca del catálogo y remite al bloque inicial.
   - **Informe, fallbacks:** cada hallazgo que aporta solo un fallback se marca «cobertura parcial (fallback de X)», y la metodología lista cada fallback con la herramienta que reemplaza.
   - **Tabla del escaneo** (`resumen_crudo.py`): incluye los 12 chequeos nuevos, con `fallback_de=<herramienta>`.
   - **IUA:** A1 ya leía los hallazgos de `ux_estatico` y `presupuesto_build` como `parcial_fallback`, sin puntaje. No hubo que tocarlo.
5. **Defecto hallado en la corrida y corregido** (TDD, `TestRlsFkCubiertaPorPkOUnique`):
   - `rls_estatico.fk_sin_indice` no reconocía el índice implícito de PRIMARY KEY ni de UNIQUE.
   - En la app sembrada marcaba `perfiles.id`, que es a la vez PK y FK a `auth.users`.
   - La corrección es genérica (semántica de Postgres y splinter 0001): no se escribió para un defecto sembrado.
6. **Opciones «decide el investigador» que NO se aplicaron:**
   - los pases `ok_sbom_versionado` (SEG-SBOM) y `ok_html_lang` (UX-LANG);
   - `sin_cache_hash` → INF-CACHE-CDN;
   - quitar `radon`.

   Con eso **ningún control puede quedar en `pass` solo por un fallback**. El test `test_ningun_control_pasa_solo_por_fallback` lo comprueba para los 24 controles.

Suite: `python3 -m unittest discover -s tests` → **544 tests OK**: 360 previos, los de A1/A2/A3 y 23 de esta integración (`test_integracion_fallbacks.py` 17, `test_integracion_informe.py` 6). `test_doctor.py` se actualizó con las 4 herramientas nuevas.

### Verificación de la corrida (`bin/auditar all validacion/app-sembrada --modo estandar`)

Corrida `2026-11-18_0232-sin-git`, rc 0, unos 8 s de reloj (escaneo 4,0 s).

| Verificación | Resultado | Evidencia |
|---|---|---|
| Aviso legal presente | **Cumple** | Bloque «⚠ Aviso legal — verificación del creador» antes del veredicto. Tabla de 10 controles en `manual_pendiente`, Leyes 19.628 y 21.719 (re-verificar en BCN) y 20.584 condicionada a salud. No afirma cumplimiento. |
| Letra A-E | **Cumple** | Global **E**, 38,0/100, cobertura 29,5 % (gris). Por dominio: SEG E, DAT E, COD D, OPS C, INF A; UX y ESC sin letra (sin controles evaluados). |
| IUA con cobertura | **Cumple** | «IUA: sin datos · cobertura 0 % del peso · 0/6 componentes». Cada componente trae su motivo (sin sonda Playwright/axe ni LHCI). No se inventa un valor. |
| Fallbacks ejecutados y marcados parciales | **Cumple** | 11/11 corrieron, todos con `cobertura: "parcial (fallback)"`. Estados: 9 ok, 2 no_aplica (`dockerfile`, `iac`: no hay Dockerfile ni IaC). Hallazgos: deps_muertas 7, rls_estatico 2, sbom 2, migraciones_sql 1. Marcados en la tabla del escaneo (`fallback_de=`), en los hallazgos del informe y en la metodología. |
| Ningún control pasa solo por fallback | **Cumple** | `estado.json`: 22 pass, ninguno con herramienta fallback. Los controles sin hallazgo cuya única fuente es un fallback quedan `no_evaluado` («cobertura parcial del control, no basta para pass»). |
| Sin contenido confidencial en artefactos | **Cumple** | (a) Copia de la app con `datos-reales/` (CSV, JS con `sk_live_…`, SQL con `USING (true)`), `src/pacientes/` y `src/estudio.dcm`, todos con el canario `CANARIOCONF7Q2X`. Resultado: **0** archivos de salida (crudo incluido) contienen el canario. El único rastro es el inventario de `check_datos_confidenciales.json`: ruta, n.º de archivos y bytes. (b) 11 secretos de gitleaks y `.env` buscados literalmente en los 16 artefactos fuera de `crudo/` y `cache/`: **0** coincidencias. |
| Determinismo | **Cumple** | Dos corridas estándar: `gates.json`, `score.json`, `hallazgos*.jsonl`, `roadmap.json`, `merged.sarif` e `iua.json` idénticos byte a byte. |

Nivel: global **N0** (demostrado y potencial), 14 bloqueos. Estados: 27 fail, 22 pass, 97 no_evaluado, 20 manual_pendiente, 10 no_aplica. `--modo rapido` produce los mismos 81 hallazgos (los fallbacks corren en los tres modos; lo que excede el modo se informa como incidental).

### Métricas nuevas (SÍNTESIS)

Comando: `python3 validacion/metricas.py --hallazgos …/2026-11-18_0232-sin-git/hallazgos_todos.jsonl --raiz validacion/app-sembrada/ --subconjunto desarrollo|reservado|todo [--dominio SEG --gate N1 --solo-f1]`. IC95 % de Wilson. «Antes» es la corrida post-verificación (`2026-11-18_0130`, modo rápido). El valor de desarrollo de «antes» se reconstruye: 37/47 de §2.1 más D34, recuperado en la post-verificación.

| Métrica | Desarrollo | Reservado | Total | Antes (total) |
|---|---|---|---|---|
| Sensibilidad SEG·N1·detectable F1 | 16/16 = 1,00 (0,81-1,00) | 7/7 = 1,00 (0,65-1,00) | 23/23 = 1,00 (0,86-1,00) | 23/23 |
| Sensibilidad global | 40/47 = 0,85 (0,72-0,93) | 17/20 = 0,85 (0,64-0,95) | 57/67 = 0,85 (0,75-0,92) | 52/67 = 0,78 |
| · N1 | 19/19 = 1,00 (0,83-1,00) | 7/8 = 0,88 (0,53-0,98) | 26/27 = 0,96 (0,82-0,99) | 26/27 |
| · N2 | 14/19 = 0,74 (0,51-0,88) | 6/8 = 0,75 (0,41-0,93) | 20/27 = 0,74 (0,55-0,87) | — |
| · N3 | 6/8 = 0,75 (0,41-0,93) | 3/3 = 1,00 (0,44-1,00) | 9/11 = 0,82 (0,52-0,95) | — |
| VPP sin triage | 40/64 = 0,62 (0,50-0,73) | 17/41 = 0,41 (0,28-0,57) | 57/81 = 0,70 (0,60-0,79) | 52/63 = 0,83 |
| FP en controles limpios | 0/39 (0,00-0,09) | 0/17 (0,00-0,18) | 0/56 (0,00-0,06) | 0/56 |

**Defectos recuperados (5): D62, D64 (desarrollo); D39, D53, D63 (reservado).**

- **D62** (DAT-RLS-ON) y **D63** (DAT-RLS-PERMISIVA): `rls_estatico`.
- **D64** (DAT-MIGRACIONES-SEGURAS): `migraciones_sql`.
- **D39**: movido de SEG-SECRETO-BUNDLE a SEG-AUTH-CLIENTE (A2).
- **D53**: la regla de fusión cambió (A2). Ahora ya no une reglas distintas de una misma herramienta en la misma línea, y `artipacked`/`pull-request-target` dejaron de fusionarse con `unpinned-uses`.

**FN restantes (10):**

- 7 de desarrollo: D41, D48, D51, D57, D58, D60, D61.
- 3 del reservado: D36, D46, D59.
- Todos están fuera del alcance determinista declarado: regla faltante o juicio LLM (F3).

**FP frente a la verdad (24).** Sus causas:

- **9 vienen de fallbacks.** Revisados, son problemas reales no sembrados:
  - 7 `dep_sin_uso`: axios, ejs, handlebars, jsonwebtoken, lodash, minimist y shell-quote, con 0 referencias en `src/` y `server/`;
  - `sbom_no_versionado`;
  - `proyecto_sin_licencia`: no hay LICENSE.
- **9 avisos reales de osv:** 3 altos y 6 medios. Los medios caen en el nuevo SEG-DEPS-CVE-MEDIO (A2), que antes estaban en ALTO por el comodín.
- **6 ya conocidos:**
  - SEG-ENV-EJEMPLO;
  - SEG-AGENTES-IA (`.mcp.json` flotante);
  - duplicado de D56 en `triage.yml:14`;
  - COD-DOC-AGENTE;
  - OPS-ERROR-TRACKING;
  - un `eval-dinamico` en `reportes.js:15`, a 6 líneas de D34 (no verificado si es duplicado o un defecto real no sembrado).

La caída de la VPP (0,83 → 0,70) se explica por hallazgos reales que la verdad de terreno no registra. Es un límite inferior. Que no se haya disparado ningún control limpio (0/56) indica que los fallbacks no agregaron ruido en controles limpios.

### Advertencias (leer antes de F6)

- **El set reservado ya no es ciego.**
  - D39 y D53 se recuperaron por cambios que respondían a pendientes de §6, redactados mirando FN del reservado. A2 aplicó el cambio de control de D39 y la nueva regla de fusión. Esta integración no los revirtió ni ajustó nada al reservado.
  - D63 se recuperó con un fallback genérico (splinter 0024), escrito antes de esta medición y sin mirar el reservado.
  - La sensibilidad reservada 17/20 debe leerse como **no independiente** para esos dos defectos. Sin D39 y D53 sería 15/20 = 0,75 (**ESTIMACIÓN** contrafactual).
- **Adaptadores de herramientas reales.** No existen para jscpd, lizard, knip, squawk, hadolint, checkov, syft, actionlint ni lhci. Si `doctor` detecta una de ellas, su fallback se omite y el control queda `no_evaluado` hasta que exista el adaptador. Conviene crear los adaptadores antes de instalar esas herramientas.
- **splinter.** `rls_estatico` solo se omite si `herramientas.json` declara `splinter` disponible, y hoy ninguna fase lo escribe. `psql` presente no basta.
- **Coberturas de los fallbacks.** Son **ESTIMACIÓN** hasta medirlas contra la herramienta real (informe 13 §5).
- **Tests de otros agentes.** A1 adaptó `tests/test_config_toml.py` y A2 modificó 3 asserts de `test_catalogo.py`/`test_normalizar.py` para reflejar las decisiones. Quedan aceptados en esta integración; si el investigador no los acepta, hay que revertirlos junto con los cambios que prueban.

### Decisiones pendientes del investigador (GUÍA; no se autoseleccionaron)

1. Pases explícitos `ok_sbom_versionado` (SEG-SBOM) y `ok_html_lang` (UX-LANG): con ellos esos dos controles podrían pasar solo por fallback.
2. `sin_cache_hash` (info) → INF-CACHE-CDN: ¿debe un asset sin hash hacer fallar el control?
3. `dep_no_declarada`: COD-CICLOS-MUERTO (aplicado) o SEG-DEPS-EXISTEN (N1).
4. Quitar `radon` de COD-COMPLEJIDAD (sin actividad desde 2024-10-20).
5. Cómo tratar el reservado contaminado (D39, D53) en F6: excluirlos, sembrar defectos nuevos o declarar la dependencia.
6. Sigue pendiente de §6: zizmor `--persona` (D51) y la licencia del plugin.

---

## Cierre de pases vacíos (rondas 1-3, fail-closed; 2026-11-18)

**Regla.** Ningún control queda `pass` sin evidencia positiva de que se evaluó algo relevante (alcance > 0 registrado, pase explícito o todos los `pases_requeridos`). Ante la duda: `no_evaluado`, o `no_aplica` con motivo. Detalle de cada ronda en README.md («Ronda 1/2/3 de pases vacíos») y en `validacion/brazo-c-kine-us/REAUDITORIA.md`, sección «Re-auditoría 3».

**Suite:** 830 OK (antes de las rondas, 646). Pruebas nuevas: `test_pases_vacios_r1.py` (57), `test_pases_vacios_r2.py` (62), `test_pases_vacios_r3.py` (65).

### Bucle (SÍNTESIS)

| Ronda | Residuales de la re-verificación anterior | Estado |
|---|---|---|
| 1 | 9 (COD-CI-BASICO, SEG-SAST-INY/DAT-SQL-CONCATENADO en Python sin Flask/Django y Kotlin, `src/build/` excluido, SEG-AGENTES-IA, SEG-LOCKFILE, DAT-ESQUEMA-VERSIONADO, OPS-HEALTH, COD-DOC-AGENTE, COD-REPRO) | corregidos en la ronda 2 |
| 2 | 8 (PV-R2-01…08: DAT-PII-REPO con CSV de pacientes, COD-CI-BASICO por cortocircuito/heredoc/`|| true`/filtros, SEG-LOCKFILE ×2, SEG-SAST-INY contradicho, SEG-DEPS-EXISTEN, INF-INVENTARIO) | corregidos en la ronda 3 |
| 3 | 2 confirmados + 1 plausible (abajo) | **no corregidos: limitación conocida** |

### App sembrada después de la ronda 3 (corrida de cierre, modo estándar, `hallazgos_todos.jsonl`; IC95 % de Wilson)

| Métrica | Valor | Cambio frente a `1339` |
|---|---|---|
| Sensibilidad SEG·N1 detectable en F1 | 23/23 = 1,00 (0,86-1,00) | = |
| Sensibilidad global | 57/67 = 0,85 (0,75-0,92) | = |
| Desarrollo / reservado | 40/47 = 0,85 (0,72-0,93) / 17/20 = 0,85 (0,64-0,95) | = |
| Por gate N1 / N2 / N3 / N4 | 26/27 · 20/27 · 9/11 · 2/2 | = |
| VPP | 57/82 = 0,70 (0,59-0,78) | +1 FP: `COD-REPRO git_sin_versionar` (la copia no tiene archivos versionados) |
| FP en controles limpios | 0/56 (0,00-0,06) | = |
| Estados | pass 3 · fail 27 · no_evaluado 115 · manual_pendiente 20 · no_aplica 11 | SEG-LOCKFILE pass → no_evaluado (sin repo git) |

FN sin cambios: D36, D41, D46, D48, D51, D57-D61. Sin regresión.

### kine us (brazo C) después de la ronda 3

Corrida `2026-11-18_1555-8f38a6d` (solo lectura verificada: `git status` vacío antes y después, `.git/index` sin cambios). N0/N0, 0 bloqueos, 114 hallazgos (idénticos a la re-auditoría 2). Pass: 12 → 8 (salen SEG-SAST-INY, DAT-SQL-CONCATENADO, SEG-LOCKFILE e INF-INVENTARIO). Cobertura global 0,177 → 0,152. DAT-PII-REPO sigue provisional (sintéticos sin confirmar por el creador).

### Pases vacíos residuales (limitación conocida; ESTIMACIÓN del riesgo)

| Control | Fixture | Resultado | Riesgo |
|---|---|---|---|
| DAT-PII-REPO (crítico, N1) | `db/seed.sql` con `INSERT` de nombre, RUT, email y diagnóstico, y `db/export.yaml`, versionados | **pass** | Alto: solo se inspeccionan CSV/TSV y JSON de registros (`datos_confidenciales.py:362-366`) |
| SEG-DEPS-EXISTEN (N1) | paquetes alucinados en `[dependency-groups]`, grupo dev de Poetry, `setup.py` y un `-r deps/base.txt` | **pass** (1 dependencia verificada) | Medio: esos manifiestos no se leen ni están en `NO_CUBIERTOS` (`registro_deps.py:144-200, 271`) |
| COD-TIPOS (N2) | no reproducido (exige tsc local) | plausible | Bajo: el pase no registra cuántos archivos tipó tsc |

Observación aparte (no es pase vacío): en kine, SEG-SAST-INY queda `no_evaluado` por dos scripts Python offline de `pruebas/`. Es el costo esperado de la regla fail-closed. Decisión pendiente (GUÍA): permitir que el creador declare rutas fuera de alcance o aceptar el `no_evaluado`.
