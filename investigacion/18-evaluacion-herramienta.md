# 18 — Evaluación de la herramienta: funcionamiento, usabilidad, activación y alcance (2026-11-19)

> **Sistema exploratorio** (DECISIONES.md #10). auditor-integral entrega evidencia para que una persona decida. **No es una herramienta de investigación validada** y no certifica seguridad ni cumplimiento legal (README.md:123).

Este documento integra cuatro evaluaciones independientes (funcionamiento, usabilidad, activación y alcance) hechas el 2026-11-19 sin abrir Claude Code ni `claude -p`, sin instalar nada y con kine us en solo lectura. Las cifras provienen de comandos ejecutados por los evaluadores (logs en la scratchpad de la sesión, ruta abajo) o de archivos citados con ruta:línea. Donde dos evaluaciones discrepaban, el sintetizador volvió a correr el comando (ver §9).

Sellos: **SÍNTESIS** = observación verificada; **ESTIMACIÓN** = juicio con supuestos; **GUÍA** = orientación procedimental.

Raíz de evidencia (`EV/`): una carpeta `evaluacion/` en el scratchpad temporal de la sesión del 2026-11-19 (ruta local de esa máquina, no versionada). Era efímera y ya no está disponible en otro clon; lo que importaba conservar está transcrito aquí.

### Estado de las correcciones (actualizado el 2026-11-20; el texto original de la evaluación se conserva abajo)

| Defecto | Estado | Evidencia |
|---|---|---|
| **U-1** (H-3): `--salida` inexistente creaba una corrida vacía con rc 0 | **Corregido** (2026-11-19). Las fases que trabajan sobre una corrida previa terminan con rc 4, stdout vacío y sin crear nada si `--salida` no existe, no tiene `run.json` o es un archivo; desde el 2026-11-20 el mensaje distingue «no es una carpeta (es un archivo)». | `bin/auditar` (bloque `EXIGE_CORRIDA`); `tests/test_u1_salida_corrida.py`, `tests/test_h2_fp_humano.py::TestCliFpVerificados`. Revisión adversarial del 2026-11-20: rc 4 reproducido con un error de tipeo, una ruta con espacio y una carpeta vacía. |
| **A3**: las respuestas de la entrevista podían perderse | **Corregido** (2026-11-19: el skill escribe `respuestas.json`; `perfil.py` no pisa un `perfil.json` con datos si falta `respuestas.json`, rc 1). El 2026-11-20 se cerró la variante que encontró la revisión adversarial: un `respuestas.json` con JSON inválido (coma final) o que no es objeto ahora da rc 1 y deja `perfil.json` idéntico byte a byte; las claves de primer nivel desconocidas se advierten. | `scripts/perfil.py` (`leer_respuestas`, `CLAVES_RESPUESTAS`); `tests/test_a3_perfil_respuestas.py`. |
| **H-2**: un FP crítico verificado por una persona no tenía salida | **Corregido, con decisión pendiente** (DECISIONES.md #11, pendiente de confirmar por Enzo). Registro `fp-verificados.json` que escribe la persona. El 2026-11-20, tras la revisión adversarial, solo se aplica si el operador lo autoriza con `--fp-verificados RUTA`; el informe recalcula el registro en cada `report` y no confía en `<corrida>/fp_humanos.json`; los descartes se ven en la cabecera, la 6c y `gates.json`, y con alguno `listo_datos_reales` nunca es `SI`. | `scripts/veredictos.py` (`_registro_fp`, `leer_fp_humanos`, `aviso_fp_humanos`), `scripts/gates.py`, `bin/auditar`; `tests/test_h2_fp_humano.py`. |

Las secciones siguientes describen el estado del 2026-11-19 **antes** de estas correcciones: donde dicen «abierto» o «DEFECTO», léase como historia.

---

## 1. Resumen ejecutivo

| Pregunta | Respuesta | Sello |
|---|---|---|
| **¿Funciona?** | Sí, la parte determinista. `bin/auditar all` corre todas las fases con rc 0 en la app sembrada (19,1 s) y en un proyecto trivial (6,7 s). Los artefactos existen y validan contra los schemas del repo; `merged.sarif` pasa un chequeo estructural SARIF 2.1.0 con 0 errores; `gates.json` es byte a byte reproducible. Hay **3 defectos funcionales confirmados**: el «no» a la red no se respeta (D1), un falso positivo de la IA sobre un crítico puede borrar su bloqueo (D2) y el paso de medición de tokens del skill falla con rc 2 (A1). | SÍNTESIS |
| **¿Es usable?** | Parcialmente. La CLI tiene mensajes claros en español y códigos de salida coherentes. Pero hay 2 problemas de severidad 4 (control de red falso; falso positivo crítico sin salida) y 6 de severidad 3, sobre todo en el resumen para la persona dueña, que se declara «sin jerga» y no lo es. SUS: **no medido**. | Severidades: ESTIMACIÓN (un evaluador) |
| **¿Qué alcance tiene?** | Catálogo amplio (176 controles, 7 dominios) y ejecución estrecha: en modo estándar se evalúa el 14 % (kine us, 19/138) y el 18 % (app sembrada, 30/165) de los controles aplicables. Lo cubierto es casi solo análisis estático de SEG y COD en JS/TS. Ningún control `llm` ni `manual` llegó a pass/fail en esas corridas. | SÍNTESIS (cifras); ESTIMACIÓN (45 controles sin ejecutor) |
| **¿Se puede activar?** | La CLI sí, verificado de punta a punta. La carga como plugin de Claude Code (`--plugin-dir`, `/auditor-integral:auditar`) **no se verificó** porque la evaluación prohibía ejecutar `claude`. | SÍNTESIS / NO VERIFICADO |

**Veredicto (ESTIMACIÓN, confianza moderada):** sirve hoy como **cribado exploratorio de seguridad estática y calidad de código** en proyectos JS/TS (Vite/React/Express/Next) y, en parte, Python, usado desde la CLI por alguien técnico que sepa leer `no_evaluado` como «no sabemos». No sirve para afirmar madurez en usabilidad, escala, infraestructura en ejecución ni cumplimiento legal, ni para entregarse a una persona dueña no técnica sin acompañamiento. Antes de cualquier uso con terceros hay que corregir D1 (red) y D2/H-2 (falsos positivos graves).

Por qué la confianza es moderada y no alta: una sola app sembrada construida por el mismo equipo y una sola auditoría real (n = 1 por brazo; `investigacion/10-f0-f1-resultados.md:139`); jueces LLM no ejecutados en esta evaluación; tokens sin medir; evaluación heurística de un solo evaluador y sin usuarios.

---

## 2. Funcionamiento por paso (SÍNTESIS)

Copia de `validacion/app-sembrada` en `EV/app-copia` (las 10 corridas previas se apartaron a `EV/auditoria-previa-copiada`); proyecto trivial `EV/vacio` (un `package.json` sin dependencias y un `index.js`). Tiempos con `time` de zsh.

| # | Paso | rc | Tiempo | Observación |
|---|---|---|---|---|
| 1 | `auditar doctor` | 0 | 3,60 s | JSON válido; 9 herramientas presentes y 15 ausentes (24). No instala. |
| 2 | `auditar all EV/app-copia` | 0 | 19,10 s (13,2 s al repetir, §12) | Todas las fases `ok`. N0, puntaje 5,8 (E), cobertura 0,182, 83 hallazgos (86 sin tope), 135 crudos, «bloqueos 14» (ver O2). |
| 3 | `stack` | 0 | 0,22 s | Crea corrida nueva. |
| 4 | `scan` | 0 | 6,89 s | 194 crudos en vez de 135: osv-scanner leyó el SBOM de la corrida anterior (O1). |
| 5 | `normalize` | 0 | 0,34 s | 83 hallazgos con fingerprints idénticos al paso 2: la contaminación de O1 no llega a los hallazgos. |
| 6 | `gates` (+ score + iua) | 0 | 0,46 s | `gates.json` idéntico byte a byte entre corridas (`cmp`): determinista. |
| 7 | `report` | 0 | 0,28 s | — |
| 8 | `perfil` sin respuestas | 0 | 0,15 s | «16 preguntas pendientes». |
| 9 | `digest` | 0 | 0,18 s | Triage ~3936 de 4000 tokens, INCOMPLETO: 47 críticos/altos quedan «incierto», que cuenta como verdadero (fail-closed). |
| 10 | `veredictos` sin `veredictos.jsonl` | 1 | 0,16 s | Mensaje correcto, pero dice «terminó con código 2» y el rc externo es 1. |
| 11 | `veredictos` con JSONL sintético (6 líneas) | 0 | 0,55 s | «50 aplicados, 3 descartados»; descarta bien JSON inválido, cambio de otro dominio y pass con ubicación inexistente. Reveló D2. |
| 12 | `all EV/vacio` (estándar) | 0 | 6,72 s | N0, 31,8 (D), 7 hallazgos, 0 bloqueos. pass 2, fail 6, no_aplica 42, no_evaluado 107, manual_pendiente 19. |
| 13 | `all EV/vacio --modo rapido` | 0 | 6,53 s | Mismo puntaje, cobertura 0,058. |
| 14 | `veredictos` con JSONL vacío | 0 | 0,49 s | «0 aplicados». |
| 15 | `AUDITOR_SIN_RED=1 all EV/app-copia` | 0 | 13,39 s | **D1**: igual consultó api.osv.dev y el registro npm (registro_deps 8,875 s). |
| 16 | Errores: subcomando desconocido, carpeta inexistente, `report` sin corrida, `--modo turbo` | 2, 2, 4, 2 | — | Mensajes claros en español. |
| 17 | `doctor --salida DIR` | 0 | — | Escribe `herramientas.json`. |
| 18 | Fixture de activación con ruta con espacio, `AUDITOR_REGISTRO_SIN_RED=1 AUDITOR_SEMGREP_REGISTRO="" … --modo rapido` | 0 | 6,3 s | N0, 1 bloqueo (DAT-SQL-CONCATENADO), 34,5 (E). Las rutas con espacio funcionan. |
| 19 | `medir_tokens.py --corrida C` (como indica el skill) | **2** | — | **A1**: «unrecognized arguments: --corrida». Reverificado por el sintetizador. |

**Artefactos de la corrida** (`EV/app-copia/.auditoria/2026-11-19_0016-sin-git/`): `informe.md` (612 líneas), `hoja-de-ruta.md` (231), `resumen-dueno.md` (56), `merged.sarif` (27 reglas, 86 resultados, 0 errores estructurales), `estado.json`, `gates.json`, `score.json`, `iua.json`, `roadmap.json`, `hallazgos.jsonl` (83), `hallazgos_todos.jsonl` (86), `digest/`, `crudo/` (22 adaptadores), `herramientas.json`, `perfil_tecnico.json`, `run.json`. `scripts/validar_schema.py` da rc 0 para hallazgo, estado y perfil. Sin `{{`, `None` ni `Traceback` en los .md. El JWT del `.env` sembrado sale enmascarado (`eyJh****pOus`).

**Pasos que exigen LLM (no ejecutados por regla):** entrevista interactiva (`auditar-perfil`), jueces triage-fp / revisor-autorizacion / revisor-arquitectura / revisor-ux, `redactor-dueno` y la medición headless de tokens (bloqueada: `claude auth status` sin sesión). Sin LLM, los controles `llm`/`mixto` quedan `no_evaluado` (115 en la app, 107 en el vacío), como corresponde al diseño fail-closed. No se probó `--modo profundo` ni se volvió a correr la suite (contexto conocido: 1148 pruebas, con un test de timeout inestable, `test_adaptadores…test_timeout_por_herramienta`).

---

## 3. Defectos y observaciones (SÍNTESIS salvo indicación)

### 3.1 Defectos confirmados

| ID | Defecto | Evidencia | Impacto |
|---|---|---|---|
| **D1** (= A2, H-1) | **[CORREGIDO 2026-11-19, §3.3]** El consentimiento de red se ignora. `skills/auditar/SKILL.md:48` exporta `AUDITOR_SIN_RED=1` si el usuario dice que no, pero ningún script la lee: `grep -rn SIN_RED bin scripts skills hooks` solo encuentra el skill y `AUDITOR_REGISTRO_SIN_RED` (`scripts/checks/registro_deps.py:95`). `scripts/adaptadores/osv.sh:4-6` consulta la API de OSV sin interruptor. | `EV/app-copia/.auditoria/2026-11-19_0024-sin-git/crudo/osv.meta.json:30` (`"fuente": "https://api.osv.dev …"`); `EV/logs/sinred.err` (registro_deps 8,875 s) | Un «no» del usuario no impide consultar servicios externos (se envían nombres y versiones de paquetes, no código). |
| **D2** | **[CORREGIDO 2026-11-19, §3.3]** Un `falso_positivo` de triage-fp sobre un crítico (H-d06d0e597385, DAT-RLS-PERMISIVA) dejó el control `no_evaluado` con el motivo «splinter: sin datos…» en vez del motivo de `veredictos.ajustar`; `gates.py` no lo reconoce como `pendiente_ia` y los bloqueos bajan de 14 a 13. Causa: `scripts/veredictos.py:534-540` solo escribe el motivo FP si el estado posterior está en `ESTADOS_OK_FP` (línea 519). | `EV/logs/gates_antes_veredictos.json` frente a `EV/app-copia/.auditoria/2026-11-19_0017-sin-git/gates.json` | Contradice DECISIONES.md #10. **ESTIMACIÓN:** si ese crítico fuera el único bloqueo, el nivel global podría subir sin verificación humana. |
| **A1** | **[CORREGIDO 2026-11-19, §3.3]** El paso 10 de `/auditar` llama `medir_tokens.py --corrida "$C"` (`skills/auditar/SKILL.md:92`), pero el script solo acepta un directorio posicional de transcripts (`scripts/medir_tokens.py:22`). rc 2. | Reverificado el 2026-11-19 | `tokens.json` nunca se genera desde el skill. |
| **A3** | `auditar-perfil` indica escribir `perfil.json` a mano (`skills/auditar-perfil/SKILL.md:82`) y luego correr `bin/auditar perfil` (`:88`), pero `scripts/perfil.py:188-202` regenera `perfil.json` desde `respuestas.json` y usa `{}` si no existe. | Sin `--respuestas`: «16 preguntas pendientes; declaraciones: ninguna» | **ESTIMACIÓN** (inferido del código, no observado en una sesión real): las respuestas de la entrevista pueden perderse. |
| **U-1** (H-3) | `--salida` con una carpeta inexistente crea una corrida vacía en silencio; `digest` devuelve rc 0 e informa «completo» sobre datos vacíos. Lógica: `bin/auditar:68-71` (`mkdir -p` previo) y `:86-89` (`crear_corrida` si no hay `run.json`). | Prueba con `corrida-typo` en `EV/proy-min/.auditoria/` | Éxito silencioso ante un error de tipeo. |
| **U-2** (H-4) | `auditar digest <carpeta-de-corrida>` responde «no hay corrida previa en `<corrida>/.auditoria`; ejecute primero 'auditar stack `<corrida>`'», sugerencia que crearía `.auditoria/` dentro de la corrida. | `bin/auditar:90-92`; prueba | Mensaje engañoso. |

### 3.2 Observaciones menores

- **O1.** **[CORREGIDO 2026-11-19, §3.3]** osv-scanner escanea `.auditoria/` de corridas anteriores (lee `crudo/sbom.cdx.json`): los crudos crecen 59 → 118 → 177 y los paquetes 7 → 14 → 21, mientras `meta.alcance.lockfiles` sigue en 1. La normalización lo filtra (0 rutas `.auditoria` en hallazgos y SARIF), pero infla el resumen y el tráfico de red.
- **O2.** «bloqueos 14» en consola frente a 11 en informe y resumen. Resuelto en §9: son 14 entradas sobre 11 controles distintos.
- **O3.** **[CORREGIDO 2026-11-19, §3.3]** `crudo/gitleaks*.json` guarda el campo `Secret` completo (12 entradas con 9 valores distintos en `gitleaks.json`, 3 en `gitleaks-bundle.json`; recontado en la verificación crítica, §12) porque gitleaks corre sin `--redact`. **ESTIMACIÓN:** riesgo si alguien comparte `.auditoria/`.
- **O4.** Mensajes confusos: SEG-DEPS-EXISTEN pide «pase explícito… ver /auditar-doctor» con 0 dependencias; el motivo de osv dice «analizó 0 de osv-scanner.lockfiles» (plantilla mal resuelta); «Verificar: /auditar --modo estandar» remite a Claude Code aunque se use la CLI; queda un `.run.lock` de 0 bytes por corrida; `duracion_s` en segundos enteros.
- **O5.** **[PARCIAL 2026-11-19: README ya dice 176 controles y 1226 pruebas; el resto sigue abierto]** Documentación desalineada: README dice 174 controles (`README.md:5`; hay 176), 1131 pruebas (`README.md:81`; el contexto conocido es 1148), «Skills: auditar, auditar-doctor» (`README.md:58`; hay 4 con SKILL.md), comandos `/auditar` y `/auditar-doctor` sin prefijo de plugin (`README.md:61`), y omite `resumen-dueno.md` en la lista de salidas (`README.md:71`). Ni README, ni plantillas, ni `render_informe.py` contienen «explorat» (grep sin resultados), aunque DECISIONES.md #10 dice que el auditor «se declara sistema exploratorio».
- **O6.** **[CORREGIDO 2026-11-19: doc. 17 actualizado]** `investigacion/17-comparacion-calidad-tokens.md:263` dice «kine us … nivel global N0 sin bloqueos». El `gates.json` vigente de la corrida 2110 (modificado 2026-11-19 00:04, después de #10) tiene 2 entradas de bloqueo sobre 1 control (SEG-SECRETO-BUNDLE, `pendiente_ia: true`). El documento 17 quedó desactualizado en ese punto.
- **A7.** El hook solo intercepta `Write|Edit|MultiEdit|NotebookEdit` (`hooks/hooks.json:6`); una escritura vía Bash no queda bloqueada.
- **A8.** El repo git no tiene commits (`git log`: «does not have any commits yet»): sirve para `--plugin-dir`, no para distribución por marketplace desde git.
- `skills/auditar-diff/` y `skills/auditar-sus/` están vacías.

---

### 3.3 Estado de las correcciones (2026-11-19, SÍNTESIS)

Corregidos con TDD (prueba en rojo antes del código). Suite completa: `python3 -I -m unittest discover -s tests` → `Ran 1226 tests … OK`, dos corridas seguidas (logs `defectos/integ_suite1.log` y `integ_suite2.log` en la scratchpad de la sesión). Corrida de integración sobre una copia nueva de la app sembrada, sin `.auditoria/` previa (`defectos/integ/`), `bin/auditar all … --modo profundo`.

| ID | Corrección | Pruebas | Evidencia de punta a punta |
|---|---|---|---|
| D1 | `--sin-red` / `AUDITOR_SIN_RED` apaga osv (`no_evaluado`, o `parcial` con base local `--offline`), `registro_deps` (`no_evaluado`), el ruleset remoto de semgrep (`parcial`) y fuerza zizmor `--offline`; el motivo del control cita «sin red (AUDITOR_SIN_RED)» (`scripts/estado.py`, `motivos_adaptadores`). El skill pide el permiso también para el atajo `all`. | `tests/test_sin_red.py`, `tests/test_sin_red_verificador.py` | Con `AUDITOR_SIN_RED=1` y `HTTPS_PROXY=HTTP_PROXY=http://127.0.0.1:9`: rc 0, 0 errores de red en stderr y crudos; osv y SEG-DEPS-EXISTEN `no_evaluado`, semgrep `parcial`, SEG-DEPS-CVE-CRIT y SEG-DEPS-EXISTEN `no_evaluado` con «sin red (AUDITOR_SIN_RED)»; 21 controles citan «sin red» en el motivo. |
| D2 | `veredictos.ajustar` antepone la frase «falso positivo crítico/alto según IA» a todo control que quede `no_evaluado` por cualquier vía, sin duplicarla al reaplicar. | `tests/test_d2_fp_sobre_no_evaluado.py` | Veredicto FP sintético sobre H-d06d0e597385 (DAT-RLS-PERMISIVA): con red, 14 bloqueos antes y 14 después (1 `pendiente_ia`); sin red, 12 y 12 (1 `pendiente_ia`). |
| A1 | `medir_tokens.py` acepta `--corrida`; sin DIR solo lee `C/transcripts/`, ignora los artefactos de la corrida (`veredictos.jsonl`, `hallazgos*.jsonl`…) y, sin mensajes con `usage`, no escribe `tokens.json` («no medido») y aparta uno previo como `.obsoleto`. | `tests/test_a1_medir_tokens_corrida.py` | Pendiente de diseño: el skill seguirá informando «no medido» hasta que los transcripts lleguen a `C/transcripts/`. |
| O1 | osv excluye `g:**/.auditoria` y la carpeta de la corrida; `bin/auditar` rechaza con rc 2 un `--salida` dentro del proyecto fuera de `.auditoria/`. | `tests/test_sin_red.py` (`TestOsvDosCorridasReal`), `tests/test_sin_red_verificador.py` | Segunda corrida `all` con red sobre la misma copia: osv lee solo `package-lock.json` en ambas, 59 vulnerabilidades en las dos (antes crecían 59 → 118 → 177). |
| O3 | gitleaks corre con `--redact=100`; `gitleaks_redactar.py` deja máscara + huella (columnas en bytes UTF-8) y `normalizar/gitleaks.py` no usa la línea del archivo si no hay huella. | `tests/test_gitleaks_redaccion.py` | En la corrida de integración: `gitleaks.json` 12 entradas y `gitleaks-bundle.json` 3, 0 con `Secret` en claro, todas con huella; 0 apariciones de los 13 valores secretos de referencia en todo `.auditoria/` (con y sin red). Solo aparece `VITE_SUPABASE_URL` (6), que es pública. |

**Límites que quedan:** las corridas antiguas no se reescriben (10 de las 11 de la app sembrada y las 7 de kine us conservan valores en claro en `crudo/gitleaks*.json`); una carpeta de corrida que ya exista dentro del proyecto fuera de `.auditoria/` se sigue escaneando; la ruta de la base OSV local no se verificó con una base descargada; U-1 (corrida vacía con `--salida` inexistente) seguía abierto en ese momento (corregido después; ver «Estado de las correcciones» al inicio).

## 4. Evaluación heurística (Nielsen) del flujo CLI y skills

Escala: 0 no es problema · 1 cosmético · 2 menor · 3 mayor · 4 catástrofe. **Todas las severidades son ESTIMACIÓN de un solo evaluador**; las evidencias son SÍNTESIS. Los informes evaluados son los de kine us, corrida `2026-11-18_2110-8f38a6d` (solo lectura).

| ID | Heurística | Problema | Sev. | Evidencia |
|---|---|---|---|---|
| H-1 | 1 Visibilidad / 3 Control | Rechazar la red no la apaga (D1); la CLI va a la red sin avisar. | **4** | `skills/auditar/SKILL.md:48`; `osv.meta.json` |
| H-2 | 3 Control / 9 Recuperación | Un falso positivo crítico verificado por una persona no tiene salida: el propio resumen dice que el auditor no tiene mecanismo para registrarlo. kine us queda en N0 indefinidamente. | **4** | kine `resumen-dueno.md:46`, `hoja-de-ruta.md:21` |
| H-3 | 5 Prevención de errores | `--salida` mal tipeado crea corrida vacía y `digest` da rc 0 (U-1). | 3 | `bin/auditar:68-71,86-89` |
| H-4 | 9 Mensajes de error | `digest <corrida>` sugiere una acción dañina (U-2). | 3 | `bin/auditar:90-92` |
| H-5 | 4 Consistencia | «Hay 0 problema(s) crítico(s) abierto(s)» (línea 7) y en la línea 11 un bloqueo N0 por SEG-SECRETO-BUNDLE; el tablero del informe muestra 3 críticos en SEG. Se cuentan solo críticos en `fail`; el bloqueante está en `no_evaluado`. | 3 | kine `resumen-dueno.md:7,11` (reverificado); `scripts/render_informe.py:890-892,959-961` |
| H-6 | 8 Minimalismo / 6 Reconocer | La numeración empieza en «Paso 2»; la acción n.º 1 (SEG-ENV-EJEMPLO, «para llegar a N1») no levanta el bloqueo N0; el bloqueante real va segundo. | 3 | `scripts/render_informe.py:893-901`; kine `resumen-dueno.md:36-47` |
| H-7 | 10 Documentación | `auditar-sus` no existe aunque `UX-SUS-68` la exige para N4 (`catalogo/controles.toml:2259-2270`): N4 de UX es inalcanzable. `auditar-diff` vacía. README desactualizado (O5). | 3 | `ls skills`; `README.md:58,71,81` |
| H-8 | 2 Lenguaje del usuario | El resumen «sin jerga» (línea 3) trae IDs de controles, `no_evaluado`, `pass`, `bundle`, `service_role`, `sk_live`, AKIA, `.gitleaksignore`, triage-fp, playwright_ux, detectar_stack, «F1», «LLM», `/auditar-doctor`. El redactor IA no corrió (línea 13: «Texto generado por plantilla, sin IA»). | 3 | kine `resumen-dueno.md:3,11,13,44-57` |
| H-9 | 9 Ayuda para resolver | «Verificar» manda a `/auditar-doctor` cuando falta una entrevista o un juicio (DAT-BACKUP, COD-FLUJOGRAMA, OPS-PERFIL-RIESGO). | 2 | kine `hoja-de-ruta.md` ítems 3, 5, 8 |
| H-10 | 4 Consistencia | OPS-PERFIL-RIESGO dice «juicio LLM no ejecutado en F1» en una corrida F3; no hay `perfil.json` ni `redaccion-dueno.json` y no se explica por qué. | 2 | kine `resumen-dueno.md:56` |
| H-11 | 2 Lenguaje | DAT recibe letra A y 100/100 con cobertura del 6 %; una «A» invita a lectura optimista pese a la marca gris. | 2 | tablero de kine `informe.md` |
| H-12 | 8 Minimalismo | 5 de 71 oraciones del resumen superan 30 palabras (máx. 50); frases repetidas en un mismo ítem. | 2 | `EV/scripts/largas.py` |
| H-13 | 1 Visibilidad | `auditar all` sin RUTA audita el cwd en silencio (rc 0), crea `.auditoria/` ahí y consulta osv.dev. | 2 | prueba |
| H-14 | 7 Flexibilidad | `--mode` no sugiere `--modo`; no hay `--version` ni ejemplos en `--help`. | 1 | `bin/auditar:2-28` |
| H-15 | 8 Estética | Plurales «(s)»: 11 en el resumen, 7 en el informe, 3 en la hoja de ruta. | 1 | `grep -c "(s)"` |
| H-16 | 10 Documentación | La instalación queda bajo 34 líneas de registro interno en el README. | 1 | `README.md:11-46` |

**A favor (SÍNTESIS):** códigos de salida documentados y coherentes (0/1/2/3/4); mensajes de uso cortos y en español; los informes usan SÍNTESIS/GUÍA/ESTIMACIÓN; siempre se informa la cobertura y se advierte que el auditor no certifica.

---

## 5. Legibilidad de los informes de kine us

### 5.1 Longitud (SÍNTESIS, `wc -w` reverificado)

| Archivo | Líneas | Palabras |
|---|---|---|
| informe.md | 413 | 9028 |
| hoja-de-ruta.md | 163 | 2735 |
| resumen-dueno.md | 62 | 832 |

El resumen se presenta como «una página» (`resumen-dueno.md:3`; `plantillas/resumen-dueno.md.tmpl:3`) y tiene 832 palabras: **ESTIMACIÓN**, unas 2 páginas a 400-500 palabras por página.

### 5.2 Índices (SÍNTESIS para los valores; script `EV/scripts/legibilidad.py`, solo stdlib)

Fernández-Huerta: L = 206,84 − 0,60·P − 1,02·F. Szigriszt-Pazos: 206,835 − 62,3·(síl./pal.) − (pal./oración). Variante A quita markdown y backticks; B además quita IDs en mayúsculas con guion. Sílabas por núcleos vocálicos (9/9 palabras de prueba correctas; es una aproximación).

| Archivo | Var. | Palabras | Síl./pal. | Pal./oración | Fernández-Huerta | Szigriszt-Pazos |
|---|---|---|---|---|---|---|
| resumen-dueno.md | A | 810 | 2,015 | 11,41 | 77,0 | 69,9 |
| resumen-dueno.md | B | 778 | 2,035 | 10,96 | 75,4 | 69,1 |
| hoja-de-ruta.md | B | 2647 | 2,081 | 11,98 | 73,5 | 65,2 |
| informe.md | B | 7571 | 2,148 | 12,62 | 69,9 | 60,4 |

**ESTIMACIÓN (interpretación):** Szigriszt-Pazos 65-80 se lee como «normal/bastante fácil», pero aquí sobreestima la facilidad: cortar en cada ítem de lista produce oraciones artificialmente cortas y la fórmula no detecta jerga. La barrera para una persona dueña no técnica es el vocabulario (H-8), no la sintaxis.

### 5.3 Tiempo hasta la primera acción

| Archivo | Primera acción | Palabras antes | ¿Es la correcta? |
|---|---|---|---|
| resumen-dueno.md | línea 38 | 271 | No: SEG-ENV-EJEMPLO no levanta N0; el bloqueante está en la línea 44. |
| informe.md | línea 116 | 1258 | Igual; antes hay un aviso legal de 24 líneas, el veredicto y «Qué falta». |
| hoja-de-ruta.md | línea 13 | — | Igual. |

**ESTIMACIÓN** (~200 palabras/min en lectura técnica): ~1,5 min hasta la primera acción en el resumen y ~6 min en el informe; la acción útil (verificar `dist/assets/leerDicomNavegador-*.js:5,10,11`) termina en el callejón de H-2.

---

## 6. Alcance por dominio

### 6.1 Catálogo (SÍNTESIS, `catalogo/controles.toml`; `grep -c '^\[\[control\]\]'` = 176)

| Dominio | Total | N1 | N2 | N3 | N4 | N5 | det. | mixto | llm | manual |
|---|---|---|---|---|---|---|---|---|---|---|
| SEG | 41 | 6 | 16 | 11 | 6 | 2 | 18 | 19 | 3 | 1 |
| DAT | 30 | 2 | 13 | 9 | 5 | 1 | 16 | 8 | 5 | 1 |
| UX | 28 | 1 | 10 | 10 | 5 | 2 | 14 | 8 | 2 | 4 |
| OPS | 28 | 2 | 7 | 11 | 7 | 1 | 5 | 10 | 2 | 11 |
| COD | 20 | 2 | 6 | 8 | 3 | 1 | 14 | 5 | 1 | 0 |
| INF | 18 | 2 | 5 | 7 | 4 | 0 | 10 | 6 | 2 | 0 |
| ESC | 11 | 0 | 3 | 4 | 3 | 1 | 3 | 5 | 0 | 3 |
| **Total** | **176** | 15 | 60 | 60 | 33 | 8 | 80 | 61 | 15 | 20 |

`evidencia_pass`: 80 `no_demostrable_estatico` (nunca pasan en estático), 59 `checks_pass`, 37 `ausencia_suficiente`. 9 controles bloquean el nivel global. 10 controles legales (OPS) no bloquean y nunca quedan en `pass` (`scripts/estado.py:48-53`).

Ejecutores reales: 4 adaptadores externos (gitleaks, semgrep, osv, zizmor) y 18 chequeos propios (`scripts/ejecutar_scanners.sh:34-55`), `detectar_stack`, 5 agentes y 4 skills con SKILL.md. `scripts/sondas/k6/`, `skills/auditar-sus/` y `skills/auditar-diff/` solo tienen `.gitkeep`.

### 6.2 Cobertura efectiva en modo estándar (SÍNTESIS; «cubiertos» = pass + fail sobre aplicables)

| Dominio | Sin ejecutor implementado (ESTIMACIÓN) | kine us | App sembrada |
|---|---|---|---|
| SEG | 6 | 9/33 (27 %) | 16/41 (39 %) |
| DAT | 8 | 1/17 (6 %) | 5/28 (18 %) |
| COD | 7 | 7/20 (35 %) | 6/20 (30 %) |
| UX | 12 | 1/27 (4 %) | 0/26 (0 %) |
| INF | 4 | 0/8 (0 %) | 1/11 (9 %) |
| ESC | 7 | 0/10 (0 %) | 0/11 (0 %) |
| OPS | 1 | 1/23 (4 %) | 2/28 (7 %) |
| **Total** | **45** | **19/138 (14 %)** | **30/165 (18 %)** |

Estados globales: kine us pass 7, fail 12, no_evaluado 100, no_aplica 38, manual_pendiente 19; app sembrada pass 3, fail 27, no_evaluado 115, no_aplica 11, manual_pendiente 20. De lo cubierto, 17/19 (kine; los otros 2, SEG-ERRORES y COD-DOC-AGENTE, son `mixto`) y 23/30 (app; 7 `mixto`) lo cubren controles con `metodo = determinista`.

**Por qué quedan `no_evaluado`** (kine / app): juez LLM no ejecutado u omitido 41 / 32; herramienta o sonda no ejecutada 40 / 56; falta pase explícito 5 / 10; fuera del modo estándar (N5) 7 / 8; falta respuesta de entrevista 4 / 5; otros 3 / 4. En kine us, 15 controles quedaron sin juez por «falta flujograma confirmado».

**Calidad ya medida** (`investigacion/17-comparacion-calidad-tokens.md:258-260`): en la app sembrada, detección 60/67 = 0,90 (IC 0,80-0,95), VPP 60/91 = 0,66 (IC 0,56-0,75), 0/56 controles limpios disparados. kine us: N0, puntaje 55,3 (D) (`:263`; ver O6 sobre los bloqueos).

### 6.3 Stacks (SÍNTESIS, `scripts/detectar_stack.py`)

Detecta 17 familias de lenguaje por extensión (líneas 36-43), 15 frameworks Node (46-50) y 6 Python (52-53), además de ORM, BaaS, SDKs de LLM, pagos, emails, móvil, PWA, configuración de agentes y ~25 plataformas de despliegue. Fixtures: solo 5 stacks (docker, estatico, fastapi, next_prisma, vite_supabase). Go, Ruby, Rust, PHP y Dart: solo manifiesto y lockfile (líneas 128-134). SAST de inyección en Python solo con Flask/Django/Pyramid/Lambda (kine us: SEG-SAST-INY quedó `no_evaluado` por eso). Reglas propias de semgrep: 10 JS/TS y 7 genéricas; nada propio para Python, Java ni Go.

**ESTIMACIÓN:** sin cobertura real para Java/Kotlin, Swift, C#, Elixir, móvil nativo, ni Go/Rust/Ruby/PHP más allá de manifiestos.

---

## 7. Límites

1. **Exploratorio y validación piloto n = 1 por brazo** (una app sembrada del mismo equipo, una auditoría real). El set reservado ya no es ciego para D39 y D53 (README, bloque de validación).
2. **Tokens sin medir:** 0 de 9 llamadas headless llegaron a la API (`investigacion/17…md:5,73,83-85`); además A1 impide generar `tokens.json` desde el skill. El criterio «estándar ≤ 60 k tokens» sigue sin verificar.
3. **Sin vía para registrar verificación humana:** 20 manuales, 10 legales y los falsos positivos graves no pueden cerrarse por diseño (`scripts/estado.py:322-323,49-53`; `scripts/veredictos.py:9-11,539`). ESTIMACIÓN por búsqueda con grep.
4. **F4/F5 pendientes:** sin sondas UX (Playwright/axe/LHCI) ni pruebas dinámicas o de carga (k6, ZAP, nuclei) (README.md:108-109; PLAN_MAESTRO.md:559-560).
5. **Jueces LLM** no deterministas ni medidos con κ en sesión limpia (PLAN_MAESTRO.md §12 #5); en estándar, UX no se lanza y arquitectura se omite sin flujograma.
6. **Umbrales y pesos** con `origen = "propuesta"`, sin norma (PLAN_MAESTRO.md §12 #7). El puntaje es informativo; el nivel lo decide `gates.py` (nota de `score.json`).
7. **Legal:** el auditor no afirma cumplimiento (estado.py:48-53, 77); no hay revisión contra el texto de la Ley 19.628 ni otras.
8. **Falsos negativos conocidos:** cookies sin HttpOnly/Secure/SameSite, task/tox/nox, `jest --passWithNoTests`, JSON anidado (README.md:20,44).
9. **Esta evaluación:** sin `claude` (no se verificó la carga del plugin ni los skills en sesión), sin `--modo profundo`, sin rerun de la suite, un evaluador heurístico, sin usuarios.

---

## 8. Mejoras priorizadas

Esfuerzo: S = horas, M = días, L = semanas. **Prioridad y esfuerzo son ESTIMACIÓN.** La decisión de qué abordar es del investigador.

| Prio | Mejora | Resuelve | Sev. | Esf. |
|---|---|---|---|---|
| 1 | Hacer real el «no» a la red: que `AUDITOR_SIN_RED=1` apague osv (dejar `no_evaluado` «sin red» o usar modo offline si la versión instalada lo trae; **no verificado**), registro_deps y el registro de semgrep. En la CLI, anunciar la red en stderr o exigir `--con-red`/`--sin-red`. | D1, H-1 | 4 | S-M |
| 2 | Corregir `veredictos.py:534-540` para que el motivo FP se escriba también cuando el control ya sale `no_evaluado` por otra vía; test de regresión con DAT-RLS-PERMISIVA. | D2 | 4 | S |
| 3 | Mecanismo de «falso positivo verificado por persona»: archivo en la corrida (quién, fecha, archivo:línea, conclusión) que deje el control en un estado propio, visible y auditable, sin `pass` automático. Requiere decisión del investigador (toca DECISIONES #9/#10). | H-2, límite 3 | 4 | M |
| 4 | Validar `--salida` (rc 4 si falta `run.json` en subcomandos que exigen corrida) y detectar si RUTA es una corrida. | U-1, U-2, H-3, H-4 | 3 | S |
| 5 | Corregir el skill: `medir_tokens.py` con el directorio de transcripts; en `auditar-perfil`, escribir `respuestas.json` y no `perfil.json`. | A1, A3 | 3 | S |
| 6 | Resumen y «Qué hacer ahora»: contar como crítico todo crítico que bloquee el nivel; poner primero el ítem con `bloqueo`; numeración continua. | H-5, H-6 | 3 | S |
| 7 | Resumen del dueño realmente sin jerga: traducir IDs, glosario breve, tope de palabras y una acción principal; test que falle si aparecen IDs o `no_evaluado`. | H-8, H-12 | 3 | M |
| 8 | `skills/auditar-sus` (carga CSV, SUS con IC95 %) o retirar la exigencia de N4 mientras no exista; marcar `auditar-diff` como F7. | H-7 | 3 | M |
| 9 | Declarar «sistema exploratorio» en README, informe y resumen (hoy 0 apariciones). | O5, DECISIONES #10 | — | S |
| 10 | Correr gitleaks con `--redact` o enmascarar `crudo/gitleaks*.json`; excluir `.auditoria/` del escaneo de osv. | O3, O1 | 2 | S |
| 11 | «Verificar» según la causa (entrevista → perfil; juicio → auditar; herramienta → doctor); explicar en el veredicto la falta de `perfil.json`/`redaccion-dueno.json`; corregir «F1». | H-9, H-10 | 2 | S |
| 12 | Sin letra ni puntaje cuando la cobertura es insuficiente. | H-11 | 2 | S |
| 13 | `auditar` sin RUTA: exigirla o anunciar el cwd; sugerencias de opciones; `--version`; ejemplos en `--help`. | H-13, H-14 | 2 | S |
| 14 | README: reordenar (qué es, instalar, uso), prefijo de plugin en los comandos, 4 skills, 176 controles, cifra de pruebas actual, `resumen-dueno.md`; actualizar `investigacion/17…md:263`. | O5, O6, H-16 | 1-3 | S |
| 15 | Unificar el conteo de bloqueos (entradas frente a controles) entre consola e informe; plurales correctos. | O2, H-15 | 1 | S |
| 16 | Ejecutores para F4/F5 (los 45 controles sin ejecutor). | alcance | — | L |
| 17 | Protocolo SUS (§10) tras aplicar 1-8. | validación | — | L |

---

## 9. Contradicciones entre evaluadores y su resolución

| Punto | Discrepancia | Resolución (comando corrido por el sintetizador) |
|---|---|---|
| Bloqueos de la app sembrada | Consola «14» frente a «11» en el informe. | `gates.json` de `…/2026-11-19_0016-sin-git`: `global.bloqueos` tiene 14 entradas sobre 11 controles distintos. Ambas cifras son correctas; miden cosas distintas (O2). |
| Bloqueos de kine us | `investigacion/17…md:263` dice «sin bloqueos»; usabilidad y el resumen muestran 1. | `gates.json` vigente (modificado 2026-11-19 00:04): N0, NO, 2 entradas sobre 1 control (SEG-SECRETO-BUNDLE, `pendiente_ia: true`). El documento 17 está desactualizado (O6). |
| Número de controles | README 174 frente a 176. | `grep -c '^\[\[control\]\]' catalogo/controles.toml` = 176. |
| Bug de tokens | Solo activación lo reportó. | `python3 -I scripts/medir_tokens.py --corrida …` → rc 2, «unrecognized arguments: --corrida». Confirmado. |
| Variable de red | Funcionamiento, usabilidad y activación coinciden. | `grep -rn SIN_RED bin scripts skills hooks`: solo `SKILL.md:48` y `registro_deps.py:20,95-96`. Confirmado. |
| Mención «exploratorio» | Funcionamiento: ausente en las salidas. | `grep -rli explorat README.md plantillas scripts/render_informe.py` → sin resultados. Confirmado. |

---

## 10. Protocolo SUS pendiente (GUÍA; parámetros ESTIMACIÓN a decidir por el investigador)

**SUS: no medido.** No se puede calcular sin usuarios reales.

- **Bloqueo previo:** no existe `skills/auditar-sus` para cargar resultados (H-7); aunque se mida, N4 de UX no se puede otorgar hasta implementarla.
- **Perfiles y n:** (a) desarrollador que usa Claude Code, n ≥ 5; (b) persona dueña no técnica que lee solo `resumen-dueno.md`, n ≥ 5. Total 10-12. El plan pide «≥ 5 usuarios por perfil» con IC95 % (`PLAN_MAESTRO.md:402`). Con n = 5 el IC95 % será amplio: reportar como piloto (DECISIONES #8).
- **Tareas** (en un proyecto de prueba, nunca la app sembrada como cwd de Claude Code ni datos reales): T1 instalar el plugin y correr el diagnóstico; T2 auditar en modo rápido; T3 decir el nivel y si está listo para datos reales; T4 identificar la primera acción que levanta el bloqueo; T5 regenerar el informe; T6 (solo dueño) explicar con sus palabras qué debe hacer.
- **Medidas:** éxito por tarea (sí/no), tiempo, errores, pensamiento en voz alta; SUS al final; UMUX-Lite opcional.
- **Instrumento:** versión en español validada del SUS: Sevilla-Gonzalez MDR et al. *Spanish Version of the System Usability Scale for the Assessment of Electronic Tools: Development and Validation.* JMIR Hum Factors. 2020;7(4):e21161. PMID 33325828. doi:10.2196/21161 (validada en población mexicana; adaptación a Chile no verificada). Escala original: Brooke J. «SUS: a quick and dirty usability scale», 1996, capítulo de libro sin DOI ni PMID: **referencia a verificar**.
- **Análisis:** SUS 0-100 por participante; media con IC95 % (t) por perfil; comparación descriptiva con 68 (umbral que fija el plan para N4).
- **Ética:** consentimiento informado; sin datos personales en grabaciones. Si se formaliza, considerar Ley 19.628 y Ley 20.120 y el comité de ética correspondiente; este documento no afirma cumplimiento.

---

## 11. Fuentes de esta síntesis

- Evaluaciones del 2026-11-19: funcionamiento, usabilidad, activación y alcance (scripts y logs en `EV/`: `logs/`, `scripts/legibilidad.py`, `scripts/largas.py`, `scripts/chequear_sarif.py`, `alcance_estado.py`, `alcance_cat.py`, `alcance_tabla.py`, `activacion-*`).
- Guía de activación derivada: `docs/ACTIVAR.md`.

---

## 12. Verificación crítica (2026-11-19, posterior a la síntesis)

Re-ejecución independiente de las cifras clave (logs en `EV/critico/`; copia nueva de la app sembrada sin `.auditoria/` previa y un proyecto trivial nuevo; kine us solo leído en `.auditoria/2026-11-18_2110-8f38a6d/`).

- **Confirmado (SÍNTESIS):** 176 controles y la tabla completa de §6.1 (dominio × gate × método; `evidencia_pass` 80/59/37; 9 `bloquea_global`; 10 `aviso_legal`); `doctor` rc 0, 24 herramientas, 9 presentes (gitleaks 8.30.1, semgrep 1.181.0, osv-scanner 2.7.0, zizmor 1.32.0, node, npx, python3, jq, git), 3,0 s; `all` sobre la app: rc 0, 135 crudos, 83 hallazgos (86 sin tope), N0, 5,8 (E), cobertura 0,182, «bloqueos 14» = 14 entradas sobre 11 controles, SARIF 2.1.0 con 27 reglas y 86 resultados, estados 3/27/115/11/20 y 30/165 cubiertos con el mismo desglose por dominio de §6.2; `all` sobre el proyecto trivial: N0, 31,8 (D), 7 hallazgos, estados 2/6/107/42/19, 7,0 s; kine us: estados 7/12/100/38/19, 19/138 con el desglose de §6.2, N0, 55,3 (D), 2 entradas de bloqueo sobre SEG-SECRETO-BUNDLE con `pendiente_ia: true`; `medir_tokens.py --corrida` rc 2; `grep SIN_RED` como en §9; `veredictos` sin JSONL rc 1; adaptador de gitleaks sin `--redact` (grep vacío); 4 adaptadores + 18 chequeos (`scripts/ejecutar_scanners.sh:34-55`); reglas propias de semgrep 10 JS/TS + 7 `generic` (IaC); git sin commits; líneas citadas de README (5, 58, 61, 71, 81, 123) y de `veredictos.py` (519, 536-540).
- **Corregido en este documento:** cita `bin/auditar:71-74` → `68-71` (U-1, H-3); conteo de secretos en `gitleaks.json` (decía 6; son 12 entradas, 9 valores distintos); cobertura determinista de kine us (decía 18/19; es 17/19); línea de frameworks Python (51 → 52-53).
- **Variabilidad de tiempos (SÍNTESIS):** la misma auditoría estándar de la app sembrada tardó 19,1 s en la evaluación y 13,2 s al repetirla; buena parte del escaneo depende de la red (osv, registro). En kine us, `run.json` registra `duracion_s` doctor 3 + stack 1 + scan 17 + normalize 14 (≈ 35 s, segundos enteros) para un proyecto real.
- **Sigue sin evidencia en esta evaluación:** carga real del plugin y los skills en Claude Code; `--modo profundo`; suite de pruebas (1148 es contexto, no re-ejecutado aquí); los 45 controles «sin ejecutor» (ESTIMACIÓN del script `alcance_tabla.py`, no reproducida); severidades heurísticas (un evaluador); índices de legibilidad (no recalculados).

