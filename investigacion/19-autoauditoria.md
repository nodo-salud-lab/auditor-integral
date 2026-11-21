# 19 · Autoauditoría del auditor (2026-11-20)

El auditor se aplicó a su propio repositorio. Este documento registra el método, el resultado de la primera corrida, la clasificación de sus hallazgos, las correcciones que se hicieron sobre la herramienta y el resultado de la corrida posterior. Termina con una valoración de qué significa, y qué no, que una herramienta «se audite a sí misma».

Corridas comparadas:

- **Antes:** `.auditoria/2026-11-20_0031-sin-git`
- **Después:** `.auditoria/2026-11-20_0139-sin-commits`

(La corrida `2026-11-20_0137-sin-commits` fue una ejecución intermedia de verificación de las correcciones y no se usa en la comparación.)

## 1. Método

- **Objeto auditado:** el propio proyecto `auditor-integral`, que es a la vez la herramienta que audita. No se excluyó ninguna carpeta por decisión ad hoc: `tests/`, `tests/fixtures/`, `validacion/app-sembrada/` y `reglas/` entraron al alcance tal como entraría cualquier otro repositorio.
- **Modo:** `estandar`, con `--sin-red` en todas las fases (no había autorización de red). Por eso osv y el registro de dependencias no corrieron, y los controles que dependen de ellos quedaron `no_evaluado` con motivo «sin red» (21 antes, 19 después).
- **Perfil:** la sesión no era interactiva, así que no se respondió la entrevista. Las 16 preguntas quedaron pendientes y los controles que dependen de declaraciones del investigador quedaron `no_evaluado`.
- **Verificación humana:** no se usó `--fp-verificados`. Ningún falso positivo se descartó por decisión humana; todo lo que la IA marcó como falso positivo sobre un crítico o alto siguió contando según la regla fail-closed.
- **Corte temprano:** en ambas corridas hubo bloqueos de N1 en controles SEG-* y DAT-*, de modo que el protocolo solo permitió lanzar el juez `triage-fp`. `revisor-autorizacion` y `revisor-arquitectura` se omitieron por el corte; `revisor-ux` no corresponde al modo estándar. Sus controles quedaron `no_evaluado`.
- **Jueces LLM emulados.** El plugin no estaba instalado en la sesión. El juez `triage-fp` fue **emulado** por un agente que siguió literalmente `agents/triage-fp.md`, leyó solo `digest/triage.json` y escribió `veredictos.jsonl` (10 líneas en cada corrida). Esto no equivale a una ejecución del plugin: el prompt de sistema, el contexto y el modelo efectivo pueden diferir, y la calidad de juicio observada aquí no es transferible sin más al uso real.
- **Digest incompleto.** El digest de triage tiene un tope de 4000 tokens. Antes quedaron 619 ítems recortados y 488 críticos o altos sin juzgar; después, 623 recortados y 485 sin juzgar. Esos hallazgos quedan como `incierto` y cuentan como verdaderos.
- **Tokens:** `medir_tokens.py` terminó con rc=0 pero informó «no medido» (no encontró transcripts con `message.usage` y no escribió `tokens.json`). **El consumo de tokens de esta autoauditoría no se midió.**
- **Tiempos (reloj de pared, antes / después):** doctor 4,58 / 3,19 s; scan 16,86 / 9,94 s; normalize 3,36 / 2,43 s; digest 1,5 / 1,87 s. Todas las fases terminaron con rc=0. La diferencia del scan no se investigó y no debe leerse como mejora de rendimiento (caché del sistema y carga de la máquina no se controlaron).
- **Secretos:** ningún valor de secreto se imprimió ni se copia en este documento. Los hallazgos se citan por id, regla y ubicación.

## 2. Resultado inicial (corrida 0031)

> **SÍNTESIS** (datos de `estado.json`, `gates.json` e `informe.md` de la corrida)

- **Nivel global:** N0 demostrado, N0 potencial. Hito «Ninguno: no apto para uso». ¿Listo para datos reales?: **NO**.
- **Puntaje informativo:** 4,4/100, letra E, cobertura 15 %. IUA sin datos (0 de 6 componentes).
- **Niveles por dominio:** SEG N0, DAT N0, COD N0, OPS N0, UX N0 (potencial N1), INF N0 (potencial N1), ESC N1.
- **Hallazgos:** 1053 crudos; 787 normalizados tras el tope (818 sin tope): 469 críticos, 29 altos, 40 medios, 249 bajos.
- **Controles (176):** pass 2 (INF-INVENTARIO, OPS-HEALTH) · fail 24 · no_evaluado 125 · manual_pendiente 20 · no_aplica 5.
- **Bloqueos (6 controles):**

| Control | Tipo | Tope | Hallazgos |
|---|---|---|---|
| SEG-SECRETO-REPO | secreto_vivo (+ bloquea_global N1) | N0 | 441 |
| SEG-SECRETO-BUNDLE | secreto_vivo (+ bloquea_global N1) | N0 | 5 |
| SEG-ENV-PUBLICAS | secreto_vivo (+ bloquea_global N1) | N0 | 4 |
| DAT-SQL-CONCATENADO | bloquea_global | N1 | 6 |
| SEG-AUTH-CLIENTE | critico_seg_dat | N1 | 9 |
| SEG-PAGOS-SERVIDOR | critico_seg_dat | N1 | 4 |

- **Juicio IA (emulado):** 10 veredictos sobre el material que cupo en el digest: 6 `incierto`, 4 `falso_positivo` (los cuatro sobre el mismo texto de prueba de concepto de un aviso GHSA copiado en salidas OSV de corridas de test). Ninguno movió un estado.

## 3. Clasificación de los hallazgos (triage)

El triage fue de solo lectura y separó tres clases. Las cifras de cada grupo son las que dio el triage; donde dice «unos» es una cuenta aproximada por carpeta, no un recuento exacto.

### 3.1 Defectos reales del proyecto

| Defecto | Hallazgos | Prioridad |
|---|---|---|
| El arnés de tests escribía temporales dentro del árbol (`tests/.tmp`) y no garantizaba su limpieza si `setUpClass` fallaba o la corrida se interrumpía. Los restos con canarios generaban unos 559 de los 605 hallazgos de gitleaks del árbol, 2 de los 5 de SEG-SECRETO-BUNDLE y 1 de SEG-SAST-INY. | unos 395 en SEG-SECRETO-REPO (tests/.tmp) y los anteriores | Alta (contamina toda autoauditoría) |
| Repositorio git sin ningún commit (COD-REPRO). | 1 | Media |
| Sin archivo de licencia (COD-LICENCIAS). | 1 | Media; decisión del investigador |
| Sin CLAUDE.md ni AGENTS.md (COD-DOC-AGENTE). | 1 | Media |
| Sin CI (COD-CI-BASICO). | 1 | Baja mientras no haya remoto |
| Complejidad ciclomática alta en la lógica central fail-closed (`veredictos.evaluar` CCN 107, `detectar_stack.detectar` 105, `estado.calcular` 96, entre otras). | 108 | Media-baja |
| Duplicación de arranque de tests y de `main()` de fases (9,1 % frente a umbral de 5 %). | 158 | Baja |

Los valores con forma de secreto del arnés son canarios falsos generados en tiempo de ejecución: el defecto es de higiene del arnés, no una exposición de credenciales.

### 3.2 Hallazgos esperados (el detector funciona como debe)

- **Casos de prueba de reglas semgrep** (`reglas/semgrep/vibe-coding/*`): 33 hallazgos en SEG-AUTH-CLIENTE, SEG-PAGOS-SERVIDOR, DAT-SQL-CONCATENADO, SEG-SAST-INY, SEG-JWT, SEG-CORS, SEG-ERRORES, DAT-PAGINACION y SEG-ENV-PUBLICAS. Cada línea marcada lleva un comentario `// ruleid:`: es código vulnerable a propósito para `semgrep --test`.
- **Caso de prueba IaC** (`reglas/semgrep/iac/iac-terraform.tf`): 4 hallazgos de INF-IAC y 1 de SEG-SECRETO-REPO (literal de prueba con `gitleaks:allow`, que el adaptador ignora deliberadamente con `--ignore-gitleaks-allow`).
- **App sembrada** (`validacion/app-sembrada/`): 22 hallazgos con id más 12 dentro del grupo de secretos. Coinciden con la verdad de terreno; detectarlos es la prueba de sensibilidad, no un riesgo.
- **Crudo de ejemplo** (`tests/fixtures/crudo/app_sembrada/`): unos 22 hallazgos de canarios falsos.
- **Fixtures de stacks** (`tests/fixtures/stacks/*`): 10 hallazgos (meta viewport ausente, Dockerfile como root, k8s sin non-root, dependencias sin uso), propios de un fixture mínimo.
- **Controles `no_evaluado` y `manual_pendiente`** por modo estándar, `--sin-red`, app no levantada y entrevista sin responder: conducta fail-closed esperada.

### 3.3 Defectos del propio auditor

El triage identificó 11. Los que se describen con evidencia en el código son:

1. **Pase falso de OPS-HEALTH:** `archivos_clave.py` aceptaba como evidencia de un endpoint `/health` un literal escrito en `tests/test_checks.py`. Era una de las dos únicas pasadas de la corrida.
2. **`dockerfile.py` se leía a sí mismo como Dockerfile:** `es_dockerfile` aceptaba `dockerfile.<cualquier extensión>`, y la línea `from pathlib import Path` se interpretaba como `FROM`. Generaba 2 hallazgos de INF-DOCKERFILE sobre el propio script.
3. **gitleaks del árbol no excluía `__pycache__`:** 3 hallazgos sobre bytecode, donde Python pliega concatenaciones de literales en cadenas con forma de secreto que el fuente no tiene.
4. **Perfil técnico contaminado:** banderas como servidor, pagos, docker, k8s o multi_idioma se activaban con evidencia de fixtures y tests.
5. **El informe contaba como «juicios de la IA» las entradas sintéticas del tope** (498 «aplicadas» cuando la IA solo emitió 10 veredictos).
6. **Texto de tokens impreciso** cuando `medir_tokens.py` corre pero no encuentra transcripts.
7. **El número de un bloqueo no distinguía** los críticos/altos marcados como falso positivo por la IA sin verificación humana.
8. **El id de corrida decía `sin-git`** para un repositorio existente sin commits.
9. **IaC pasaba con archivos de tests/fixtures** como única evidencia.
10. **SEG-ENV-EJEMPLO** falla en un proyecto que no usa variables de entorno.
11. **Agrupación de secretos en el digest:** cientos de ítems del mismo origen consumen el tope de 4000 tokens.

## 4. Correcciones aplicadas

Se corrigieron 9 de los 11 defectos del auditor (puntos 1 a 9) y el defecto del arnés de tests. Detalle de archivos en el bloque «Autoauditoría del 2026-11-20, corregido» del README.

- **Arnés:** los temporales de tests se crean en `<tempdir del sistema>/auditor-integral-tests` (configurable con `AUDITOR_TESTS_TMP`) y se limpian con `addCleanup`/`addClassCleanup` aunque falle el `setUp`. Al aplicarlo apareció un test (`test_confidencial.test_sin_git_inventario_y_pass`) que solo pasaba porque dependía, sin declararlo, del repositorio del propio auditor; se rearmó con un repo temporal explícito y se añadió `test_sin_git_no_aplica`.
- **Criterio único de tests y fixtures** (`comun.es_test_o_fixture`), usado para que tests y fixtures sigan **generando hallazgos** pero ya **no den pases** ni activen banderas del perfil (quedan en `evidencia_secundaria`).
- **No aplicados, por decisión explícita:**
  - *SEG-ENV-EJEMPLO:* el mecanismo es real, pero el arreglo afloja el control y el único beneficiado sería el propio auditor. Queda para decisión del investigador.
  - *Agrupar secretos en el digest:* no cambia ningún estado (verdadero e incierto cuentan igual) y exige cambiar el contrato digest/veredictos/agentes.
- **No hecho porque requiere autorización:** vaciar `tests/.tmp` (borrado) y el commit inicial. Por eso los restos del arnés siguen presentes en la corrida posterior.

**Verificación.**

> **SÍNTESIS**

- Suite completa: línea base 1330 pruebas OK; tras los cambios, 1353 pruebas OK en la tercera corrida. Hubo una corrida intermedia con 1 fallo en `test_timeout_por_herramienta` ('error' != 'timeout'), que pasó 3 de 3 veces aislado; se interpreta como inestabilidad bajo carga, no se corrigió y debe seguir vigilándose.
- App sembrada (modo estándar, sin red, sin IA): antes y después, VP 45 · FP 14 · FN 22, sensibilidad global 45/67 (0,67; IC95 % 0,55–0,77). `hallazgos_todos.jsonl` y `gates.json` idénticos byte a byte. Las correcciones no cambiaron la detección sobre el objeto de validación.

## 5. Resultado posterior (corrida 0139)

> **SÍNTESIS**

- **Nivel global:** N0 demostrado, N0 potencial. Hito «Ninguno: no apto para uso». ¿Listo para datos reales?: **NO**.
- **Puntaje informativo:** 2,3/100, letra E, cobertura 15 %. Bajó porque desapareció el pase falso de OPS-HEALTH: el puntaje anterior estaba inflado por un error de la herramienta.
- **Niveles por dominio:** sin cambios salvo INF, cuyo potencial sube de N1 a N3. Coincide con que INF-DOCKERFILE, INF-K8S y otros controles INF pasan a `no_aplica` al dejar de contar los fixtures; la causa exacta del salto no se desglosó.
- **Hallazgos:** 790 normalizados (820 sin tope): 466 críticos, 29 altos, 39 medios, 256 bajos.
- **Controles (176):** pass 1 (INF-INVENTARIO) · fail 24 · no_evaluado 119 · manual_pendiente 20 · no_aplica 12.
- **Bloqueos:** los mismos 6 controles. SEG-SECRETO-REPO queda con 433 hallazgos en la lista de bloqueo (438 en total; los 5 marcados falso positivo por la IA siguen sin descartarse por falta de verificación humana).
- **Juicio IA (emulado):** 10 veredictos: 5 `incierto`, 5 `falso_positivo`. Ninguno movió un estado. 485 críticos/altos sin juzgar por el tope, ahora informados como tales.

## 6. Comparación con `comparar_corridas.py`

Comando (solo lectura):

```
python3 -I scripts/comparar_corridas.py \
  --antes  .auditoria/2026-11-20_0031-sin-git \
  --despues .auditoria/2026-11-20_0139-sin-commits
```

Tabla resumida de su salida:

| | Antes | Después |
|---|---|---|
| Modo | estandar | estandar |
| Controles con motivo «sin red» | 21 | 19 |
| Versión del auditor | 0.1.0 | 0.1.0 |
| Nivel global | N0 (pot. N0) | N0 (pot. N0) |
| ¿Listo para datos reales? | NO | NO |
| Bloqueos (controles) | 6 | 6 |
| INF | N0 (pot. N1) | N0 (pot. N3) |
| SEG, DAT, COD, OPS | N0 (pot. N0) | N0 (pot. N0) |
| UX | N0 (pot. N1) | N0 (pot. N1) |
| ESC | N1 (pot. N1) | N1 (pot. N1) |

Controles que cambiaron de estado (8): OPS-HEALTH pass → fail; INF-DOCKERFILE fail → no_aplica; DAT-POOLER, INF-EMAIL-ASYNC, INF-EMAIL-DNS, INF-K8S, INF-TAREAS-LARGAS y UX-I18N no_evaluado → no_aplica.

Hallazgos nuevos: 21 (20 de COD-COMPLEJIDAD/COD-DUPLICACION en tests, en buena parte por el archivo nuevo `test_autoauditoria_r5.py` y el desplazamiento de líneas, y 1 de OPS-HEALTH). Hallazgos que ya no aparecen: 18 (13 de complejidad/duplicación, probablemente por el mismo desplazamiento, los 2 de INF-DOCKERFILE sobre `dockerfile.py` y los 3 de `__pycache__`).

**Aviso de comparabilidad** (del propio script): que un hallazgo no aparezca no prueba que esté corregido; también desaparece si la herramienta no corrió o si cambió el alcance. La comparación no cambia ningún estado y el auditor no certifica seguridad. A eso se agregan tres reservas propias de este caso:

1. **Cambió la herramienta, no solo el objeto.** Ambas corridas declaran versión 0.1.0, pero el código del auditor es distinto entre una y otra. Las diferencias mezclan cambios del proyecto con cambios del instrumento de medida, y la etiqueta de versión no lo refleja.
2. **Cambió el alcance de los no_aplica.** Seis de los ocho cambios de estado vienen de que el perfil técnico ya no enciende banderas con evidencia de fixtures, no de cambios en el proyecto.
3. **Los controles «sin red» bajaron de 21 a 19** por la misma razón (menos controles aplicables), no porque se haya usado la red.

## 7. Conclusión: ¿se «solucionó a sí misma»?

**No en el sentido literal, y el resultado lo muestra.** El nivel sigue en N0, los seis bloqueos siguen ahí y el puntaje bajó.

**Qué corrigió.** La autoauditoría sí funcionó como prueba de la herramienta: expuso un pase falso (OPS-HEALTH), un detector que se confundía con su propio código (`dockerfile.py`), escaneo de bytecode, un perfil contaminado por fixtures, un informe que sobrestimaba el trabajo de la IA y un arnés de tests que ensuciaba el árbol. Se corrigieron 9 de 11 defectos del auditor sin cambiar la detección sobre la app sembrada (45/67, idéntica byte a byte). Todas las correcciones fueron en la dirección fail-closed: un pase desapareció y ningún fail se convirtió en pass.

**Qué quedó por diseño.** La mayoría de los bloqueos provienen de material vulnerable a propósito: casos de prueba de reglas semgrep, la app sembrada, fixtures y restos de canarios en `tests/.tmp`. El auditor no sabe, ni debe suponer sin verificación humana, que un secreto es falso; por eso sigue bloqueando. Además, buena parte del catálogo (servidor, UX, pagos, despliegue) no tiene sentido para un plugin CLI en Python: esos controles quedan `no_evaluado`, `manual_pendiente` o, peor, disparan contra muestras de reglas. El nuevo fail de OPS-HEALTH es un ejemplo: la detección de «servidor» se activa por `reglas/semgrep/vibe-coding/cors-comodin-credenciales.js`, una muestra de regla, no un servidor real. Es más estricto que el pase falso anterior, pero tampoco es correcto para este proyecto.

> **ESTIMACIÓN.** Con `tests/.tmp` vaciado y una exclusión declarada de `reglas/` y `validacion/` revisada por una persona, gran parte de los bloqueos de secretos probablemente desaparecería; los defectos reales restantes (sin commits, licencia, CI, doc para agentes, complejidad) seguirían dejando a COD en N0. Esto no se ha medido.

**Qué no puede juzgar sobre sí misma.** Aquí el mismo sistema define los controles, escribe los detectores, decide qué cuenta como esperado y mide el resultado. Ese circuito tiene un sesgo de autoevaluación estructural: los defectos que comparte el diseñador del catálogo y el del detector (un control mal definido, un umbral arbitrario, una categoría de riesgo ausente) son invisibles para la autoauditoría. Además, la clasificación «esperado frente a real» la hizo un agente siguiendo las propias reglas del proyecto, los jueces fueron emulados y no hubo verificación humana. La autoauditoría sirve como prueba de regresión y de higiene, no como validación. La validez externa sigue dependiendo de la app sembrada (con su verdad de terreno escrita por el mismo autor) y, sobre todo, de una revisión independiente que aún no existe.

## 8. Pendientes

- Vaciar `tests/.tmp` (requiere confirmación explícita del investigador) y repetir la autoauditoría.
- Hacer el commit inicial (requiere autorización expresa).
- Decidir licencia, CLAUDE.md/AGENTS.md y CI.
- Decidir SEG-ENV-EJEMPLO y la agrupación de secretos en el digest.
- Revisar que la detección de «servidor» no se active con muestras de `reglas/` (sin perder recall en proyectos reales).
- Subir la versión del auditor cuando cambie el código, para que `comparar_corridas.py` pueda advertir comparaciones entre versiones distintas.
- Medir tokens en una sesión con transcripts disponibles, con el plugin instalado y jueces no emulados.
- Vigilar `test_timeout_por_herramienta` (inestable bajo carga).
