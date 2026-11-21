# 17 · Comparación de calidad entre brazos (F3) y costo en tokens

Fecha: 2026-11-18. Estudio piloto (DECISIONES.md #8): se informan todas las métricas con IC95 % de Wilson, sin umbral duro de aprobado. No se modificó código del auditor. Los scripts de medición nuevos están en `validacion/comparar_brazos.py` (pruebas en `tests/test_comparar_brazos.py`, 18 pruebas) y los datos de referencia de kine us en `validacion/brazo-c-kine-us/confirmados-revision-libre.toml`. Suite completa tras el cambio: **1027 pruebas OK**.

**Actualización F3c (2026-11-18, noche).** Se aplicaron las correcciones de F3c (§2.3) y se intentó re-medir. **La medición de los jueces no se pudo hacer:** `claude -p` no logra autenticarse en este entorno, así que no hay tokens medidos ni calidad medida de las configuraciones J1/J2/J3. Las cifras nuevas de este documento son las deterministas, las de kine us obtenidas con un subagente (no headless) y las estimaciones, cada una con su sello. Todas fueron recalculadas por un auditor de mediciones independiente; las discrepancias se anotan donde corresponde. Suite tras F3c: **1094 pruebas OK**. Para no repetir el número 2.2, la sección de tokens pasa de «2.2 Tokens medidos» a **§2.6**.

Sellos: **SÍNTESIS** para las tablas medidas, **ESTIMACIÓN** para las lecturas y el contraste con la literatura, **GUÍA** para las acciones sugeridas.

---

## 1. Diseño y datos

| Brazo | Qué es | Datos | Corridas |
|---|---|---|---|
| **A** | Auditor completo: determinista + juicio LLM (triage-fp, revisor-autorizacion, revisor-arquitectura) aplicado con `bin/auditar veredictos` | Copias de `tests/.tmp/f3-app` con `veredictos.jsonl` = unión de los 3 jueces de c1 (o de c2) | 2 (c1, c2) |
| **B** | LLM puro (revisión de todo el repo sin herramientas) | `tests/.tmp/brazo-b-{1,2}/hallazgos_todos.jsonl` | 2 |
| **C** | Herramientas sin triage | `tests/.tmp/f3-app/hallazgos_todos.jsonl` (la misma corrida determinista de A) | 1 (determinista) |
| **D** | Semgrep solo con reglas del registry (p/owasp-top-ten) | Hallazgos de C con fuente semgrep y regla sin prefijo `vibe-coding.` (7 hallazgos) | 1 |

- **Verdad de terreno:** `validacion/verdad-terreno.toml` (67 defectos, 56 controles limpios; reservado = id con n % 10 ∈ {3, 6, 9}: 20 defectos y 17 limpios).
- **Coincidencia:** la de `validacion/metricas.py` (control + archivo + línea ±3, asignación uno a uno; los hallazgos que coinciden con defectos de otro subconjunto no cuentan como FP).
- **«Antes / después» del juicio:** antes = C; después = A (triage aplicado con `estado_hallazgo = falso_positivo` excluido + `hallazgos_ia.jsonl`).
- **SEG·N1** aquí = todos los defectos SEG de gate N1 (24), incluido D46, que no es `detectable_en_F1`. El README informa 23/23 porque filtra solo los detectables en F1.
- **Limitación de cegamiento (se mantiene):** el set reservado ya no es ciego para D39 y D53 (README). La app sembrada la construyó el mismo equipo que escribió las reglas propias.

---

## 2. Métricas por brazo (SÍNTESIS)

### 2.1 Tabla principal (todo · desarrollo · reservado)

Formato: x/n proporción (IC95 %). Las columnas de tokens las completa el orquestador desde los transcripts.

| Brazo | Subconjunto | Sensibilidad global | Sensibilidad SEG·N1 | VPP | FP en limpios | Tokens totales | Tokens / VP |
|---|---|---|---|---|---|---|---|
| A (c1 = c2) | todo | 59/67 0,88 (0,78-0,94) | 23/24 0,96 (0,80-0,99) | 59/85 0,69 (0,59-0,78) | 0/56 0,00 (0,00-0,06) | ~237 k nuevos + ~12 k salida por corrida (3 jueces) | ~4,0 k/VP; ~119 k por cada VP que agrega el LLM (+2) |
| A (c1 = c2) | desarrollo | 42/47 0,89 (0,77-0,95) | 16/16 1,00 (0,81-1,00) | 42/68 0,62 (0,50-0,72) | 0/39 0,00 (0,00-0,09) | — | — |
| A (c1 = c2) | reservado | 17/20 0,85 (0,64-0,95) | 7/8 0,88 (0,53-0,98) | 17/43 0,40 (0,26-0,54) | 0/17 0,00 (0,00-0,18) | — | — |
| B-1 | todo | 51/67 0,76 (0,65-0,85) | 21/24 0,88 (0,69-0,96) | 51/102 0,50 (0,40-0,60) | 1/56 0,02 (0,00-0,09) | 104 k nuevos + 11,7 k salida | ~2,0 k/VP |
| B-1 | desarrollo | 35/47 0,74 (0,60-0,85) | 13/16 0,81 (0,57-0,93) | 35/86 0,41 (0,31-0,51) | 0/39 0,00 (0,00-0,09) | — | — |
| B-1 | reservado | 16/20 0,80 (0,58-0,92) | 8/8 1,00 (0,68-1,00) | 16/67 0,24 (0,15-0,35) | 1/17 0,06 (0,01-0,27) | — | — |
| B-2 | todo | 46/67 0,69 (0,57-0,78) | 17/24 0,71 (0,51-0,85) | 46/87 0,53 (0,42-0,63) | 1/56 0,02 (0,00-0,09) | 113 k nuevos + 15,8 k salida | ~2,4 k/VP |
| B-2 | desarrollo | 32/47 0,68 (0,54-0,80) | 11/16 0,69 (0,44-0,86) | 32/73 0,44 (0,33-0,55) | 0/39 0,00 (0,00-0,09) | — | — |
| B-2 | reservado | 14/20 0,70 (0,48-0,85) | 6/8 0,75 (0,41-0,93) | 14/55 0,25 (0,16-0,38) | 1/17 0,06 (0,01-0,27) | — | — |
| C | todo | 57/67 0,85 (0,75-0,92) | 23/24 0,96 (0,80-0,99) | 57/82 0,70 (0,59-0,78) | 0/56 0,00 (0,00-0,06) | 0 LLM (F1-5) | 0 |
| C | desarrollo | 40/47 0,85 (0,72-0,93) | 16/16 1,00 (0,81-1,00) | 40/65 0,62 (0,49-0,72) | 0/39 0,00 (0,00-0,09) | — | — |
| C | reservado | 17/20 0,85 (0,64-0,95) | 7/8 0,88 (0,53-0,98) | 17/42 0,40 (0,27-0,56) | 0/17 0,00 (0,00-0,18) | — | — |
| D | todo | 7/67 0,10 (0,05-0,20) | 0/24 0,00 (0,00-0,14) | 7/7 1,00 (0,65-1,00) | 0/56 0,00 (0,00-0,06) | 0 LLM | 0 |
| D | desarrollo | 4/47 0,09 (0,03-0,20) | 0/16 0,00 (0,00-0,19) | 4/4 1,00 (0,51-1,00) | 0/39 0,00 (0,00-0,09) | — | — |
| D | reservado | 3/20 0,15 (0,05-0,36) | 0/8 0,00 (0,00-0,32) | 3/3 1,00 (0,44-1,00) | 0/17 0,00 (0,00-0,18) | — | — |

Notas:
- **VPP es un límite inferior** en todos los brazos: la mayoría de los «FP» son problemas reales no sembrados (dependencias con CVE medio, devDependencies sin uso, ausencias de documentación). En C, 25 FP: 17 de severidad media/baja y 8 altos.
- **FP en limpios de B:** en ambas corridas, L56 (SEG-LOCKFILE en `package-lock.json`, reservado): el LLM puro reportó como defecto el lockfile presente.
- **FN por brazo (todo):** A = D36, D41, D46, D48, D51, D59, D60, D61. C = los mismos + D57, D58. B-1 = 16 FN (incluye D04, D05, D10, D24-D30, D39, D44, D52-D54, D67). B-2 = 21 FN (pierde además D01-D03, D06, D17, D45, D51). D = 60 FN (no ve secretos, configuración, dependencias ni SQL de migraciones).

### 2.2 Efecto del juicio LLM (criterio F3: «precisión después ≥ precisión antes»)

| Subconjunto | VPP antes (C) | VPP después (A) | Δ | Sensibilidad antes → después |
|---|---|---|---|---|
| todo | 57/82 0,695 (0,59-0,78) | 59/85 0,694 (0,59-0,78) | −0,001 | 0,85 → 0,88 (+D57 IDOR, +D58 BFLA) |
| desarrollo | 40/65 0,615 (0,49-0,72) | 42/68 0,618 (0,50-0,72) | +0,003 | 0,85 → 0,89 |
| reservado | 17/42 0,405 (0,27-0,56) | 17/43 0,395 (0,26-0,54) | −0,010 | 0,85 → 0,85 |

**Triage aislado (dentro de A, antes vs. después de excluir `falso_positivo`): idéntico** (59/85 en c1 y en c2). El triage no marcó ningún falso positivo: 21 `verdadero`, 1 `incierto` y 38 `incierto` por el tope anti-desborde.

**Por qué el triage no movió la precisión (SÍNTESIS):** de los 25 FP de C, el triage **no juzgó ninguno** (0/25; IC95 % 0,00-0,13): 8 altos quedaron fuera del digest por el tope (`incierto` = verdadero) y 17 son medios o bajos, fuera del alcance del triage (§3.3: solo crit/alto). Los 22 hallazgos que sí juzgó eran verdaderos positivos. El efecto del triage sobre la precisión **no es medible con esta corrida**: no es evidencia de que funcione ni de que falle.

La pequeña caída de VPP en «todo» y «reservado» la produce un hallazgo nuevo del revisor de autorización (SEG-MASIVA en `server/rutas/admin.js:14`, c1; `:13`, c2), que no está sembrado. Por el código citado (POST `/rol` sin control de rol en el servidor), es probablemente un problema real no sembrado (ESTIMACIÓN; no verificado por humano).

### 2.3 Re-medición tras correcciones (F3c)

**Estado: medición BLOQUEADA.** Se prepararon 9 llamadas headless (3 jueces × 3 corridas, `--bare --strict-mcp-config --tools Read`) y ninguna llegó a la API. Las 3 llamadas de prueba que dejaron JSON crudo (`prueba-flags/bare.json`, `prueba-flags/safe.json`, `kine/raw-triage-fp.bare.json`, en el scratchpad de la sesión `medicion-limpia/`) terminaron con `is_error: true`, `terminal_reason: "api_error"`, `duration_api_ms: 0`, usage en 0 y costo 0, y con el texto «Failed to authenticate: OAuth session expired and could not be refreshed». Causas comprobadas: `ANTHROPIC_API_KEY` no está definida (y `--bare` solo acepta API key o apiKeyHelper) y `claude auth status` devuelve `loggedIn: false`, `authMethod: none` (CLI 2.1.314). La sesión de escritorio se autentica por un canal que el proceso hijo no hereda. No se cambió de método (los subagentes del workflow arrastran ~91 k de contexto fijo, §2.6).

**Configuraciones previstas** (`armar_y_medir.py`): J1 = revisor-autorizacion; J2 = revisor-autorizacion + triage-fp; J3 = revisor-autorizacion + revisor-arquitectura + triage-fp. Corrida determinista base: `tests/.tmp/f3c-int` (modo estándar, digests de F3c).

#### 2.3.1 Tabla de calidad y tokens (app sembrada, «todo»)

Formato: x/n proporción (IC95 % Wilson). Para J1-J3 debían informarse la mediana y el rango de 3 corridas.

| Configuración | Corridas válidas | Sensibilidad global | SEG·N1 | VPP | FP en limpios | Tokens nuevos | Salida | Costo USD |
|---|---|---|---|---|---|---|---|---|
| J1 (autorización) | **0/3** | no medido | no medido | no medido | no medido | no medido | no medido | no medido |
| J2 (autorización + triage) | **0/3** | no medido | no medido | no medido | no medido | no medido | no medido | no medido |
| J3 (3 jueces) | **0/3** | no medido | no medido | no medido | no medido | no medido | no medido | no medido |
| C, determinista (`f3c-int`) | 1 (determinista) | 57/67 0,85 (0,75-0,92) | 23/24 0,96 (0,80-0,99) | 57/82 0,70 (0,59-0,78) | 0/56 0,00 (0,00-0,06) | 0 | 0 | 0 |
| A anterior (c1 = c2, §2.1 y §2.6) | 2 | 59/67 0,88 (0,78-0,94) | 23/24 0,96 (0,80-0,99) | 59/85 0,69 (0,59-0,78) | 0/56 0,00 (0,00-0,06) | 237 741 / 236 204 | 13 012 / 11 830 | no registrado |
| B-1 / B-2 (LLM puro, §2.1 y §2.6) | 2 | 51/67 0,76 · 46/67 0,69 | 21/24 0,88 · 17/24 0,71 | 51/102 0,50 · 46/87 0,53 | 1/56 · 1/56 | 104 018 / 112 619 | 11 721 / 15 774 | no registrado |

- **C no cambió con F3c:** los ids de `hallazgos_todos.jsonl` de `f3c-int` son idénticos a los de `tests/.tmp/f3-app` (comprobado con `cmp`), y las métricas también (57/67, 57/82, 0/56). F3c no toca la fase determinista. C detecta D37, D38 y D39 y no detecta D57, D58 ni D59.
- **Tokens de entrada de J1-J3 (ESTIMACIÓN, no medición):** bytes de prompt + digest + `indice.json` ÷ 3,5. Autorización ≈ 7,7 k (6 674 + 13 161 + 7 057 B); triage ≈ 7,2 k (4 451 + 13 769 + 7 057 B); arquitectura ≈ 5,1 k (5 856 + 4 935 + 7 057 B). J1 ≈ 7,7 k; J2 ≈ 14,9 k; J3 ≈ 20,0 k. Habría que sumar ≤ 1,5 k de salida por juez (tope del contrato). **No incluye** la definición de la herramienta Read, la repetición del contexto en cada turno ni el contexto fijo real de Claude Code. El `indice.json` (7 057 B, ≈ 2 k tokens) se lee en cada juez y es candidato a recorte.

#### 2.3.2 Ensayo del pipeline (NO es medición)

Para comprobar que el armado y las métricas funcionan sobre `f3c-int`, se aplicaron los veredictos **viejos** de A-c1 y A-c2, que se emitieron sobre otros digests. Sirve como control de cordura del contrato corregido, no como resultado de F3c.

| Ensayo | Sensibilidad global | SEG·N1 | VPP | FP en limpios | D37/D38/D39/D57/D58/D59 |
|---|---|---|---|---|---|
| J1 y J2 (c1 y c2) | 60/67 0,90 (0,80-0,95) | 23/24 | 60/89 0,67 (0,57-0,76) | 0/56 | 6/6 |
| J3 (c1 y c2) | 60/67 0,90 (0,80-0,95) | 23/24 | 60/91 0,66 (0,56-0,75) | 0/56 | 6/6 |

- `bin/auditar veredictos` terminó con rc=0 en las 6 combinaciones (dato tomado de `resultado.json`, no re-ejecutado por el auditor de mediciones), con 0 descartados y `jueces_omitidos = [ux]`.
- **0 pases de la IA:** la cifra es correcta (recontada por el auditor sobre `decisiones_ia.json → aplicadas`: 0 veredictos `pass` y 0 `estado_final = pass`), pero **el contador del script no medía nada**: lee la clave `aplicados`, que no existe (la real es `aplicadas`), así que siempre daba 0 (defecto A de §2.3.4).
- En J1, de 52 veredictos aplicados, 42 son `incierto` (sin juez de triage, coherente con `incierto_por_tope`).
- κ entre c1 y c2 = 1,0 en los 3 jueces (autorización 10/10, triage 22/22, arquitectura 8 claves comunes: c1 tiene 10 líneas y c2, 8).
- Lectura (ESTIMACIÓN): con el contrato corregido, los veredictos viejos ya recuperan D59 (antes 0/2, §2.5), probablemente porque el contrato corregido conserva más de una ubicación en `hallazgos_ia` (no se aisló la causa). La VPP del ensayo baja frente a C (0,70 → 0,67, IC solapados) por hallazgos de IA no sembrados. Ninguna de estas cifras vale como resultado de F3c.

#### 2.3.3 Correcciones aplicadas en F3c (todas con TDD)

- **Jueces por modo** (`config/presupuesto_tokens.toml [jueces]`): rápido = triage; estándar = triage + autorización, con arquitectura condicional; profundo = los 4. `digest.py` marca `lanzar` y `omitir_juez` por digest en `indice.json`.
- **Integración (2 choques de interfaz, `tests/test_f3c_integracion.py`, 9 pruebas):**
  - la lista vacía `controles: []` de `triage.json` ya no cae al catálogo: el índice declara `SEG-SAST-TRIAGE` y `veredictos.py` distingue «sin clave» de «lista vacía»;
  - `lanzar = false` ahora se registra como «juez no lanzado» con el motivo del modo. Solo puede bajar un `pass` a `no_evaluado`; nunca toca un `fail` ni produce un `pass`.
- **triage-fp** acepta candidatos a FP de cualquier severidad que traigan `indicios_fp`; el indicio es una pista, no una prueba (sin razón verificable, el veredicto es `verdadero` o `incierto`).
- **Motivo real en el estado** (`scripts/estado.py`, `tests/test_f3c_motivo_real.py`, 4 pruebas): el texto genérico «(p. ej. sin red)» se reemplaza por el motivo que declaró el check. Solo cambia el texto, nunca el estado.
- **Revisión adversarial (`tests/test_f3c_adversarial.py`, 12 pruebas; 7 problemas confirmados y corregidos):**
  1. un symlink intermedio (`src/lnk → ../datos-reales`) enviaba contenido confidencial al digest y servía como evidencia: ahora `ruta_segura` rechaza symlinks en cualquier componente, exige el nombre exacto en disco y rechaza rutas confidenciales;
  2. variantes de la misma ruta (`./src`, `src/./`, `SRC/`) inflaban los hallazgos de IA: se canonizan;
  3. un `falso_positivo` con línea inventada o lejana quitaba el `fail` determinista: ahora exige el mismo archivo y línea a ±5;
  4. un secreto partido quedaba a medias en «No corrieron»: se enmascara antes de recortar;
  5. y 6. inyección de Markdown/HTML en el informe desde el error de una herramienta o desde `motivo_omision`: se neutraliza con `md_literal`;
  7. dos motivos falsos o de más (nombre de archivo confidencial en el motivo de `rutas_inventario`; razón de `incierto_por_tope` que citaba el tope de 25 cuando el corte fue por tokens).
- Sin reproducir (quedan como regresión): fugas por la cuota de candidatos a FP y rutas fuera del proyecto en las ubicaciones.

#### 2.3.4 Pendientes de la medición (GUÍA)

- **Desbloquear la autenticación** (lo hace el investigador, no el agente): (a) exportar `ANTHROPIC_API_KEY` en una terminal propia, que es el camino fiel a `--bare`; o (b) `claude auth login`, quitando `--bare` y usando `--safe-mode --strict-mcp-config --setting-sources ""`, y declarando ese cambio de método.
- **Defectos de `armar_y_medir.py` / `medir.sh` a corregir antes de medir** (detectados por el auditor de mediciones, sin corregir):
  - A. `pass_ia` lee `aplicados` en vez de `aplicadas`: el control «0 pases de la IA» se cumple siempre;
  - B. `uso()` no descarta raw con `is_error: true`: un juez fallido entraría como medido con 0 tokens;
  - C. si un juez falla, `medir.sh` escribe el texto del error en `veredictos-<agente>.jsonl` y se concatena sin filtrar (se descarta, pero ensucia el conteo);
  - D. no se registra el contexto inicial: hay que guardar `--output-format stream-json --verbose` (evento `system/init`) para probar que la medición fue limpia.
- **J1 y J2 con fidelidad:** el índice sigue marcando `lanzar = true` para triage y arquitectura; si esos jueces no emiten, el informe no explica por qué. Regenerar el índice con `lanzar = false` o declarar la limitación.
- Si el digest de `f3c-int` se regenera antes de medir, recalcular las estimaciones de §2.3.1.

### 2.4 Estabilidad entre corridas

| Brazo | Unidad | Acuerdo | κ de Cohen |
|---|---|---|---|
| A, veredictos LLM (3 jueces) | Veredictos con la misma clave (agente, control, hallazgo_id) | 40/40 = 1,00 (0,91-1,00) | 1,00 |
| A, triage-fp | ídem | 22/22 = 1,00 (0,85-1,00) | 1,00 |
| A, revisor-autorizacion | ídem | 10/10 | 1,00 |
| A, revisor-arquitectura | ídem | 8/8 comunes; c1 emitió 2 más (INF-ENTORNOS-SEPARADOS, OPS-LLM-PII, ambos `no_evaluado`) | 1,00 |
| A, resultado final | Defectos detectados (67) y métricas | Idénticos en c1 y c2 | — |
| B | Defecto detectado sí/no (67) | 58/67 = 0,87 (0,76-0,93) | 0,67 |
| C, D | Determinista | Mismos fingerprints por construcción (criterio F1-3) | — |

En A la ubicación del hallazgo de SEG-MASIVA cambió de línea (14 → 13) entre corridas: el veredicto coincide, la ubicación no. En B, 7 defectos solo los vio B-1 (D01-D03, D06, D17, D45, D51) y 2 solo B-2 (D04, D67): los secretos de `.env` aparecen o no según la corrida.

### 2.5 Defectos que exige F3: IDOR y autorización en el cliente

Hay **2 corridas** del brazo A, no 3: se informa x/2.

| Defecto | Control | A (c1, c2) | Origen de la detección en A | B (1, 2) | C | D |
|---|---|---|---|---|---|---|
| D57 IDOR `server/rutas/citas.js:9` | SEG-IDOR | **2/2** | revisor-autorizacion (`hallazgos_ia`, línea 8, ±3) | 2/2 | no | no |
| D58 BFLA `admin.js:7` | SEG-BFLA | 2/2 | revisor-autorizacion | 2/2 | no | no |
| D59 BFLA `admin.js:13` (reservado) | SEG-BFLA | **0/2** | El LLM lo citó en ambas corridas, pero `hallazgos_ia` guarda solo la primera ubicación del veredicto | 2/2 | no | no |
| D37 auth en cliente `RutaPrivada.jsx:5` | SEG-AUTH-CLIENTE | **2/2** | Regla propia de semgrep (determinista) | 2/2 | sí | no |
| D38 auth en cliente `Login.jsx:19` | SEG-AUTH-CLIENTE | 2/2 | ídem | 2/2 | sí | no |
| D39 service_role en cliente (reservado) | SEG-AUTH-CLIENTE | 2/2 | ídem | 0/2 | sí | no |

**Auth en cliente por juicio LLM:** en c1 y c2 el revisor de autorización emitió `fail` de SEG-AUTH-CLIENTE con las 3 ubicaciones correctas (D37, D38, D39), pero el veredicto se **descartó** por la regla (a) de `veredictos.py` (sobre un hallazgo solo valen verdadero/falso_positivo/incierto). El juicio fue correcto; el contrato entre el agente y el script no. Lo mismo pasó con 4 veredictos más por corrida (SEG-PAGOS-SERVIDOR, OPS-LOGICA-ABUSO, DAT-RLS-PERMISIVA, DAT-RLS-SEMANTICA): 5 descartados por corrida. Ninguno cambió el resultado, porque esos controles ya fallaban por evidencia determinista.

---


### 2.6 Tokens medidos (antes «2.2»; transcripts de los subagentes, deduplicados por `message.id`)

«Nuevos» = `input_tokens` + `cache_creation_input_tokens` (lo que se procesa sin caché). «Lectura de caché» es el contexto reutilizado, más barato. «Incremento» = contexto final − contexto inicial; descuenta el contexto fijo de ~91 k tokens con el que arranca cualquier subagente en esta sesión (CLAUDE.md, lista de herramientas MCP, etc.), que no es del auditor.

| Brazo / agente | Llamadas | Nuevos | Salida | Lectura de caché | Incremento propio |
|---|---|---|---|---|---|
| A-c1 revisor-autorización | 4 | 79 872 | 3 949 | 357 903 | 29 048 |
| A-c1 revisor-arquitectura | 6 | 76 733 | 4 303 | 580 644 | 25 905 |
| A-c1 triage-fp | 4 | 81 136 | 4 760 | 356 969 | 30 324 |
| **A-c1 total** | 14 | **237 741** | **13 012** | 1 295 516 | **85 277** |
| **A-c2 total** | 12 | **236 204** | **11 830** | 1 068 569 | **83 744** |
| **B-1 (LLM puro)** | 5 | **104 018** | **11 721** | 508 877 | **53 125** |
| **B-2 (LLM puro)** | 7 | **112 619** | **15 774** | 772 491 | **61 722** |
| C (núcleo determinista) | — | 0 | 0 | 0 | 0 |
| D (semgrep registry) | — | 0 | 0 | 0 | 0 |
| kine us F3: 3 jueces | 13 | 225 055 | 9 826 | 1 175 414 | 70 136 |
| kine us F3: agente que corrió digest | 6 | 73 334 | 2 979 | 568 842 | 22 205 |
| kine us revisión libre (Re-auditoría 1, referencia) | — | ~1 800 000 | ~285 000 | ~40 000 000 | — |

Lectura (ESTIMACIÓN):
- **A cuesta más que B** en tokens nuevos (≈ 2,2×) porque son 3 subagentes y cada uno paga el contexto fijo. Por incremento propio, A ≈ 84 k y B ≈ 57 k.
- **El costo por VP marginal del LLM en A es alto:** C ya da 57 VP con 0 tokens; A suma 2 VP (IDOR, BFLA) por ~237 k nuevos.
- **kine us:** F3 ≈ 298 k nuevos / 12,8 k salida contra ~1,8 M / 285 k de la revisión libre (≈ 6× y ≈ 22× menos), con recall 11/42 (determinista + LLM) frente a la referencia.
- El contexto fijo de ~91 k es propio de esta sesión de prueba (muchos MCP conectados). En una instalación limpia del plugin sería menor, pero **no está medido**.

## 3. kine us: recall de F3 contra la revisión libre (SÍNTESIS)

**Referencia:** los 42 hallazgos CONFIRMADOS de la verificación adversarial (revision-*.md; INFORME-KINE-US.md §9.3): 32 «el problema existe» y 10 «el hallazgo determinista es falso positivo». La referencia es LLM-LLM, no humana (limitación ya declarada en el INFORME §9.3).
**F3 evaluado:** veredictos de `tests/.tmp/kine-f3/` (21 líneas: 4 de triage, 7 de autorización, 10 de arquitectura) sobre la re-auditoría 3 (`reauditoria-3/deterministico/hallazgos.jsonl`, 114 hallazgos).
**Reglas de coincidencia** (fail-closed, `recall_kine`): un FP se recupera solo con un `falso_positivo` de la IA sobre su hallazgo_id; un verdadero, con un triage verdadero/incierto sobre su hallazgo o un `fail`/`incierto` de control sobre uno de sus controles; «F3 completo» suma un hallazgo determinista de uno de sus controles y, si el ítem cita archivos, en uno de ellos. La asignación de controles y archivos de cada ítem sale de la propia revisión («**Control:**»).

| Métrica | x/n | Proporción (IC95 %) |
|---|---|---|
| Recall de F3, solo juicio LLM, sobre los 42 | 3/42 | 0,07 (0,02-0,19) |
| Recall de F3 completo (determinista + LLM) | 11/42 | 0,26 (0,15-0,41) |
| — de los 32 «verdadero» (solo LLM / completo) | 0/32 · 8/32 | 0,00 (0,00-0,11) · 0,25 (0,13-0,42) |
| — de los 10 «falso positivo» (solo LLM) | 3/10 | 0,30 (0,11-0,60) |
| Recall en el alcance declarado de F3 (triage crit/alto + controles de los 2 revisores: SEG-01…03, SEG-09, AR-01…04, IEO-04) | 3/9 | 0,33 (0,12-0,65) |
| Concordancia del triage con la revisión en los 4 hallazgos que juzgó | 3/4 | 0,75 (0,30-0,95) |
| Ítems en los que F3 declaró `no_evaluado` sobre el control (AR-01…04, IEO-04) | 5/42 | 0,12 (0,05-0,25) |

**Por revisor (recuperados solo LLM / completo / total):** seguridad-privacidad 3 / 5 / 16; arquitectura-flujo 0 / 1 / 5; infra-escala-operación 0 / 2 / 11; calidad-pruebas 0 / 3 / 6; UX en navegador 0 / 0 / 4.

**Detalle relevante:**
- **Acierto del triage:** marcó como `falso_positivo` los 3 SEG-SECRETO-BUNDLE de `dist/` (con `requiere_verificacion_humana: true`; al ser críticos, el control queda `no_evaluado`, nunca `pass`).
- **Error del triage:** SEG-ENV-EJEMPLO (H-beffb1559d49) lo dio por `verdadero` con `requiere_verificacion_humana: false`. La revisión confirmó que es falso positivo (no hay `.env*` y solo se leen `import.meta.env.DEV`, `BASE_URL` y `HTTPS_RED`).
- **Fuera del alcance del triage:** los 6 SEG-ERRORES (FP confirmados) son de severidad media; SEG-16/17 (CVE medio) los reporta el determinista pero nadie los trió; SEG-08 (picomatch, alto) ya no figura en la re-auditoría 3.
- **Revisores sin material:** autorización y arquitectura respondieron `no_evaluado` en los 17 controles que juzgaron. Motivos que ellos mismos declaran: `rutas_inventario` no evaluado (framework no reconocido), sin flujograma (no hubo entrevista E0), banderas `bd=false`, `servidor=false`. Los 5 confirmados de arquitectura (anonimización opcional, despliegue en LAN, bloqueo por inactividad, alcance clínico ampliado) necesitaban justamente esa entrada.
- **No cubiertos por diseño:** UX (UXK-01…04) es F4; ESC/INF de cliente (IEO-01, -02, -06…-09, -13) no tienen agente en F3.

**Qué encontró F3 que la revisión libre no (SÍNTESIS):**
- **Sobre el proyecto: nada nuevo.** F3 no emitió ningún `fail` ni `incierto` de control en kine us.
- **Sobre el propio auditor:** el revisor de arquitectura señaló banderas contradictorias del perfil (`agente_ia=true` con `llm=false`, SEG-LLM-AGENCIA) y que INF-PLATAFORMA no tiene rama del árbol de decisión en el digest. Son defectos del perfil y del digest, no del proyecto.
- **Lo que solo trae el determinista** (no está entre los 42; varios son bajos que la revisión no verificó): COD-LICENCIAS (proyecto sin licencia, licencia copyleft en el lockfile), SEG-SBOM, COD-DUPLICACION (58 bloques; la revisión lo trató como KQ-05, baja, sin verificar) y UX-LIGHTHOUSE (`chunk_grande` en `leerDicomNavegador`, relacionado pero distinto de IEO-06).

### 3.1 kine us tras F3c (corrida `2026-11-18_2110-8f38a6d`)

**Cambio de método (obligatorio declararlo):** el juez headless no se pudo correr (mismo error de autenticación que en §2.3; JSON crudo `medicion-limpia/kine/raw-triage-fp.bare.json`, usage 0). El único juez que el modo estándar lanzaba, triage-fp, lo aplicó un **subagente del workflow** siguiendo el contrato de `agents/triage-fp.md`, leyendo solo una copia del digest. Las 16 líneas llevan `modelo` = «claude-opus-5-5 (subagente; headless no disponible)». **Este recall no es comparable en condiciones iguales con el de F3 anterior**, y los veredictos requieren revisión humana.

- **Corrida determinista** (`all --modo estandar`): 165 crudos, 114 hallazgos, N0, 0 bloqueos, puntaje 51.0 (E).
- **Digests** (`digest/indice.json`; tokens = ESTIMACIÓN del auditor, caracteres ÷ 3,5): triage 3 871 (incompleto: 24 ítems del grupo «resto» recortados; candidatos a FP 16 de 40; `lanzar = true`); autorización 504 y arquitectura 1 014, ambos con `omitir_juez = true` (falta el inventario de rutas, porque es una SPA sin backend, y el flujograma); UX 580 (`lanzar = false`, el modo estándar no lo lanza).
- **Veredictos de triage:** 16 (5 `falso_positivo`, 5 `incierto`, 6 `verdadero`); los 10 primeros con `requiere_verificacion_humana: true`. `bin/auditar veredictos`: 16 aplicados, 0 descartados, ningún `pass` por IA; nivel N0, puntaje 55.3 (D). `jueces_omitidos = [arquitectura, autorizacion, ux]`.
- **Estados finales** (`estado.json`): no_evaluado 100, no_aplica 38, manual_pendiente 19, fail 12, pass 7.

| Métrica (sobre los 42 confirmados) | F3 anterior (§3) | F3c (subagente) |
|---|---|---|
| Recall solo juicio LLM | 3/42 0,07 (0,02-0,19) | **5/42 0,12 (0,05-0,25)**: SEG-01, 02, 03, 12, 13 |
| Recall completo (determinista + LLM) | 11/42 0,26 (0,15-0,41) | **13/42 0,31 (0,19-0,46)** |
| Solo determinista | no informado | 8/42 0,19 (0,10-0,33) |
| La IA contradice a la referencia | no informado | 5/42: SEG-09, 10, 11, 14, 15 |
| `no_evaluado` de la IA sobre el control | 5/42 0,12 (0,05-0,25) | 0/42 |

Lectura (ESTIMACIÓN):
- Los IC de ambos recalls se solapan ampliamente: con n = 42, una sola corrida y un cambio de método, **no hay evidencia de mejora**.
- Las 5 contradicciones son ítems que la revisión libre marcó como falso positivo y que el juez dejó en `incierto`. Por la regla fail-closed, eso cuenta como verdadero: es una diferencia de prudencia, no de detección.
- El `no_evaluado` 5/42 → 0/42 se explica porque autorización y arquitectura ya **no se lanzan** sobre un digest vacío (`omitir_juez`): sus controles quedan `no_evaluado` por la regla (f), con motivo, y no por un veredicto de la IA. No es más cobertura.
- **SEG-SECRETO-BUNDLE** (3 hallazgos en `dist/`): `falso_positivo` crítico → queda `no_evaluado` con «requiere verificación humana; no hay pass sin ella». Salió de «Paso 1 — Críticos» de la hoja de ruta. **Pendiente:** la sección «6. Hallazgos críticos y altos» del informe todavía lo lista como crítico con la remediación «Rotar la clave…», sin avisar que la IA lo marcó como falso positivo (confirmado por el auditor de mediciones).
- **SEG-ENV-EJEMPLO** (H-beffb1559d49): antes `verdadero` sin pedir verificación humana (error de §3); ahora `incierto`, porque el digest no permite verificar qué variables se usan. Sigue en `fail`. La revisión libre lo da por falso positivo: el juez es más conservador.
- **Motivo real en el informe:** las apariciones de «(p. ej. sin red)» pasan a 0 en el informe de la corrida 2110 (`grep -c`). El subagente reportó 8 apariciones antes de regenerar, pero esa cifra **no tiene fuente persistente** (el informe se regeneró encima); el informe de la corrida anterior (1821) tiene 9. Ahora se leen los motivos reales (SPA sin backend en `rutas_inventario`, tsc no confiable en COD-TIPOS, sin `supabase/migrations` en `rls_estatico`).
- **Tokens:** **no hay medición.** ESTIMACIÓN (caracteres ÷ 3,5, sin el contexto del harness): entrada ≈ 6,8 k (triage.json 13 548 + indice.json 5 939 + prompt 4 396 = 23 883 caracteres) y salida ≈ 1,8 k (**6 239 caracteres** según el recálculo; el subagente había informado 6 223, una diferencia de 16 que no cambia la estimación). La salida supera el tope de 1,5 k del contrato.
- **Integridad de kine us:** `git status --porcelain` da 0 líneas antes y después, pero eso no prueba nada sobre `.auditoria/`, que está en `.git/info/exclude`. El auditor de mediciones verificó con `find -newermt` (excluyendo datos-reales, datos-abiertos, node_modules, .auditoria y .git) que no se escribió nada fuera de `.auditoria/` después del inicio de la corrida. El informe copiado (`validacion/brazo-c-kine-us/INFORME-KINE-US-F3c.md`, 400 líneas, idéntico byte a byte al de la corrida) da 0 coincidencias en los patrones de datos sensibles; la única coincidencia de «paciente» es el nombre de la Ley 20.584.


### 3.2 Protección de hallazgos altos (regla a extendida, 18-11-2026)

Cambio: un `falso_positivo` de triage-fp sobre un hallazgo crítico **o alto** nunca deja el control en un estado que cuente como cumplido (`pass`, ni `no_aplica` por alcance 0 de la herramienta completa): queda `no_evaluado` con verificación humana, o `fail` si hay otro hallazgo efectivo. Medio/bajo sin cambio. Re-medición sin llamar a ningún LLM: se re-aplicó `bin/auditar veredictos` (código nuevo) sobre copias de las corridas F3c corregidas (`A-c1-fix`, `A-c2-fix` → `A-c1-alto`, `A-c2-alto`) y sobre la corrida 2110 de kine us.

| Corrida | Triage | Sensibilidad global | SEG·N1 | VPP | FP en limpios |
|---|---|---|---|---|---|
| A-c1 fix = alto | antes | 57/67 0,85 (0,75-0,92) | 23/24 0,96 (0,80-0,99) | 57/82 0,70 (0,59-0,78) | 0/56 0,00 (0,00-0,06) |
| A-c1 fix = alto | después | 60/67 0,90 (0,80-0,95) | 23/24 0,96 (0,80-0,99) | 60/91 0,66 (0,56-0,75) | 0/56 0,00 (0,00-0,06) |
| A-c2 fix = alto | antes | 57/67 0,85 (0,75-0,92) | 23/24 0,96 (0,80-0,99) | 57/82 0,70 (0,59-0,78) | 0/56 0,00 (0,00-0,06) |
| A-c2 fix = alto | después | 60/67 0,90 (0,80-0,95) | 23/24 0,96 (0,80-0,99) | 60/91 0,66 (0,56-0,75) | 0/56 0,00 (0,00-0,06) |

- App sembrada: 0 controles cambian de estado en c1 y en c2; nivel global N0 en las cuatro corridas, con los mismos bloqueos (18 en c1, 16 en c2). Motivo: en esas corridas no hay ningún `falso_positivo` aplicado (`decisiones_ia.json`: 0), así que la regla no tiene sobre qué actuar.
- kine us (corrida 2110): 0 controles cambian de estado; nivel global N0, puntaje 55,3 (letra D) antes y después. **Actualización 2026-11-19:** el `gates.json` vigente de esa corrida (recalculado tras DECISIONES.md #10) tiene 2 entradas de bloqueo sobre 1 control, SEG-SECRETO-BUNDLE, ambas con `pendiente_ia: true` (falso positivo crítico según IA, pendiente de verificación humana); la frase original «sin bloqueos» quedó desactualizada (O6 en `investigacion/18`). Resto de la medición: `informe.md` y `hoja-de-ruta.md` idénticos byte a byte. Los 5 FP de la corrida son 3 críticos (SEG-SECRETO-BUNDLE, ya `no_evaluado` con «falso positivo crítico según IA») y 2 medios (SEG-ERRORES, en `fail`): ningún alto. `GIT_OPTIONAL_LOCKS=0 git status --porcelain` vacío antes y después.
- Lectura (ESTIMACIÓN): el cambio no mueve ninguna cifra medida porque ninguna corrida disponible tiene un alto marcado falso positivo ni un control con alcance 0 afectado; su efecto solo está demostrado por los tests (`tests/test_f3c_fp_alto.py`, incluidos los casos de alcance 0 que antes terminaban en `no_aplica`).

---

## 4. Contraste con la literatura (ESTIMACIÓN)

**Advertencia de comparabilidad (obligatoria):** ninguna cifra publicada de `investigacion/15-benchmarks-similares.md` es comparable en sentido estricto con estas. Cambian la unidad (defecto sembrado vs. caso de prueba vs. hallazgo reportado), el lenguaje (JS/TS frente a C, Java o Python), la clase de defecto (aquí incluye secretos, configuración, CI, migraciones; CASTLE y OWASP Benchmark son casi solo CWE de código) y la definición de precisión. La app sembrada la construyó el mismo equipo que escribió las reglas (sesgo de espectro; PrimeVul muestra caídas de F1 de 68 % a 3 % al pasar a datos realistas). Las comparaciones de abajo sitúan órdenes de magnitud; **no** establecen superioridad.

| Observación aquí | Referencia publicada (doc. 15) | Lectura |
|---|---|---|
| D (semgrep registry solo): sensibilidad 0,10, VPP 7/7 | SAST en CASTLE: 0,17-0,35; Semgrep 0,23 con precisión 0,34 (INDEPENDIENTE) | El orden de magnitud de la sensibilidad de un SAST genérico solo es similar. La VPP alta de D no se traslada: son 7 hallazgos y la app tiene pocos patrones del registry que puedan dar FP |
| B (LLM puro): sensibilidad 0,69-0,76, VPP 0,50-0,53 (límite inferior) | LLM frontera en CASTLE: 0,76-0,90 de recall, precisión 0,47-0,63 (INDEPENDIENTE); Claude Code con prompts de seguridad en apps reales: VPP 0,14 (PROVEEDOR-RIVAL) | B queda en el borde inferior del recall de CASTLE y muy por encima de la VPP de Semgrep-Claude Code. La diferencia con esta última es esperable: aquí los defectos sembrados son densos y obvios |
| B: acuerdo entre corridas 0,87, κ 0,67; secretos de `.env` presentes o ausentes según la corrida | Claude Code: 3, 6 y 11 hallazgos con el mismo prompt (PROVEEDOR-RIVAL); SecLLMHolmes: respuestas no deterministas en todos los modelos (INDEPENDIENTE) | Coherente con la variabilidad documentada del LLM puro |
| A: 40/40 veredictos iguales entre corridas (κ 1,00) | Mismas fuentes | El LLM restringido a un digest pequeño y con esquema fue estable en este caso. Con 2 corridas y n = 40, el IC (0,91-1,00) no excluye inestabilidad ocasional |
| C → A: +2 defectos de autorización (IDOR, BFLA) sin bajar la VPP de forma apreciable | 2407.16235: combinar herramientas sube la detección (INDEPENDIENTE); IRIS + GPT-4 (LLM + CodeQL) duplica la detección de CodeQL solo (INDEPENDIENTE) | La dirección coincide: el LLM aporta en lo que las reglas no ven (autorización), no en lo que ya ven |
| Triage: 0 FP juzgados de 25 | Semgrep Assistant: acuerdo en FP 41 % (PROVEEDOR) | No hay base para comparar: nuestro triage no llegó a ver ningún FP |
| kine us, F3 solo LLM: recall 3/42 frente a la revisión libre | Sin benchmark publicado de «auditor acotado vs. revisión libre» | Lo que limita a F3 en kine us es la entrada (sin inventario de rutas ni flujograma), no el modelo |

**Tokens:** el doc. 15 (§3) no encontró ninguna cifra publicada y verificable de tokens por auditoría. La comparación A vs. B en tokens está en §2.6 (medida desde los transcripts) y sigue sin comparador externo.

---

## 5. Conclusión honesta de calidad (ESTIMACIÓN)

1. **El núcleo determinista (C) hace casi todo el trabajo** en la app sembrada: 0,85 de sensibilidad y 0/56 en limpios. El juicio LLM de F3 suma **dos** defectos que las reglas no pueden ver (D57 IDOR, D58 BFLA), sube la sensibilidad a 0,88 y deja la VPP prácticamente igual (0,695 → 0,694). En el set reservado el LLM no sumó ningún defecto: el único candidato (D59) se perdió por un detalle del contrato (`hallazgos_ia` guarda una sola ubicación).
2. **El LLM puro (B) es peor en todo** frente a A: menos sensibilidad (0,69-0,76 vs. 0,88), menos VPP (0,50-0,53 vs. 0,69), 1 limpio disparado y menos estabilidad (κ 0,67). Sí detecta lo que el determinista no ve (IDOR, BFLA, D59), pero pierde secretos y configuración que las herramientas no fallan. Con 2 corridas por brazo y una sola app sembrada, los IC se solapan en la sensibilidad global (A 0,78-0,94 vs. B-1 0,65-0,85); la diferencia de VPP es más clara (A 0,59-0,78 vs. B 0,40-0,63) pero tampoco excluye solapamiento con B-2.
3. **Semgrep con el registry solo (D) es preciso e insuficiente** (0,10 de sensibilidad; 0/24 en SEG·N1). Las reglas propias y los checks del auditor explican la mayor parte de la detección de C.
4. **El triage no demostró aporte.** No marcó ningún falso positivo y no llegó a juzgar ninguno de los 25 FP de C (tope de 25/4 k tokens y alcance solo crit/alto). El criterio F3 «precisión después ≥ antes» se cumple de forma **trivial** (igualdad), no por un efecto. En kine us acertó 3 de 4 y se equivocó en 1 (SEG-ENV-EJEMPLO, sin pedir verificación humana).
5. **En un proyecto real (kine us), F3 aporta poco** frente a la revisión libre: 3/42 solo con el LLM y 11/42 con el determinista. La causa principal no es el modelo: los revisores no recibieron inventario de rutas, flujograma ni entrevista, y declararon `no_evaluado` con honestidad (fail-closed). La revisión libre, sin esos límites, encontró los riesgos clínicos reales (anonimización opcional, exportaciones en claro, bloqueo por inactividad).
6. **Ahorro de tokens: resultado mixto (§2.6).** Frente a la revisión libre de kine us, F3 usó ~8 veces menos tokens nuevos y ~29 veces menos salida, pero con mucha menos cobertura (3/42 solo LLM). Frente al LLM puro (B) en la app sembrada, F3 **gastó más** tokens nuevos (237 k vs. 104-113 k), porque cada uno de sus 3 jueces arrastra ~91 k de contexto fijo de la sesión. Lo que sí es barato y bueno es el núcleo determinista (C): 0 tokens y sensibilidad 0,85. La afirmación de §9 («ahorra órdenes de magnitud») **no se sostiene** como estaba escrita.

7. **Tras F3c: mejoró la robustez, la calidad y el costo siguen sin medirse.**
   - **Qué mejoró (verificado por pruebas y corridas):** el auditor solo lanza los jueces que el modo pide y no lanza los que tienen el digest vacío (en kine us, autorización y arquitectura ya no gastan tokens para responder `no_evaluado`); el informe dice el motivo real de lo no evaluado; se cerraron 7 caminos adversariales, entre ellos una fuga de contenido confidencial por symlink y un `falso_positivo` con línea inventada que quitaba un `fail`; el contrato agente-script ya no pierde veredictos (0 descartados en el ensayo y en kine us). La fase determinista no cambió (57/67, 0/56).
   - **Qué no se puede afirmar:** que F3c gaste menos tokens (0 de 9 llamadas medidas; solo hay una ESTIMACIÓN de ≈ 20 k de entrada para J3, que deja fuera el contexto fijo real), que mejore la calidad en la app sembrada (el ensayo con veredictos viejos da 60/67, pero no es medición) o que mejore el recall en kine us (5/42 frente a 3/42, con IC solapados y otro método).
   - **Qué sigue igual:** el aporte del triage a la precisión sigue sin demostrarse; en kine us la limitación sigue siendo la entrada (sin inventario de rutas ni flujograma), no el modelo.

### Acciones sugeridas (GUÍA; decide el investigador)

- **F3c, primero:** desbloquear la autenticación headless (§2.3.4), corregir los defectos A-D de los scripts de medición y correr `medir.sh` (3 corridas × J1/J2/J3). Sin eso, el criterio 5 no se puede cerrar.
- **F3c, informe:** advertir en la sección 6 cuando la IA marcó un crítico como falso positivo, en vez de recomendar «Rotar la clave» sin contexto.
- **F3c, contrato:** decidir si un juez con `lanzar = false` que igual emite veredictos puede sostener un `pass` con evidencia (hoy `digest_completo` solo revisa `omitir_juez`), y si `agentes_vistos` debe contar las líneas inválidas.
- **F3c, métrica de kine:** `comparar_brazos.recall_kine` todavía no cuenta un `fail` con `hallazgo_id` como confirmación (pendiente heredado; puede subestimar el recall solo LLM).

- **Contrato agente-script:** el revisor de autorización emite `fail` con `hallazgo_id` y `veredictos.py` lo descarta (5 por corrida). Opciones: (a) instruir al agente para que use `verdadero` sobre un hallazgo y `fail` solo sin `hallazgo_id`; (b) aceptar `fail` sobre un hallazgo como `verdadero`. La (a) no toca la regla fail-closed.
- **`hallazgos_ia` con varias ubicaciones:** emitir un hallazgo por ubicación (hasta el tope de 5 instancias), para no perder defectos como D59.
- **Triage:** medir su efecto requiere que vea FP. Opciones: ordenar el digest para incluir los de menor confianza, subir el tope en modo profundo o correr un triage aparte sobre los medios.
- **Kine us:** repetir F3 con entrevista E0 (flujograma) y con `rutas_inventario` capaz de leer una SPA sin servidor; sin eso los revisores no tienen material.
- **Tercera corrida de A** para cumplir literalmente «≥ 2 de 3».

---

## 6. Criterios de aceptación de F3 (PLAN_MAESTRO §10), uno por uno

| # | Criterio | Evidencia | Veredicto (F3 anterior) | Evidencia F3c | Veredicto F3c |
|---|---|---|---|---|---|
| 1 | Digest ≤ 4 k tokens por juicio en el brazo A | `tests/.tmp/f3-app/digest/indice.json`: arquitectura 1 394, autorización 3 744, triage 3 939, UX 429 (estimador `caracteres/3,5`). El triage quedó incompleto: 38 crit/alto `incierto` por tope y 3 ítems recortados | **Cumple según el estimador del auditor.** No se verificó con el tokenizador real | `tests/.tmp/f3c-int/digest/indice.json`: autorización 3 744, arquitectura 1 400, triage 3 917, UX 429; kine us: triage 3 871, autorización 504, arquitectura 1 014, UX 580 (mismo estimador). Triage sigue incompleto en la app (43 crit/alto `incierto_por_tope`) | **Cumple según el estimador**; sin verificar con el tokenizador real |
| 2 | IDOR y auth en cliente sembrados detectados en ≥ 2 de 3 corridas | IDOR (D57): 2/2. Auth en cliente (D37, D38, D39): 2/2 en la salida final (regla determinista); el juicio LLM también los señaló en 2/2, pero se descartó por la regla (a). BFLA D59: 0/2 | **Cumple con 2/2 corridas.** Solo hay 2 corridas: el «de 3» no se puede verificar literalmente | Sin corridas válidas de J1-J3 (0/3). El ensayo con veredictos viejos detecta D37, D38, D39, D57, D58 y D59 en 2/2, incluido D59 (antes 0/2), pero no es medición | **Sin re-medición.** Sigue valiendo el veredicto anterior (2/2) |
| 3 | Precisión después del triage ≥ precisión antes | Triage aislado: 59/85 = 59/85 (c1 y c2). C → A: 0,695 → 0,694 (todo), 0,615 → 0,618 (desarrollo), 0,405 → 0,395 (reservado); la caída la explica un hallazgo IA no sembrado (SEG-MASIVA), no el triage. El triage juzgó 0 de 25 FP | **Cumple de forma trivial** (igualdad). Aporte del triage no demostrado | Sin medición. En el ensayo (no medición) la VPP bajó de 57/82 0,70 (C) a 60/89 0,67 (J1, J2) y 60/91 0,66 (J3), con IC solapados | **No verificado.** El ensayo no apoya una mejora |
| 4 | El LLM nunca convierte un `fail` en `pass` sin `falso_positivo` + razón (test) | `tests/test_f3a_veredictos.py` OK (p. ej. `test_pass_no_convierte_fail_determinista`, `test_falso_positivo_critico_nunca_queda_en_pass`). En los datos: `pases_ia = []` en c1 y c2; el diff de `estado.json` C → A solo tiene `no_evaluado → fail` (SEG-IDOR, SEG-BFLA, SEG-MASIVA); en kine us, los 3 FP críticos llevan `requiere_verificacion_humana` | **Cumple** | Suite 1094 OK, incluidas `test_f3c_adversarial.py` (un `falso_positivo` con línea lejana ya no quita un `fail`; symlinks rechazados) y `test_f3c_integracion.py` (`lanzar = false` solo baja a `no_evaluado`). Datos: 0 pases de IA en el ensayo (recontado a mano; el contador del script no servía) y «pass por IA: ninguno» en kine us; los críticos marcados FP quedan `no_evaluado`. Riesgo abierto sin prueba: un juez con `lanzar = false` que emite veredictos podría sostener un `pass` con evidencia | **Cumple**, con un riesgo residual por decidir |
| 5 | Modo estándar ≤ 60 k tokens medidos | §2.6: 237 k nuevos por corrida (3 jueces); ~84 k si se descuenta el contexto fijo de ~91 k por subagente de esta sesión | **No cumple (medido).** Hay que volver a medir en una sesión limpia con el plugin instalado y los agentes `tools: Read`, o bajar a 1-2 jueces por corrida | 0 de 9 llamadas medidas (autenticación). ESTIMACIÓN de entrada: J1 ≈ 7,7 k, J2 ≈ 14,9 k, J3 ≈ 20,0 k, más ≤ 1,5 k de salida por juez; sin el contexto fijo real ni la repetición por turnos | **No verificado.** La última medición válida (237 k, §2.6) no cumple; la estimación sugiere que podría cumplir, pero no es evidencia |

Suite: `python3 -m unittest discover -s tests` → 1027 pruebas OK antes de F3c; **1094 pruebas OK** después (2026-11-18, rc=0).
