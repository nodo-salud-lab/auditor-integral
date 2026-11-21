# auditor-integral

Plugin de Claude Code que audita proyectos hechos con IA ("vibe-coded") y entrega un **nivel de madurez N0-N5 por dominio** (seguridad, datos, código, usabilidad, infraestructura, escala y operación), los hallazgos críticos y una hoja de ruta hacia el siguiente nivel.

Combina escáneres deterministas (gitleaks, semgrep, osv-scanner, zizmor y chequeos propios) con un catálogo de 178 controles (`catalogo/controles.toml`). El nivel lo calculan scripts, no el LLM: las compuertas (`scripts/gates.py`) son reproducibles y los secretos se enmascaran antes de llegar a cualquier texto destinado a un modelo. La especificación completa está en `PLAN_MAESTRO.md`.

**Sistema exploratorio: no certifica** seguridad ni cumplimiento legal (DECISIONES.md #10). Entrega evidencia verificable para que una persona decida.

**Versión 0.2.0 — beta: el nivel global es orientativo; revisar los bloqueos antes de actuar.** En la verificación con
proyectos reales de la ronda 6 todos salieron N0, en buena parte por falsos bloqueos que esta versión corrige
(DECISIONES.md #12). Sigue siendo habitual un N0 por controles `no_evaluado` (sin red, juicio de IA pendiente): eso
significa «no revisado», no «está mal».

## Inicio rápido

### A. Como plugin de Claude Code, desde GitHub

El repositorio trae su propio marketplace (`.claude-plugin/marketplace.json`, un solo plugin). Dentro de Claude Code:

```text
/plugin marketplace add <usuario-de-github>/auditor-integral
/plugin install auditor-integral@auditor-integral
```

Luego, en la carpeta del proyecto a auditar: `/auditor-integral:auditar . --modo rapido`. **[NO VERIFICADO]**: la
instalación desde GitHub no se ha probado porque el repositorio aún no está publicado; lo verificado es
`claude plugin validate` sobre la carpeta y sobre `marketplace.json` (`--strict`). Para probarlo sin GitHub:
`claude --plugin-dir "<ruta al clon>"` (ver «Instalar como plugin local»).

| Comando | Para qué |
|---|---|
| `/auditor-integral:auditar [ruta] [--modo rapido\|estandar\|profundo]` | auditoría completa con entrevista y juicio LLM acotado |
| `/auditor-integral:auditar-doctor` | herramientas disponibles y faltantes |
| `/auditor-integral:auditar-informe` | regenera informe, resumen, hoja de ruta y SARIF de una corrida, sin re-escanear |
| `/auditor-integral:auditar-perfil` | entrevista E0 (y E5 en profundo) y flujograma |

### B. Por línea de comandos (sin Claude)

Desde la raíz del clon (use comillas: las rutas pueden tener espacios):

```bash
git clone https://github.com/<usuario-de-github>/auditor-integral.git
cd auditor-integral
bin/auditar doctor | python3 -I scripts/doctor_tabla.py      # 1. qué herramientas hay (no instala nada)
bin/auditar all "/ruta/al/proyecto" --modo rapido --sin-red   # 2. auditar; la última línea es la carpeta de la corrida
```

3. **Leer en este orden**, dentro de `"/ruta/al/proyecto/.auditoria/<corrida>/"`: `resumen-dueno.md` (versión
   breve), `informe.md` (sección «Qué hacer ahora») y `hoja-de-ruta.md` (plan por niveles).

`no_evaluado` significa «no sabemos», no «está bien». Tras corregir, corra de nuevo el paso 2 y compare:
`python3 -I scripts/comparar_corridas.py --proyecto "/ruta/al/proyecto"`. Parado en la carpeta del proyecto,
`"<ruta al clon>/bin/auditar-aqui" --sin-red --modo rapido` hace lo mismo y agrega un resumen de 10 segundos.

## Requisitos

- Python ≥ 3.11 (solo biblioteca estándar; probado con 3.14), bash, git.
- Opcionales (el auditor no instala nada): gitleaks, semgrep, osv-scanner, zizmor. Sin ellas, sus controles quedan `no_evaluado`. Para jscpd, lizard, knip, squawk, hadolint, checkov, syft, actionlint, splinter, Playwright y LHCI hay **fallbacks propios** de cobertura parcial (DECISIONES.md #6). Esos fallbacks pueden hacer fallar un control, pero nunca lo hacen pasar por sí solos. Revise qué tiene, con el comando de instalación sugerido, en `bin/auditar doctor` (legible: `bin/auditar doctor | python3 -I scripts/doctor_tabla.py`).
- **Sin «pases vacíos».** Cada control declara `evidencia_pass` en el catálogo: `ausencia_suficiente` (la herramienta cubre el control y analizó ≥ 1 objeto relevante, registrado en `meta.alcance`; p. ej. sin bundle, SEG-SECRETO-BUNDLE queda `no_aplica`), `checks_pass` (hace falta un pase explícito; es el valor por defecto) o `no_demostrable_estatico` (queda `no_evaluado` hasta F3, F4 o la entrevista). El informe cuenta estos últimos en la sección de cobertura.
- **Regla fail-closed (vigente tras las 3 rondas).** Un control solo queda `pass` con evidencia positiva de que se evaluó algo relevante: alcance > 0 registrado (`ausencia_suficiente`), pase explícito (`checks_pass`) o todos los `pases_requeridos`. Si falta una clave de alcance, si hay código o manifiestos que la herramienta no cubre, o si otro control de la misma corrida contradice el pase, el estado es `no_evaluado` (o `no_aplica` con motivo cuando no hay nada que evaluar). Una regla nueva que dude entre pass y otro estado tiene que elegir el otro.
- El detalle de cómo se llegó a esa regla (rondas 1-4 de pases vacíos) está al final, en «Historial de reglas fail-closed».

## Instalar como plugin local

Para una sesión (**[NO VERIFICADO]** en una sesión real; ver `docs/ACTIVAR.md` §3):

```bash
claude --plugin-dir "/ruta/a/auditor-integral"
```

Verificación:

```bash
claude plugin validate "/ruta/a/auditor-integral"
claude --plugin-dir "/ruta/a/auditor-integral" plugin details auditor-integral   # Skills: auditar, auditar-doctor, auditar-informe, auditar-perfil
```

Dentro de Claude Code quedan disponibles los 4 skills de la tabla de «Inicio rápido», con el prefijo del plugin:
`/auditor-integral:auditar [ruta] [--modo rapido|estandar|profundo]`, `/auditor-integral:auditar-doctor`,
`/auditor-integral:auditar-informe` y `/auditor-integral:auditar-perfil` **[NO VERIFICADO]**.

## Uso sin Claude (línea de comandos)

```bash
bin/auditar doctor                                                  # herramientas disponibles (JSON)
bin/auditar doctor | python3 -I scripts/doctor_tabla.py             # lo mismo, legible: qué falta y comando sugerido
bin/auditar all "/ruta/al/proyecto" --modo rapido                   # corrida completa (N1-N2)
bin/auditar all "/ruta/al/proyecto" --modo estandar --salida DIR    # N1-N4, carpeta de salida explícita
bin/auditar all "/ruta/al/proyecto" --modo rapido --sin-red         # sin consultas de red (= AUDITOR_SIN_RED=1)
python3 -I scripts/comparar_corridas.py --proyecto "/ruta/al/proyecto"   # qué cambió entre las 2 últimas corridas
bin/auditar gates "/ruta/al/proyecto" --fp-verificados "/ruta/a/fp-verificados.json"   # aplica descartes humanos (ver abajo)
bin/auditar --version
```

- **Tabla de doctor.** `scripts/doctor_tabla.py` lee el JSON de doctor (stdin o `--archivo`) y muestra primero las
  herramientas disponibles y luego las que faltan con su comando sugerido, **sin ejecutarlo**. Con
  `--corrida C` cuenta, por herramienta, los controles `no_evaluado` cuyo motivo la nombra (coincidencia de texto).
  `scripts/doctor.sh --tabla` hace lo mismo; el JSON sigue siendo la salida por defecto.
- **Comparar corridas.** `scripts/comparar_corridas.py` (`--proyecto P` o `--antes C1 --despues C2`) muestra nivel
  global y por dominio, controles que cambiaron de estado y hallazgos nuevos o que ya no aparecen (solo control,
  severidad y archivo:línea). Avisa si las corridas no son comparables (modo, red o versión). Solo lectura.
- **Errores frecuentes.** `auditar "<carpeta>"` sin subcomando sugiere `auditar all`; `--mode`, `--output` y
  `--offline` sugieren `--modo`, `--salida` y `--sin-red`; pasar una carpeta de corrida como RUTA explica cómo
  usar `--salida` (rc 4 en las fases sobre una corrida previa, rc 2 en `all`/`stack`).

### Auditar el proyecto actual: `bin/auditar-aqui`

Desde la carpeta del proyecto:

```bash
"<ruta al clon>/bin/auditar-aqui" --sin-red --modo rapido
```

- Anuncia la ruta («Auditando: …»), llama a `bin/auditar all "$PWD"` (no reimplementa ninguna fase) y termina con
  un resumen en stderr (`scripts/resumen_corrida.py`, que lee solo `gates.json` y `run.json`): nivel demostrado,
  ¿listo para datos reales?, bloqueos contados por control, cobertura, por qué queda N0 si no hay bloqueos y las 3
  rutas en orden de lectura. La última línea de stdout sigue siendo la carpeta de la corrida.
- **La red se elige siempre:** `--sin-red` o `--con-red`; sin ninguna, rc 2 (`AUDITOR_SIN_RED=1` en el entorno
  cuenta como `--sin-red`). *Decisión pendiente de Enzo:* dejarlo así o usar `--sin-red` por defecto.
- Se niega con rc 2 en `/`, en `$HOME`, en la raíz del auditor, dentro de `.auditoria/` o de una corrida, y en una
  carpeta sin archivos de proyecto (sin package.json, pyproject, requirements, .git ni código).
- Alias opcional, para copiar a mano en `~/.zshrc` (no se instala solo):

  ```bash
  alias auditar-aqui='"<ruta al clon>/bin/auditar-aqui"'
  ```

Por defecto la salida va a `RUTA/.auditoria/<fecha>-<commit>/`: `resumen-dueno.md`, `informe.md`, `hoja-de-ruta.md`, `gates.json`, `estado.json`, `score.json`, `hallazgos.jsonl` y `merged.sarif`. Del proyecto auditado solo se escribe esa carpeta. Las subfases se pueden correr por separado: `stack`, `scan`, `normalize`, `gates`, `report`.

**Red.** Por defecto osv-scanner consulta `api.osv.dev`, `registro_deps` el registro npm/PyPI y semgrep descarga `p/owasp-top-ten`. Con `--sin-red` o `AUDITOR_SIN_RED=1` (cualquier valor distinto de vacío o `0`) ninguna fase consulta la red: osv queda `no_evaluado` (o `parcial` con una base OSV local `--offline`), SEG-DEPS-EXISTEN `no_evaluado`, semgrep `parcial` con solo reglas locales (los tres con el motivo «sin red (AUDITOR_SIN_RED)») y zizmor siempre `--offline`; nada de eso puede dar `pass`. `--salida` debe quedar fuera del proyecto o dentro de su `.auditoria/` (si no, rc 2). Detalle en `docs/ACTIVAR.md` §2.1.

**Secretos en los crudos.** gitleaks corre con `--redact=100` y `crudo/gitleaks*.json` guarda solo máscara y huella (`scripts/adaptadores/gitleaks_redactar.py`), nunca el valor. Las corridas generadas antes del 2026-11-19 no se reescriben: conservan el valor en claro hasta que se re-escaneen o se borren.

**Falsos positivos verificados por una persona** (DECISIONES.md #11, pendiente de confirmar por Enzo). Si una persona
revisa un hallazgo crítico o alto y concluye que no es un problema real, lo registra en un JSON (por convención
`<proyecto>/.auditor-integral/fp-verificados.json`, o fuera del proyecto) con `control`, `huella` (el id `H-…` de la
sección 6 del informe), `ubicacion` opcional, `quien`, `fecha` y `conclusion`; el formato exacto está en la sección
6c de cada informe. **Solo se aplica si el operador lo pasa con `--fp-verificados RUTA`** a `gates`, `report`,
`veredictos` o `all`, en cada invocación: un archivo que trae el propio repositorio auditado, sin ese flag, es una
autoatestación del repo y no descarta nada (el informe lo avisa en la cabecera). Con el flag, el hallazgo sale de la
sección 6, su control queda `no_aplica` con `descarte_humano` (**nunca `pass`**, no suma puntaje), deja de bloquear el
nivel y aparece en la cabecera del informe, en la 6c, en `gates.json` (`global.descartes_humanos`) y en el resumen
del dueño; con algún descarte, «¿listo para datos reales?» nunca es `SI` (a lo sumo `CONDICIONAL`). El informe
recalcula el registro en cada `report` y no confía en `<corrida>/fp_humanos.json`. La IA y los agentes nunca
escriben ese archivo ni pasan el flag por su cuenta (regla 7 del skill `auditar`).

Pruebas: `python3 -I -m unittest discover -s tests` (la primera corrida materializa sola la app sembrada).
Un solo módulo: `python3 -I -m unittest discover -s tests -p "test_x.py"`. La forma `python3 -I -m unittest tests.test_x`
**no funciona**: con `-I` el directorio actual no entra en `sys.path` y `tests/` no es un paquete (`ModuleNotFoundError`).
Los temporales de las pruebas van **fuera del repositorio**, en `<tempdir del sistema>/auditor-integral-tests` (respeta `TMPDIR`; `AUDITOR_TESTS_TMP` fija otra carpeta), y cada prueba registra su borrado aunque falle su `setUp`/`setUpClass`. Antes iban a `tests/.tmp/`, donde las corridas cortadas dejaban canarios que ensuciaban la autoauditoría. Las corridas manuales (app sembrada, comparaciones) también deben escribir fuera del repo (`--salida /ruta/externa` o la `.auditoria/` del proyecto auditado), nunca en `tests/.tmp/`.

### Solo lectura: vite.config que ejecuta git (Anexo C del brazo C, M-04)

El auditor **no ejecuta vite** ni vitest ni los scripts del proyecto auditado: solo lee archivos y escribe en `.auditoria/`. Ojo con un `vite.config.(ts|js|mjs)` que llama a git al cargarse (por ejemplo `git status` o `git rev-parse` para inyectar la versión): cualquier runner de vite o vitest que lo cargue puede refrescar y **escribir `.git/index`**. Si durante una auditoría se corre a mano un runner del proyecto, hágalo con `GIT_OPTIONAL_LOCKS=0` y compare `git status` antes y después. El runner opcional de tipos (`scripts/checks/tipos.py`, `tsc --noEmit --listFiles`) tipa `vite.config` pero no lo ejecuta, y deja el `.tsbuildinfo` en una carpeta temporal fuera del proyecto. **Ronda 4:** usa un tsc confiable ajeno al proyecto (`AUDITOR_BIN_TSC` o `tsc` del PATH, cuya ruta real no esté dentro del proyecto). El `node_modules/.bin/tsc` del proyecto auditado es código del repositorio y solo se ejecuta si es el enlace estándar a `node_modules/typescript` (paquete `typescript`) **y** el investigador declara `AUDITOR_CONFIAR_TSC_PROYECTO=1`; si no, COD-TIPOS queda `no_evaluado`. El pase exige además ≥ 1 archivo fuente del proyecto tipado.

## Versión 0.2.0 (2026-11-20): ronda 6, falsos bloqueos en proyectos reales

Estado: **beta: el nivel global es orientativo; revisar los bloqueos antes de actuar.** Detalle y decisiones en
DECISIONES.md #12. Qué cambió:

- **Secretos.** gitleaks ya no escanea entornos virtuales ni cachés (`.venv*`, `.nox`, `.tox`, `site-packages`,
  `.pytest_cache`, `supabase/.temp`, carpetas con `pyvenv.cfg`); las carpetas ignoradas por git se escanean aparte
  con presupuesto propio. Un secreto en un archivo ignorado y nunca versionado, un `.env` ignorado y sin historial, o
  un JWT con `role = anon` van al control nuevo **`SEG-SECRETO-LOCAL`** (severidad baja, no bloquea, no pide rotar ni
  `git filter-repo`). `service_role`, otros roles, JWT ilegibles y todo lo versionado o con historial siguen en
  `SEG-SECRETO-REPO`/`SEG-SECRETO-BUNDLE` (críticos, bloquean). `con_timeout.py` ya no cae con `EPERM` en macOS.
- **Datos.** `pacientes/` y `patients/` son carpetas ambiguas: solo sus archivos de datos son confidenciales; el
  código se escanea (antes se perdía, por ejemplo, una inyección SQL en `pages/api/patients/`). YAML/JSON de
  configuración ya no dan PII; los correos de dominios reservados (example.com, `.test`…) y `noreply` no cuentan; la
  PII en tests o fixtures va al control nuevo **`DAT-PII-TEST`** (media, no bloquea). El historial ya no confunde
  carpetas con archivos borrados.
- **Stack.** `.env.example`, lockfile, README, `/salud`, migraciones SQLite, RLS en bloques `DO $$`, formularios con
  componentes envueltos en `<label>` y CI con archivos `*.test.mjs` dejan de dar falsos positivos; lo que no puede
  quedar `no_aplica` queda `no_evaluado` con motivo, nunca `pass`. Nuevos hallazgos: rutas admin sin auth
  (`SEG-BFLA`) y respuestas con `process.env` completo (`SEG-ERRORES`). Pagos se detectan por código.
- **Tipo de proyecto.** `detectar_stack` registra `detalle.tipo_proyecto`; en CLI/librerías Python y apps móviles los
  controles exclusivos de servidor HTTP o navegador sin hallazgos quedan `no_aplica` con motivo.
- **Compuertas y CLI.** Un bloqueo por control en `gates.json`; el informe cuenta las herramientas «parciales» como
  ejecutadas y explica que «no evaluado» significa «no revisado»; `auditar all` exige RUTA; `bin/auditar` exige
  Python ≥ 3.11 con un mensaje claro.

**Verificación de la 0.2.0 (2026-11-20):** suite completa 1533 pruebas OK (`python3 -I -m unittest discover -s tests`);
con la máquina muy cargada fallaron de forma intermitente dos pruebas de tiempos (`test_adaptadores`
`test_timeout_por_herramienta`, que da 2 s a todas las herramientas, y una de `test_r6_secretos` cuyo nombre no quedó
registrado) y pasaron al repetirlas. App sembrada (materializada fuera del repo con `--git`, `--sin-red`): VP 47 · FP 14 · FN 20 (antes
45 · 14 · 22; los dos nuevos son D58 y D59, `SEG-BFLA`; D59 es del
set reservado, que con esto deja de ser ciego para ese defecto), VPP 0,77, 0/56 controles limpios disparados, 12/12 secretos
del repositorio. gitleaks sobre el árbol subible (`git ls-files --cached --others --exclude-standard`): 0 hallazgos.

**Limitaciones conocidas de la 0.2.0:**

- El nivel global puede seguir en N0 sin bloqueos reales: los controles `no_evaluado` (sin red, juicio de IA
  pendiente, pases que el análisis estático no puede demostrar) cuentan como no demostrados.
- Secretos en archivos de test versionados (por ejemplo `*.test.js`) siguen contando como secretos del repositorio;
  no hay una decisión para valores de prueba.
- Si se agota el presupuesto del escaneo de carpetas ignoradas, sus secretos locales no se ven (SEG-SECRETO-LOCAL
  queda `no_evaluado`; SEG-SECRETO-REPO no cambia, porque esas carpetas nunca se versionaron).
- Un hallazgo `untracked` no ignorado (`no_versionado`) sigue con la remediación «rotar + filter-repo»: el hallazgo
  normalizado aún no trae la marca `versionado`.
- SEG-ENV-EJEMPLO y SEG-LOCKFILE en una CLI o librería sin variables ni dependencias quedan `no_evaluado` (no
  `no_aplica`): el catálogo aún no tiene una condición por tipo de proyecto para ellos. OPS-ERROR-TRACKING se sigue
  exigiendo a CLI y librerías.
- Dentro de una carpeta ambigua, un archivo de extensión desconocida es confidencial para el auditor, pero semgrep y
  gitleaks lo recorren (sus filtros no pueden expresar «todo menos el código»).
- La aplicabilidad por tipo de proyecto la aplica `gates.py` (que reescribe `estado.json`); `estado.py` solo no la
  aplica.

## Estado: F0 + F1 + decisiones del investigador + cierre de pases vacíos + F3 (2026-11-18)

- **Suite:** 1330 pruebas OK (`python3 -I -m unittest discover -s tests`, 2026-11-20, dos corridas seguidas sin fallos, tras las correcciones de la revisión adversarial).
- **Revisión adversarial del 2026-11-20, corregido:** el registro de falsos positivos humanos solo se aplica con `--fp-verificados` (antes un `fp-verificados.json` del propio repo, o un `fp_humanos.json` escrito a mano en la corrida, descartaba todos los críticos); `respuestas.json` inválido ya no pisa `perfil.json` (rc 1); claves desconocidas en `respuestas.json` se advierten; `--salida` que es un archivo dice «no es una carpeta»; 0 hallazgos de gitleaks en el árbol versionable; la prueba de semgrep usa el mismo binario que decide el salto.
- **Autoauditoría del 2026-11-20, corregido** (`tests/test_autoauditoria_r5.py`): OPS-HEALTH ya no acepta como evidencia una ruta `/health` escrita en tests o fixtures (la detección de servidor no cambia); `dockerfile.py` ya no trata `dockerfile.<ext>` de código o texto (`dockerfile.py`) como Dockerfile, y un Dockerfile o IaC de tests/fixtures sigue dando hallazgos pero no pase; gitleaks del árbol excluye `__pycache__/` y `.pyc`/`.pyo`; el perfil técnico deja la evidencia que sale solo de tests/fixtures en `evidencia_secundaria`, sin encender banderas (los escaneos no cambian); el informe ya no cuenta como «juicios de la IA» las entradas sintéticas del tope de triage (las muestra como «no juzgados», que cuentan como verdaderos) y `decisiones_ia.json → resumen` trae `aplicadas_ia` y `sin_juzgar_por_tope`; el número de un bloqueo muestra aparte los críticos/altos con falso positivo de IA pendiente de verificación humana; el id de corrida distingue `sin-commits` (repo sin commits) de `sin-git`. App sembrada sin cambios: mismo `hallazgos_todos.jsonl` y `gates.json` byte a byte (VP 45 · FP 14 · FN 22).
- **Informe de la autoauditoría** (método, antes/después, triage, comparación y conclusión): [`investigacion/19-autoauditoria.md`](investigacion/19-autoauditoria.md).
- **Defectos de la evaluación del 2026-11-19 corregidos** (`investigacion/18-evaluacion-herramienta.md` §3): D1 (el «no» a la red ahora se respeta: `--sin-red`), D2 (un falso positivo de la IA sobre un crítico mantiene el bloqueo con `pendiente_ia`), A1 (`medir_tokens.py --corrida`; sin transcripts informa «no medido»), O1 (osv ya no lee `.auditoria/` ni salidas previas) y O3 (gitleaks redactado en los crudos).
- **Hecho:**
  - **Cierre de pases vacíos (3 rondas, fail-closed):** en kine us, 28 → 8 `pass`, todos con evidencia registrada (re-auditoría 3, corrida `2026-11-18_1555-8f38a6d`, sin cambios en el proyecto auditado); en la app sembrada, sin regresión (23/23 SEG·N1, 57/67 global, 0/56 limpios). Los residuales de la ronda 3 se corrigieron en la ronda 4 (ver arriba); kine us no se re-auditó tras la ronda 4.
  - **F3 (juicio LLM acotado, con correcciones F3c):** `bin/auditar digest` resume la corrida en `digest/{autorizacion,arquitectura,triage,ux}.json` más `indice.json` (≤ ~4 k tokens por digest, estimados); los jueces (`agents/*.md`) leen solo ese digest y emiten JSONL; `bin/auditar veredictos` aplica las reglas duras y escribe `decisiones_ia.json` y `hallazgos_ia.jsonl`.
    - **Jueces por modo** (`config/presupuesto_tokens.toml [jueces]`): rápido = triage; estándar = triage + autorización, y arquitectura solo si tiene material; profundo = los 4.
    - **Omisión de jueces vacíos:** un digest sin material (`omitir_juez`) o un juez que el modo no lanza (`lanzar = false`) no gasta tokens; sus controles quedan `no_evaluado` con el motivo en el informe («Jueces omitidos o no lanzados»).
    - **Contrato de veredictos (fail-closed):** la IA nunca convierte un `fail` en `pass`; un `falso_positivo` exige el mismo archivo y una línea a ±5 del hallazgo, y si es crítico o alto nunca deja el control en un estado que cuente como cumplido (ni `pass` ni `no_aplica` por alcance 0): queda `no_evaluado` con verificación humana, o `fail` si hay otro hallazgo efectivo (medio/bajo sí pueden descartarse); las ubicaciones se canonizan y se rechazan symlinks, rutas fuera del proyecto y carpetas confidenciales.
    - **Medición pendiente:** la comparación de brazos y la re-medición F3c están en `investigacion/17-comparacion-calidad-tokens.md`. El consumo de tokens de F3c **no está medido** (las llamadas headless no se pudieron autenticar), así que el criterio «modo estándar ≤ 60 k tokens» sigue sin verificar.
  - **F0:** esqueleto del plugin, catálogo y schemas.
  - **F1:** MVP determinista N1-N2 sin LLM, con adaptadores, normalización, deduplicación, enmascarado, compuertas, puntaje e informe por plantilla.
  - **Decisiones de `DECISIONES.md` aplicadas:**
    - pesos y umbrales con fuente (letra A-E estilo SonarQube y puntaje estilo OpenSSF Scorecard);
    - Índice de Usabilidad Automatizado (IUA), que se informa siempre con su cobertura;
    - aviso legal destacado que no bloquea el nivel;
    - SUS exigido en N4;
    - carpetas confidenciales excluidas de todo análisis;
    - 11 fallbacks estáticos marcados «cobertura parcial (fallback)».
- **Validación preliminar** en la app sembrada del brazo A (modo estándar; estudio piloto, IC95 % de Wilson):
  - sensibilidad SEG·N1 detectable en F1 de 23/23 (1,00; 0,86-1,00);
  - sensibilidad global de 57/67 (0,85; 0,75-0,92);
  - VPP de 0,70: un límite inferior, porque la mayoría de los FP son problemas reales no sembrados;
  - 0/56 controles limpios disparados.
  - **El set reservado ya no es ciego** para dos defectos (D39 y D53).
  - Detalle, falsos negativos y decisiones pendientes: `investigacion/10-f0-f1-resultados.md`, sección «Decisiones aplicadas (2026-11-18)».
- **Pendiente:**
  - adaptadores de las herramientas reales que hoy cubren los fallbacks;
  - F3: medir tokens y calidad de los jueces en una sesión limpia (ver `investigacion/17`, §2.3);
  - F4 (sondas UX con Playwright/axe y LHCI para medir el IUA);
  - F5 (pruebas dinámicas y carga);
  - F6 (validación formal);
  - F7 (modo continuo).

## App sembrada (validación): se materializa, no se versiona

`validacion/app-sembrada/` es una app con defectos sembrados **a propósito** para validar el auditor: un
`.claude/settings.json` peligroso (bypass de permisos, Bash con comodín), un `.mcp.json` con un servidor MCP de versión
flotante y una clave `service_role` literal, 12 canarios **falsos** con forma de secreto real, workflows vulnerables y
dependencias con CVE. Por eso **no viaja en git tal cual**: el repositorio trae una plantilla inerte
(`validacion/plantilla-app-sembrada/`, rutas con prefijo `PUNTO`, sufijo `.plantilla` y marcadores `@@CANARIO:Cnn@@`)
y `validacion/sembrado.py` la materializa en la carpeta ignorada `validacion/app-sembrada/`. Detalle y evidencia de
exactitud en `validacion/README.md`.

En un clon limpio la app **no existe** hasta materializarla (la suite lo hace sola al importarse):

```bash
python3 -I validacion/sembrado.py                     # materializa validacion/app-sembrada/ (y el crudo de tests)
python3 -I validacion/sembrado.py --verificar         # rc 1 si difiere de la plantilla o si falta materializar
bin/auditar all validacion/app-sembrada --modo estandar --sin-red
```

Para **métricas comparables** con la línea base (59 hallazgos; VP 45, FP 14, FN 22 en `--modo estandar --sin-red`,
medido el 2026-11-19), materialícela fuera del repositorio con un git propio y audite esa copia:

```bash
python3 -I validacion/sembrado.py --destino "/tmp/app sembrada" --git
bin/auditar all "/tmp/app sembrada" --modo estandar --sin-red
```

Auditada en su sitio (dentro de este repo, ignorada por el `.gitignore` raíz) da 58 hallazgos (FP 13), y fuera de git
sin `--git`, 59 hallazgos con VP 39 (`validacion/README.md`). Los 12 FN que dependen de la red no se cubren con
`--sin-red`.

**No abra Claude Code (ni otro agente) con la app materializada como directorio de trabajo**: cargaría esa
configuración y esos servidores MCP. Audítela siempre con `bin/auditar` desde la raíz del clon, que solo lee sus
archivos.

El auditor no certifica seguridad ni cumplimiento legal: entrega evidencia verificable para que una persona decida.

## Historial de reglas fail-closed

Registro de las cuatro rondas de cierre de «pases vacíos» (2026-11-18). La regla vigente está en «Requisitos»; el detalle de la ronda 4 y sus limitaciones, en `investigacion/16-pases-vacios-residuales.md`.

- **Ronda 1 de pases vacíos (2026-11-18, fail-closed).** Ningún control queda `pass` sin evidencia positiva de que se evaluó algo relevante:
  - el alcance de semgrep sale de `paths.scanned` (lo que semgrep analizó de verdad), solo con lenguajes que tienen reglas de inyección (no `.sh`, `.yaml`, `.json`) y sin contar código de test; el código de `test/` y `tests/` **sí se escanea** (una carpeta así puede ser código desplegado), pero no cuenta como alcance;
  - DAT-SQL-CONCATENADO exige archivos con consultas SQL (si no hay, `no_aplica`); SEG-SECRETO-REPO exige el historial escaneado si el repo git tiene commits; INF-INVENTARIO no pasa con inventario vacío;
  - SEG-ENV-PUBLICAS sin `.env*` ni código que lea variables de entorno, DAT-PII-REPO sin repositorio git y SEG-AGENTES-IA sin configuración de agentes o MCP quedan `no_aplica` con motivo; DAT-ESQUEMA-VERSIONADO aplica solo si `bd == true`;
  - COD-CI-BASICO exige que el CI ejecute lint, typecheck o tests (la comprobación corre siempre, también con actionlint instalado);
  - COD-TESTS-HUMO, SEG-CORS, SEG-COOKIES y SEG-CSRF son `no_demostrable_estatico`;
  - el tope de 5 instancias por (control, archivo) nunca descarta críticos de N1; `validacion/metricas.py` advierte si recibe el archivo con tope;
  - `osv.meta.json` registra la fecha de consulta de la base OSV (`base_osv.consultada_utc`).
  - Falso negativo conocido, sin regla todavía: cookies emitidas sin `HttpOnly`/`Secure`/`SameSite`.
- **Ronda 2 de pases vacíos (2026-11-18, fail-closed).** Fixtures adversariales f09-f23 de la re-auditoría de la ronda 1 (`tests/test_pases_vacios_r2.py`):
  - COD-CI-BASICO: solo cuentan comandos que se ejecutan (no `echo "npm test"`, comentarios `# npm test`, jobs o pasos con `if: false`) en workflows de push o PR (no `workflow_dispatch` ni `schedule`);
  - SEG-SAST-INY y DAT-SQL-CONCATENADO: la cobertura sale de las reglas que semgrep cargó de verdad (SARIF): Python cuenta solo con Flask, Django, Pyramid o un handler de Lambda; Kotlin y Scala no cuentan. El código sin reglas de inyección (`fuentes_sin_reglas`, `consultas_sql_sin_reglas`) impide el pass (`alcance_excluyente` → `no_evaluado`);
  - semgrep: las exclusiones de build (`/build`, `/dist`, `/out`, `/.next`, `/vendor`) se anclan a la raíz; `src/build/` se escanea;
  - SEG-AGENTES-IA: hallazgos nuevos por hooks que descargan y ejecutan, `enableAllProjectMcpServers`, `Bash(<cmd>:*)` con comandos peligrosos y `WebFetch` sin dominio; cualquier hook o comando configurado impide el pase;
  - SEG-LOCKFILE: lockfile vacío o JSON inválido → hallazgo; el pass exige (`pases_requeridos`, lógica AND) contenido válido, lockfile versionado, instalación reproducible en CI (`npm ci`, `--frozen-lockfile`…) y hosts `https` permitidos;
  - DAT-ESQUEMA-VERSIONADO exige ≥ 1 migración real (no `.gitkeep`); OPS-HEALTH exige una ruta de salud registrada (no un literal `'status'`); COD-DOC-AGENTE exige un documento para agentes con contenido y el README de arranque; COD-REPRO exige ≥ 1 archivo del proyecto versionado (una carpeta ignorada por el repo padre da `git_sin_versionar`).
- **Ronda 3 de pases vacíos (2026-11-18, fail-closed).** Pases vacíos PV-R2-01…08 de la re-auditoría de la ronda 2 (`tests/test_pases_vacios_r3.py`):
  - COD-CI-BASICO: el comando de calidad tiene que correr siempre y su fallo tiene que hacer fallar el CI. Se modela bash -e: no cuentan `true || npm test`, `false && …`, `exit 0; …`, `npm test || true` (o `|| exit 0`, `|| echo`), `npm test &`, `! npm test`, `set +e`, el cuerpo de un heredoc ni `continue-on-error: true`. Los `if:` se evalúan (github.event_name, `always()`, `failure()`…), y también los filtros branches y paths. `npm test` y `npm run X` se cruzan con package.json: un script inexistente o vacío (`echo no tests && exit 0`) no cuenta. Los casos dudosos (filtros que no coinciden, `if:` no evaluable, continue-on-error con expresión) no dan ni pase ni hallazgo;
  - SEG-LOCKFILE: `lockfile_ci` usa ese mismo análisis por comandos (un `npm ci` dentro de un echo no cuenta). `lockfile_valido` exige que el lockfile fije las dependencias directas: si no fija ninguna, hay hallazgo `lockfile_incompleto`; si es una desincronización parcial, no hay pase ni hallazgo (`lockfile_desincronizado`). `lockfile_hosts` exige ≥ 1 paquete fijado y, en package-lock, ≥ 1 URL resuelta;
  - DAT-PII-REPO: los archivos de datos versionados (CSV/TSV, JSON/JSONL de registros) se inspeccionan de forma acotada: encabezado y hasta 200 filas o 256 KiB. Si hay columnas o valores personales o de salud (RUT con dígito verificador, email, nombre + diagnóstico…), se reporta `pii_tabular` (crítico) sin copiar ningún valor. Un archivo de datos binario (xlsx, sav, sqlite…) impide el pase;
  - SEG-SAST-INY: `pass_contradicho_por`. Una inyección SQL de semgrep en la misma corrida (DAT-SQL-CONCATENADO) deja el control en `no_evaluado`, sin duplicar el hallazgo;
  - SEG-DEPS-EXISTEN: Pipfile se verifica en PyPI. go.mod, Cargo.toml, Gemfile, composer.json, pubspec.yaml, pom.xml, build.gradle, *.csproj, mix.exs y Package.swift con dependencias impiden el pase (`no_cubiertos`);
  - INF-INVENTARIO: exige también ≥ 1 plataforma de despliegue (`perfil_tecnico.plataformas_despliegue`, sacada de archivos de configuración, de acciones o comandos de despliegue en workflows o scripts, de contenedores, Kubernetes o IaC);
  - SEG-SECRETO-REPO: `archivos_clave.secreto_en_env` reporta lo que gitleaks no reconoce en los `.env*` reales: contraseñas con nombre genérico y JWT con role service_role. El valor nunca se copia;
  - `alcance_excluyente` es fail-closed: si la clave no está registrada, no hay pass. El adaptador registra siempre `fuentes_sin_reglas` y `consultas_sql_sin_reglas`, también cuando valen 0.
- **Ronda 4 de pases vacíos (2026-11-18, fail-closed).** Los 15 residuales PV-R3-01…15 de la re-verificación de la ronda 3, más SEG-DEPS-EXISTEN y COD-TIPOS, se reprodujeron (17/17 confirmados) y se corrigieron (`tests/test_pases_vacios_r4.py`; detalle en `investigacion/16-pases-vacios-residuales.md`):
  - código, `.env*` y lockfiles en rutas confidenciales (se comparan por segmento: `src/patients/`) no se escanean, pero ahora impiden el pass de SEG-SECRETO-REPO, SEG-SAST-INY, DAT-SQL-CONCATENADO y SEG-DEPS-CVE-* (`codigo_confidencial`, `fuentes_no_escaneadas`, `lockfiles_confidenciales`); el código > 2 MB que semgrep omite también;
  - gitleaks escanea como bundle las carpetas `build/`, `dist/`, `out/` y `.next/` a cualquier profundidad;
  - COD-TIPOS ya no ejecuta el `node_modules/.bin/tsc` del repo auditado salvo enlace estándar a `typescript` y `AUDITOR_CONFIAR_TSC_PROYECTO=1` (o un tsc confiable externo, `AUDITOR_BIN_TSC`); el pase exige ≥ 1 archivo tipado;
  - DAT-PII-REPO inspecciona volcados `.sql`, `.yaml`/`.xml`/`.txt` y comprimidos con nombre o carpeta sospechosos, JSON truncados con raíz objeto y el historial de git (`trackeado_historial`);
  - SEG-ENV-EJEMPLO revisa los `.env` de subcarpetas y exige un ejemplo con las variables que lee el código; COD-CI-BASICO compara argumentos completos, lee el Makefile/justfile y exige que el cuerpo del script `test` ejecute calidad; DAT-ESQUEMA-VERSIONADO no acepta SQL solo con comentarios; OPS-HEALTH no acepta clientes HTTP; OPS-ERROR-TRACKING no acepta plugins de build de Sentry; SEG-DEPS-EXISTEN sigue `-r`, lee `[dependency-groups]` y grupos de Poetry, y `setup.py`/`setup.cfg`/`environment.yml` impiden el pase.
  - Limitaciones que quedan (documentadas en investigacion/16): task/tox/nox no leen su configuración; `jest --passWithNoTests` cuenta como calidad; JSON con registros anidados a más de un nivel; `.txt`/`.yaml` sin nombre sospechoso no se inspeccionan.

## Licencia

MIT. Ver [LICENSE](LICENSE).
