# Activar auditor-integral

> **Sistema exploratorio** (DECISIONES.md #10). Entrega evidencia verificable para que una persona decida.
> No es una herramienta de investigación validada y no certifica seguridad ni cumplimiento legal.

Guía verificada el 2026-11-19 en macOS (Python 3.14.6, bash 3.2.57, git 2.54.0, jq 1.7.1, node 22.23.3).
Cada paso lleva una marca:

- **[VERIFICADO]**: ejecutado con el resultado descrito.
- **[NO VERIFICADO]**: tomado de la documentación oficial de Claude Code o del código, sin ejecutarlo
  (la evaluación no permitía correr `claude`).
- **[DEFECTO CONOCIDO]**: comportamiento confirmado que hoy no coincide con lo que promete el skill.

Detalle de la evaluación: `investigacion/18-evaluacion-herramienta.md`.

---

## 1. Requisitos

- **Python ≥ 3.11** (usa `tomllib`, `scripts/utiles.py:15`; solo biblioteca estándar), bash y git. **[VERIFICADO]** con 3.14.6.
- **Recomendadas** (el auditor no instala nada; sin ellas sus controles quedan `no_evaluado`):
  gitleaks, semgrep, osv-scanner, zizmor. **[VERIFICADO]** con gitleaks 8.30.1, semgrep 1.181.0, osv-scanner 2.7.0, zizmor 1.32.0.
- **Opcionales con fallback propio** de cobertura parcial (el fallback puede hacer fallar un control, nunca hacerlo pasar;
  `scripts/checks/fallback.py:1-21`): jscpd, lizard, knip, squawk, hadolint, checkov, syft, actionlint,
  splinter/psql, playwright, lhci.
- **Sin fallback** (F4/F5, pendientes): trivy, k6, nuclei, ZAP. (`psql` solo sirve para correr splinter, cuyo fallback es `check:rls_estatico`.)

Ver qué tiene instalado y el comando sugerido para lo que falta: **[VERIFICADO]** rc 0, 3,0-3,6 s, JSON con 24 herramientas (9 presentes en el equipo evaluado).

```bash
cd "/ruta/a/auditor-integral"
bin/auditar doctor            # JSON a stdout; no instala nada
```

---

## 2. Uso sin Claude Code (CLI determinista, 0 tokens)

**[VERIFICADO]** en una copia de `validacion/app-sembrada`, en un proyecto trivial y en una ruta con espacio.

La app sembrada **no viene en git**: en un clon limpio, materialícela antes con `python3 -I validacion/sembrado.py`
(o la suite lo hace sola). Para métricas comparables con la línea base, materialícela fuera del repo:
`python3 -I validacion/sembrado.py --destino "<carpeta fuera del repo>" --git` y audite esa carpeta
(`validacion/README.md`). Sin materializar, `bin/auditar all validacion/app-sembrada …` da rc 2
(«no es una carpeta»).

```bash
cd "/ruta/a/auditor-integral"
bin/auditar all "/ruta/al/proyecto" --modo rapido      # evalúa hasta N2
bin/auditar all "/ruta/al/proyecto"                    # estandar (por defecto): hasta N4
bin/auditar all "/ruta/al/proyecto" --modo profundo    # hasta N5 [NO VERIFICADO]
```

- Use siempre comillas: las rutas pueden tener espacios.
- La **última línea de stdout** es la carpeta de la corrida (`C`). **[VERIFICADO]**
- Tiempo observado (modo estándar): 6-7 s en un proyecto mínimo y 13-19 s en la app sembrada (varía con la red);
  en kine us, `run.json` registra ≈ 35 s para doctor + stack + scan + normalize.
- **Pase siempre la RUTA.** Sin ella, `auditar all` audita en silencio el directorio actual y crea `.auditoria/` ahí. **[VERIFICADO]**
- Del proyecto auditado solo se escribe `.auditoria/` (y, si hay git, la línea `.auditoria/` en `.git/info/exclude`).

Fases sueltas: `doctor`, `stack`, `scan`, `normalize`, `gates` (incluye score e IUA), `report`, `perfil`, `digest`,
`veredictos`. Sin `--salida`, cada fase usa la corrida más reciente de RUTA. **[VERIFICADO]**

**`--salida` en fases sobre una corrida previa** (`scan`, `normalize`, `gates`, `report`, `perfil`, `digest`,
`veredictos`): si la carpeta no existe (por ejemplo, por un error de tipeo), si es un archivo o si no tiene
`run.json`, la fase termina con **rc 4, stdout vacío y sin crear nada** (U-1, corregido el 2026-11-19; el mensaje
distingue «no existe», «no es una carpeta (es un archivo)» y «falta run.json»). **[VERIFICADO]** con
`tests/test_u1_salida_corrida.py` y `tests/test_h2_fp_humano.py`. `stack`, `all` y `doctor` sí crean la carpeta.
`--salida` recibe la carpeta de corrida; RUTA es siempre el proyecto, no la corrida.
`--salida` debe quedar **fuera del proyecto o dentro de su `.auditoria/`**: si cae en otra carpeta del proyecto,
`auditar` termina con rc 2 sin crear nada (`bin/auditar:82`), porque la corrida siguiente leería esa salida como
parte del proyecto (osv-scanner sumaba su `sbom.cdx.json` y `check_sbom` la tomaba por «SBOM en el repo», tapando
un `fail` real de SEG-SBOM). **[VERIFICADO]** con `tests/test_sin_red_verificador.py`.

Códigos de salida **[VERIFICADO]**: `0` ok · `1` falló una fase (ver `run.json` → `fases`) · `2` uso incorrecto ·
`3` fase pendiente · `4` no hay corrida previa.

### 2.1 Red

Por defecto se consulta la red: osv-scanner consulta `api.osv.dev` (nombres y versiones de paquetes, sin código),
`registro_deps` consulta el registro de paquetes y semgrep descarga el ruleset `p/owasp-top-ten`.

**Sin red:** agregue `--sin-red` a cada comando que escanea (`all` o `scan`). Equivale a `AUDITOR_SIN_RED=1`
(cualquier valor distinto de vacío o `0`); `--sin-red` es lo seguro en Claude Code, donde cada comando Bash es un
shell nuevo y un `export` previo no se conserva.

```bash
bin/auditar all "/ruta/al/proyecto" --modo rapido --sin-red
```

Efecto por herramienta (los motivos dicen «sin red (AUDITOR_SIN_RED)» y nada de esto puede dar `pass`):

| Herramienta | Con `--sin-red` |
|---|---|
| osv-scanner | sin base OSV local descargada (o versión sin `--offline`): **no se ejecuta**, queda `no_evaluado`. Con base local: corre `--offline` y queda `parcial` (los hallazgos valen; la ausencia no) |
| `registro_deps` (SEG-DEPS-EXISTEN) | no consulta npm/PyPI → `no_evaluado` |
| semgrep | no descarga `p/owasp-top-ten`; solo reglas locales → `parcial` |
| zizmor | siempre `--offline`, aunque `AUDITOR_ZIZMOR_EN_LINEA=1` |

**[VERIFICADO]** con la red bloqueada por sandbox (0 errores de red, rc 0) y con `tests/test_sin_red.py`; también
en una copia nueva de la app sembrada con `AUDITOR_SIN_RED=1` y `HTTPS_PROXY=HTTP_PROXY=http://127.0.0.1:9`
(`all --modo profundo`): rc 0, 0 errores de red, SEG-DEPS-CVE-CRIT y SEG-DEPS-EXISTEN `no_evaluado` con
«sin red (AUDITOR_SIN_RED)» en el motivo (2026-11-19). La ruta de
la base local de osv-scanner (`<RAIZ>/osv-scalibr/<Ecosistema>/all.zip`) sale del comportamiento observado de 2.7.0 y
**no se verificó con una base descargada de verdad** (eso requiere red); si difiere, osv queda `no_evaluado`.

`AUDITOR_REGISTRO_SIN_RED=1` es un alias antiguo que apaga **solo** `registro_deps`: el resto de la corrida sí usa
la red (osv.dev, semgrep.dev), y por eso su motivo dice «registro no consultado (AUDITOR_REGISTRO_SIN_RED=1, solo
este check)» y no «sin red». Para no usar la red, use `--sin-red`.

---

## 3. Instalar como plugin de Claude Code

Estructura **[VERIFICADO por lectura]**: manifiesto `.claude-plugin/plugin.json` (name `auditor-integral`, version
`0.1.0`), 4 skills con `SKILL.md` (`auditar`, `auditar-doctor`, `auditar-informe`, `auditar-perfil`),
5 agentes en `agents/` (todos con `tools: Read`), un hook en `hooks/hooks.json` y la CLI `bin/auditar`.
`skills/auditar-diff/` y `skills/auditar-sus/` están vacías.

Carga **[NO VERIFICADO]** (según la documentación oficial de plugins de Claude Code: code.claude.com/docs/en/plugins).
Solo se comprobó, sin ejecutarlo, que el binario instalado (2.1.314) contiene las cadenas `plugin-dir`,
`Validate a plugin`, `reload-plugins` y `CLAUDE_CODE_PLUGIN_DIRS`: indica que existen, no que funcionen con este plugin.

```bash
claude plugin validate "/ruta/a/auditor-integral"   # valida el plugin
claude --plugin-dir "/ruta/a/auditor-integral"      # lo carga para esta sesión
```

- Alternativa sin flag: variable `CLAUDE_CODE_PLUGIN_DIRS` con la ruta. **[NO VERIFICADO]**
- Tras editar el plugin en plena sesión: `/reload-plugins`. Para ver si cargó o falló: `/plugin`. **[NO VERIFICADO]**
- Con el plugin habilitado, `bin/` entra al PATH de Bash. **[NO VERIFICADO]**
- El repositorio git no tiene commits: sirve para `--plugin-dir`, no para distribuir por marketplace. **[VERIFICADO]**

Comandos en la sesión **[NO VERIFICADO]**. Según la documentación oficial, los skills de un plugin llevan el prefijo
del plugin; el README («Inicio rápido») ya los escribe con el prefijo:

| Comando | Para qué |
|---|---|
| `/auditor-integral:auditar [ruta] [--modo rapido\|estandar\|profundo]` | auditoría completa con entrevista y juicio LLM acotado |
| `/auditor-integral:auditar-doctor` | herramientas disponibles y faltantes |
| `/auditor-integral:auditar-informe` | regenera informe, resumen, hoja de ruta y SARIF de una corrida, sin re-escanear |
| `/auditor-integral:auditar-perfil` | entrevista E0 (y E5 en profundo) y flujograma |

**Seguridad:** no abra Claude Code con `validacion/app-sembrada` (ni una copia materializada) como directorio de
trabajo: contiene `.claude/settings.json` y `.mcp.json` peligrosos sembrados a propósito. Materialícela con
`python3 -I validacion/sembrado.py` y audítela con la CLI desde la raíz del plugin.

---

## 4. Qué hace `/auditor-integral:auditar` (según `skills/auditar/SKILL.md`)

Todo este flujo es **[NO VERIFICADO]** en una sesión real; las fases deterministas que invoca sí están verificadas por CLI.

1. **Red.** Pide autorización para osv.dev, el registro de paquetes y el registro de semgrep. Sin un sí claro,
   el skill agrega `--sin-red` al `scan` (y al atajo determinista `all`); ver §2.1.
2. **doctor + stack.** Crean la corrida y el marcador `.auditoria/.auditar_activo`. Mientras exista, el hook niega
   Write/Edit/MultiEdit/NotebookEdit fuera de `.auditoria/` (**[VERIFICADO]** con eventos simulados). No bloquea
   escrituras hechas por Bash (`hooks/hooks.json:6`).
3. **Entrevista** con AskUserQuestion; «no sé» ⇒ `null` ⇒ `no_evaluado`. Sin sesión interactiva no se inventan respuestas.
   El skill `auditar-perfil` escribe **`respuestas.json`** (nunca `perfil.json`, que el skill prohíbe tocar) y
   `bin/auditar perfil` genera `perfil.json` desde él (A3, corregido el 2026-11-19). Si `respuestas.json` no es JSON
   válido (p. ej. una coma final) o no es un objeto, `perfil` termina con rc 1 y `perfil.json` queda intacto; las
   claves de primer nivel desconocidas se ignoran con advertencia (corregido el 2026-11-20). **[VERIFICADO]** con
   `tests/test_a3_perfil_respuestas.py`.
4. **Escaneo, normalización y gates.** Si hay un bloqueo SEG/DAT en N1, el juicio se limita a triage.
5. **Digest y jueces.** Los subagentes solo leen `digest/`. La IA nunca convierte un `fail` en `pass`.
   En modo estándar se lanzan triage y autorización (arquitectura solo si hay flujograma); el juez UX, solo en profundo.
6. **Veredictos, gates e informe**; resumen para la persona dueña; se borra el marcador.
7. **Medición de tokens.** `medir_tokens.py --corrida "$C"` termina con rc 0 (corregido el 2026-11-19). Sin DIR
   solo lee transcripts en `$C/transcripts/` e ignora los artefactos de la corrida (`veredictos.jsonl`,
   `hallazgos*.jsonl`…). Si no hay mensajes con `message.usage`, informa «no medido», no escribe `tokens.json` y
   aparta uno previo como `tokens.json.obsoleto`. **[VERIFICADO]** con `tests/test_a1_medir_tokens_corrida.py`.
   Hoy el skill no deja transcripts en `$C/transcripts/`, así que el informe dirá «no medido» hasta que se pase el
   directorio real: `medir_tokens.py DIR --corrida "$C"`.

---

## 5. Leer los resultados

En `RUTA/.auditoria/<AAAA-MM-DD_HHMM>-<commit7|sin-commits|sin-git>/` (`sin-commits`: repo git sin ningún commit; `sin-git`: fuera de todo repo) **[VERIFICADO]**:

| Archivo | Para qué |
|---|---|
| `informe.md` | veredicto, qué hizo el auditor, qué falta, qué hacer ahora, tablero por dominio, hallazgos, decisiones de la IA, lo no evaluado |
| `gates.json` | `global.nivel_demostrado` (el que vale), `listo_datos_reales`, `bloqueos` |
| `resumen-dueno.md` | versión breve para la persona dueña (hoy contiene jerga técnica; acompáñela) |
| `hoja-de-ruta.md` | qué hacer para subir de nivel |
| `score.json` | puntaje 0-100 con letra, **informativo**: el nivel lo decide `gates.py` |
| `merged.sarif`, `hallazgos.jsonl` | para otras herramientas |
| `crudo/`, `hallazgos_todos.jsonl` | salida bruta; no la pase a un LLM ni la comparta |

Reglas de lectura:

- `no_evaluado` significa «no sabemos», no «está bien».
- La consola cuenta **entradas** de bloqueo (un control puede generar dos, N0 y N1); el informe cuenta **controles**.
  Por eso pueden diferir (14 frente a 11 en la app sembrada). **[VERIFICADO]**
- Si el primer paso de «Qué hacer ahora» no levanta el bloqueo N0, busque el ítem marcado como bloqueo: hoy no siempre va primero.
- **Secretos en `crudo/gitleaks*.json`:** desde el 2026-11-19 gitleaks corre con `--redact=100` y el adaptador
  (`scripts/adaptadores/gitleaks_redactar.py`) deja en `Secret`, `Match` y `Line` solo una máscara más una huella
  (`AuditorHuella`); si no logra recuperar el valor, queda `REDACTED` sin huella y la normalización no copia la
  línea del archivo. **[VERIFICADO]** en una copia nueva de la app sembrada: 0 de 15 entradas con `Secret` en claro y
  0 apariciones de los 13 valores secretos de referencia en todo `.auditoria/`. Las corridas **anteriores** a esa
  fecha no se reescriben y siguen guardando el valor en claro: no las comparta; re-escanee o bórrelas.
  `gitleaks-git.json` conserva autor y correo de los commits en claro. Aun así, `crudo/` no se pasa a un LLM.

---

## 6. Re-auditar

- Tras corregir el código: corrida nueva con `bin/auditar all "$P"` (o el skill). Cada corrida es una carpeta nueva y
  las anteriores se conservan. **[VERIFICADO]**
- Ver qué cambió entre las dos corridas más recientes (solo lectura; lee `gates.json`, `estado.json`,
  `hallazgos.jsonl` y `run.json`, nunca `crudo/`; muestra hallazgos solo como control · severidad · archivo:línea):

  ```bash
  python3 -I scripts/comparar_corridas.py --proyecto "$P"
  python3 -I scripts/comparar_corridas.py --antes "$C1" --despues "$C2"   # dos corridas concretas
  ```

  Si cambió el modo, la red (`--sin-red`) o la versión del auditor, la salida empieza con «Aviso: corridas no
  comparables»: una mejora aparente puede deberse a eso. rc 4 si no hay dos corridas. **[VERIFICADO]** con
  `tests/test_comparar_corridas.py` y una re-auditoría de un proyecto mínimo (2026-11-19).
- Tras responder la entrevista, sin re-escanear **[VERIFICADO]**:

  ```bash
  bin/auditar perfil "$P" --salida "$C" --respuestas respuestas.json
  bin/auditar gates  "$P" --salida "$C"
  bin/auditar report "$P" --salida "$C"
  ```

  Sin `--respuestas` y sin `respuestas.json` en la corrida: si `perfil.json` ya trae datos de la entrevista, `perfil`
  termina con rc 1 («no se sobrescribe…») y lo deja intacto; si no trae datos, se regenera con todo en `null`.
  Un `respuestas.json` inválido también da rc 1 sin tocar `perfil.json`. **[VERIFICADO]**
- Para aplicar veredictos: `bin/auditar veredictos "$P" --salida "$C"` (requiere `veredictos.jsonl` en la corrida;
  sin él termina con rc 1). **[VERIFICADO]**
- Tras instalar una herramienta: `bin/auditar doctor` y luego una corrida nueva.
- **Falso positivo crítico o alto confirmado por una persona** (H-2, DECISIONES.md #11, pendiente de confirmar por
  Enzo). La persona escribe un JSON (por convención `<proyecto>/.auditor-integral/fp-verificados.json`, o fuera del
  proyecto) con `{"version": "1", "entradas": [{"control", "huella" (id H-… de la sección 6), "ubicacion"
  (opcional, archivo:línea), "quien", "fecha" (AAAA-MM-DD), "conclusion"}]}` y el **operador** lo autoriza en cada
  invocación:

  ```bash
  bin/auditar gates  "$P" --salida "$C" --fp-verificados "$P/.auditor-integral/fp-verificados.json"
  bin/auditar report "$P" --salida "$C" --fp-verificados "$P/.auditor-integral/fp-verificados.json"
  ```

  Sin `--fp-verificados` no se aplica nada aunque el archivo esté en el proyecto (un archivo del repo auditado es
  una autoatestación: lo pudo versionar su autor o escribirlo cualquier proceso); el informe lo avisa en la cabecera
  y los críticos siguen abiertos. Con el flag, el control queda `no_aplica` con `descarte_humano` (nunca `pass`),
  deja de bloquear y se lista en la cabecera del informe, la sección 6c, `gates.json` (`global.descartes_humanos`) y
  el resumen del dueño; «¿listo para datos reales?» nunca queda en `SI` con descartes. El informe recalcula el
  registro en cada `report`: un `fp_humanos.json` editado a mano en la corrida no cambia nada y se avisa como
  discrepancia. Entradas sin «quien», con fecha futura, firmadas por la IA, duplicadas o con huella que ya no
  coincide se ignoran con aviso. La IA nunca escribe el archivo ni pasa el flag por su cuenta. **[VERIFICADO]** con
  `tests/test_h2_fp_humano.py`.

---

## 7. Variables de entorno

Leídas por los scripts (ruta:línea según grep, 2026-11-19):

| Variable | Efecto | Por defecto | Ruta |
|---|---|---|---|
| `AUDITOR_REGISTRO_SIN_RED=1` | alias antiguo: solo `registro_deps` sin red → SEG-DEPS-EXISTEN `no_evaluado`; el resto de la corrida sí usa red | con red | `scripts/checks/registro_deps.py:84` |
| `AUDITOR_REGISTRO_TIMEOUT` | timeout del registro (s) | 5 | `scripts/checks/registro_deps.py:437` |
| `AUDITOR_CACHE_REGISTRO` | caché del registro | `<corrida>/cache/registro_deps.json` | `scripts/checks/registro_deps.py:509` |
| `AUDITOR_SEMGREP_REGISTRO` | ruleset de semgrep; vacío = solo reglas locales | `p/owasp-top-ten` | `scripts/adaptadores/semgrep.sh:46` |
| `AUDITOR_ZIZMOR_EN_LINEA=1` (+ `GH_TOKEN`) | auditorías en línea de zizmor | offline | `scripts/adaptadores/zizmor.sh:38` |
| `AUDITOR_BIN_TSC` | tsc externo confiable para COD-TIPOS | `tsc` del PATH fuera del proyecto | `scripts/checks/tipos.py:112` |
| `AUDITOR_CONFIAR_TSC_PROYECTO=1` | permite el `tsc` de `node_modules` del proyecto | apagado | `scripts/checks/tipos.py:46` |
| `AUDITOR_CONFIDENCIAL` | archivo de rutas confidenciales | `config/confidencial.toml` | `scripts/checks/datos_confidenciales.py:100` |
| `AUDITOR_TIMEOUT_S` / `AUDITOR_PARALELO` | timeout por tarea / paralelismo del escaneo | 300 / 4 | `scripts/ejecutar_scanners.sh:89` |
| `AUDITOR_TIMEOUT_VERSION_S` | timeout de `--version` en adaptadores | 15 | `scripts/adaptadores/_comun.sh:16` |
| `AUDITOR_DOCTOR_TIMEOUT` | timeout por herramienta en doctor | 10 | `scripts/doctor.sh:18` |
| `AUDITOR_PYTHON` | intérprete | `python3` | `bin/auditar:36` |
| `AUDITOR_FP_VERIFICADOS` | registro de FP humanos autorizado (lo fija solo `auditar --fp-verificados`; `bin/auditar` ignora el valor heredado del entorno) | sin descartes | `scripts/veredictos.py` (`fuente_fp_humanos`) |
| `AUDITAR_ACTIVO=1` | activa el hook sin marcador | — | `hooks/proteger_escritura.py:30` |
| `AUDITOR_SIN_RED` (o `auditar --sin-red`) | ninguna fase consulta la red (ver §2.1) | con red | `bin/auditar:57`, `scripts/ejecutar_scanners.sh:123`, `scripts/adaptadores/osv.sh:56`, `semgrep.sh:73`, `zizmor.sh:37`, `scripts/checks/registro_deps.py:80` |

Las variables `AUDITOR_BIN_{GITLEAKS,SEMGREP,OSV,ZIZMOR}` y `AUDITOR_HERRAMIENTAS_JSON` son para pruebas;
`AUDITOR_RAIZ/PROYECTO/CORRIDA/MODO/CRUDO` las exporta `bin/auditar` internamente.

---

## 8. Limitaciones conocidas

- Sistema exploratorio con validación piloto (una app sembrada y una auditoría real).
- En modo estándar se evalúa ~14-18 % de los controles aplicables; UX, ESC, INF y OPS casi no se cubren.
- Consumo de tokens del modo estándar sin medir.
- F4/F5 (sondas UX, pruebas dinámicas y de carga) pendientes; `auditar-sus` y `auditar-diff` no existen aún.
- El hook no bloquea escrituras hechas por Bash.
- Defectos de la evaluación del 2026-11-19 que figuraban abiertos aquí, **corregidos el 2026-11-19/20**: `--salida`
  inexistente o que no es corrida (U-1, §2: rc 4 sin crear nada), respuestas del perfil que se perdían (A3, §4.3:
  `respuestas.json`, rc 1 ante JSON inválido) y falsos positivos graves sin vía de registro humano (H-2, §6:
  `--fp-verificados`). El registro humano sigue sin prueba criptográfica de autoría: es una autorización del
  operador, visible en el informe y en `gates.json`.
- Corregidos el 2026-11-19 (detalle en `investigacion/18-evaluacion-herramienta.md` §3.3): red (D1, §2.1),
  falso positivo de la IA sobre un crítico que perdía su bloqueo si el control ya estaba `no_evaluado` (D2: ahora
  queda con `pendiente_ia`), medición de tokens (A1, §4.7), osv leyendo corridas previas (O1, §2) y secretos en
  claro en `crudo/gitleaks*.json` (O3, §5; solo corridas nuevas).
