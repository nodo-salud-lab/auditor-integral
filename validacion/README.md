# validacion/

Material de validación del auditor (PLAN_MAESTRO §11): app sembrada del brazo A, su verdad de terreno,
métricas y la comparación de brazos.

| Ruta | Qué es | ¿En git? |
|------|--------|----------|
| `plantilla-app-sembrada/` | Plantilla inerte de la app sembrada (AgendaKine) | sí |
| `app-sembrada/` | App sembrada **materializada** desde la plantilla | **no** (`.gitignore`) |
| `sembrado.py` | Materializa / verifica / regenera las plantillas | sí |
| `verdad-terreno.toml` | Defectos y controles limpios (archivo:línea) | sí |
| `construir_verdad.py` | Regenera `verdad-terreno.toml` (lee `app-sembrada/`) | sí |
| `metricas.py`, `comparar_brazos.py` | Sensibilidad, VPP, IC95 % | sí |
| `brazo-c-kine-us/` | Informes y capturas del brazo C | sí |

## Por qué la app sembrada no se versiona tal cual

La app trae, **a propósito**:

- 12 canarios **falsos** con forma de secreto real (JWT `service_role`, claves Stripe `sk_live_`,
  token GitHub, claves AWS, OpenAI, SendGrid…) en `.env`, `.mcp.json`, código y bundle;
- `.claude/settings.json` con `Bash(*)` y `.mcp.json` con un servidor MCP con `service_role`;
- workflows de GitHub Actions vulnerables (`pull_request_target`, inyección de plantillas);
- dependencias con CVE en `package-lock.json`.

Versionada tal cual, la protección de push de GitHub bloquearía el push, Dependabot y CodeQL abrirían
alertas sobre defectos plantados y quien clonara el repo tendría configuración de agente activa en disco.

## Mecanismo: plantilla inerte → materialización a demanda

En git solo viajan dos plantillas:

```
validacion/plantilla-app-sembrada/            → validacion/app-sembrada/             (ignorada)
tests/fixtures/crudo/plantilla-app_sembrada/  → tests/fixtures/crudo/app_sembrada/  (ignorada)
```

La segunda es el crudo de ejemplo de los tests (salida recortada de gitleaks, semgrep, osv-scanner y
zizmor sobre la app), que repite los canarios.

Reglas de la plantilla (inversas exactas al materializar):

1. Cada componente de ruta que empieza con `.` lleva el prefijo `PUNTO`
   (`PUNTO.env.plantilla`, `PUNTO.claude/settings.json.plantilla`, `PUNTO.github/workflows/…`).
2. Cada archivo lleva el sufijo `.plantilla`: ninguna herramienta (Actions, Dependabot, CodeQL,
   Claude Code, npm) lo reconoce como propio.
3. Cada canario se reemplaza por un marcador `@@CANARIO:Cnn@@`. El valor se arma en tiempo de
   ejecución desde la tabla de `sembrado.py`, guardado como bytes invertidos en hexadecimal: en el
   árbol versionado no hay ningún literal con forma de secreto.

`tests/apoyo_corrida.py` y `tests/test_verdad_terreno.py` llaman a `sembrado.asegurar()` al importarse:
en un clon limpio la suite materializa la app y el crudo sola, sin pasos manuales. `asegurar()` es
idempotente: reescribe solo lo que difiere y borra lo que sobra en esas dos carpetas, salvo
`app-sembrada/.auditoria/` (salidas de `bin/auditar`).

```bash
python3 -I validacion/sembrado.py               # materializa ambas carpetas
python3 -I validacion/sembrado.py --verificar   # exit 1 si lo materializado difiere de la plantilla
python3 -I validacion/sembrado.py --listar      # ids, tipo y largo de los canarios (nunca valores)
```

## Exactitud (verificado al crear el mecanismo, 2026-11-19)

- **Bytes:** la app y el crudo materializados son idénticos byte a byte a los originales
  (`diff -r` sin diferencias en 43 + 16 archivos). Por eso la verdad de terreno (archivo:línea) no
  cambia: `TestVerdadTerreno.test_lineas_coinciden_con_patron` la verifica sobre la app materializada.
- **Plantillas sin forma de secreto:** gitleaks 8.30.1 (`gitleaks dir`) sobre las dos plantillas más
  `sembrado.py`: 0 hallazgos. `TestPlantillas` repite el control con las formas de `sembrado.FORMAS`.
- **Detección:** `bin/auditar all … --modo estandar --sin-red` sobre la app original en su sitio y sobre
  una materialización con `--destino DIR --git` produjo `hallazgos_todos.jsonl` **idéntico byte a byte**
  (59 hallazgos; con `metricas.py`: VP 45 · FP 14 · FN 22) y el mismo `gates.json`. No se repitió en modo
  con red (osv-scanner en línea, registro npm, reglas de semgrep del registro): ese caso no está medido.

## Cómo medir el brazo A sin alterar los números

La app materializada en su sitio (`validacion/app-sembrada/`) queda **ignorada por el `.gitignore` de la
raíz**, y el auditor lo nota: `archivos_clave.env_no_ignorado` deja de dispararse sobre `.env`
(medido: 58 hallazgos en vez de 59; el que falta era un FP para `metricas.py`, FP 13 en vez de 14).
Para métricas comparables con las corridas de referencia, materialice fuera del repo y con un
`git init` sin commits, que reproduce las condiciones de entonces (dentro de un repo, nada versionado,
nada ignorado):

```bash
python3 -I validacion/sembrado.py --destino /ruta/fuera/del/repo/app-sembrada --git
bin/auditar all /ruta/fuera/del/repo/app-sembrada --modo estandar
python3 -I validacion/metricas.py --hallazgos <corrida>/hallazgos_todos.jsonl --raiz validacion/app-sembrada/
```

Sin `--git` (carpeta fuera de todo repo) los números también cambian: `COD-REPRO` sale como
`git_sin_repo` en vez de `git_sin_versionar` y las rutas de zizmor quedan sin carpeta (`preview.yml` en
vez de `.github/workflows/preview.yml`), lo que baja los VP de 45 a 39.

## Seguridad

- No abra Claude Code (ni otro agente) con `validacion/app-sembrada/` ni con una materialización como
  directorio de trabajo: cargaría su `.claude/settings.json` y su `.mcp.json`. Audítela desde la raíz
  del plugin (`bin/auditar all validacion/app-sembrada`). Las plantillas no tienen ese riesgo: con los
  nombres cambiados ninguna herramienta las carga.
- Los canarios son falsos. Aun así, nunca los imprima ni los pegue en un prompt: el auditor los
  enmascara y los tests lo verifican.

## Mantenimiento de la app sembrada

1. Materialice (`python3 -I validacion/sembrado.py`) y edite `validacion/app-sembrada/`.
2. Si agrega un canario nuevo, súmelo antes a `_TABLA` de `sembrado.py` (bytes invertidos en hex).
3. `python3 -I validacion/sembrado.py --plantillar` regenera ambas plantillas. Falla, sin escribir nada,
   si queda alguna forma de secreto sin canario en la tabla.
4. Si cambió alguna línea sembrada, regenere la verdad de terreno (`python3 -I validacion/construir_verdad.py`)
   y corra la suite.
