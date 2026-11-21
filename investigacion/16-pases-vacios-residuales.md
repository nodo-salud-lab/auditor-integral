# 16 · Pases vacíos residuales de la ronda 3: reproducción y corrección (ronda 4, fail-closed)

Fecha: 2026-11-18. Alcance: los 15 posibles pases vacíos PV-R3-01…15 que reportó el verificador de la ronda 3, más los dos residuales del cierre (SEG-DEPS-EXISTEN confirmado y COD-TIPOS plausible; `validacion/brazo-c-kine-us/REAUDITORIA.md` §R3.6). El cierre de la ronda 3 solo había reproducido 2 de ellos y 1 como plausible.

## Método

- **Reproducción (GUÍA):** un fixture mínimo y sintético por caso en `tests/.tmp/pv16/` (sin datos reales). Cada fixture se auditó de punta a punta con `bin/auditar all <fixture> --modo estandar` antes y después de corregir. Los fixtures se borraron al terminar. Los casos quedan como pruebas unitarias en `tests/test_pases_vacios_r4.py` (56 pruebas; usan carpetas temporales del sistema).
- **Corrección:** TDD estricto. Primero se escribieron las pruebas: 49 fallaron y 15 dieron error. Después se implementó la corrección. Se mantuvo la regla fail-closed: ante la duda, `no_evaluado` y nunca `pass`.
- **Clasificación:** CONFIRMADO si el fixture daba `pass` (o `no_aplica` en lugar de detectar el defecto) con el código de la ronda 3; NO REPRODUCIBLE si no.
- No se instaló nada, no se hicieron commits y no se abrió kine us.

## Tabla final

| ID | Control | Sev. | Fixture (síntesis) | Antes (ronda 3) | Clasificación | Después (ronda 4) | Corrección |
|---|---|---|---|---|---|---|---|
| PV-R3-01 | SEG-SECRETO-REPO, SEG-SAST-INY, DAT-SQL-CONCATENADO (+ SEG-DEPS-CVE-*) | crítica | `src/patients/routes.js` con clave AWS, SQLi y `eval` | pass ×3 | CONFIRMADO | no_evaluado ×3 | Las rutas confidenciales siguen sin escanearse (DECISIONES #3), pero ahora se cuentan sin abrirlas. Se cuentan el código y los `.env*` (`gitleaks.codigo_confidencial`), el código de aplicación (`semgrep.fuentes_confidenciales` → `fuentes_no_escaneadas`) y los lockfiles (`osv-scanner.lockfiles_confidenciales`). Todos son `alcance_excluyente`: si valen > 0 o no están registrados, no hay pass |
| PV-R3-02 | COD-TIPOS | alta | `node_modules/.bin/tsc` = `#!/bin/sh exit 0` | pass | CONFIRMADO | no_evaluado (no se ejecuta) | Ver la sección «COD-TIPOS: riesgo de ejecutar binarios del repo auditado» |
| PV-R3-03 | SEG-SECRETO-REPO / SEG-SECRETO-BUNDLE | crítica | `apps/web/packages/ui/build/config.js` (profundidad 5) con `sk_live_` y `ghp_` | pass / no_aplica | CONFIRMADO | pass / **fail** | `gitleaks.sh`: la búsqueda de bundles ya no tiene `-maxdepth 4`. Las carpetas `dist`, `build`, `.next` y `out` se escanean a cualquier profundidad (el árbol las excluye a cualquier profundidad) |
| PV-R3-04 | SEG-SAST-INY, DAT-SQL-CONCATENADO | alta | `src/handlers.js` de ~2,1 MB con `eval` y `exec` | pass ×2 | CONFIRMADO | no_evaluado ×2 | `alcance.py`: el código de aplicación > 2 MB (que semgrep omite) cuenta en `fuentes_grandes` → `fuentes_no_escaneadas` (excluyente). `*.min.js` sigue excluido |
| PV-R3-05 | SEG-ENV-EJEMPLO (+ SEG-SECRETO-REPO) | alta | `packages/api/.env` versionado; `backend/.env` con `.gitignore` `/.env` | pass | CONFIRMADO | **fail** (env_comiteado / env_no_ignorado; también secreto_en_env) | `archivos_clave.py`: revisa los `.env*` reales de cualquier carpeta (`comun.recorrer`, sin dependencias ni build), no solo los de la raíz. Las rutas se informan relativas |
| PV-R3-06 | SEG-ENV-EJEMPLO | media | `.env.example` de 0 bytes y el código lee `STRIPE_SECRET_KEY` | pass | CONFIRMADO | no_evaluado | El pase `env_ejemplo` exige que el ejemplo declare variables y, entre ellas, todas las que el código lee por nombre literal (salvo NODE_ENV, MODE…). Sin pase no hay hallazgo, para no crear falsos positivos |
| PV-R3-07 | COD-CI-BASICO | alta | `run: node scripts/generate-test-fixtures.js` | pass | CONFIRMADO | **fail** (ci_sin_calidad) | `workflows.py`: `_token_calidad` exige que el argumento sea la herramienta o el subcomando completo (`pytest`, `test`, `test:unit`, `scripts/test.js`). No basta con que lo contenga (`generate-test-fixtures.js`, `deploy-test`, `print('tests ok')`) |
| PV-R3-08 | COD-CI-BASICO | media | `make test` con `test:` → `@echo ok` | pass | CONFIRMADO | **fail** | `make X` y `just X` leen el Makefile o el justfile. Cuentan solo si la receta, o la de un prerrequisito, ejecuta calidad. Sin archivo, sin target o con `-C`/`-f` no cuentan |
| PV-R3-09 | COD-CI-BASICO | media | `scripts.test = "node --version"` y `npm test` | pass | CONFIRMADO | **fail** | El nombre del script («test») ya no basta: el cuerpo tiene que ejecutar calidad. Siguen contando `jest`, `vitest`, `react-scripts test`, `ng test`, `next lint` y `node --test` |
| PV-R3-10 | DAT-PII-REPO | crítica | `db/seed.sql` con `INSERT` (nombre, RUT, diagnóstico VIH, email) y `db/export.yaml` | pass | CONFIRMADO | **fail** (pii_tabular, crítico) | `datos_confidenciales.py`: los `.sql` se inspeccionan siempre (columnas y valores de `INSERT`/`COPY`; un `CREATE TABLE` no es dato). Los `.yaml`/`.yml`/`.xml`/`.txt` y los comprimidos (`.zip`, `.gz`, `.7z`…) se inspeccionan si el nombre o la carpeta son sospechosos (seed, dump, export, backup, datos, pacientes…); `.bak`/`.dump`/`.dmp` se tratan siempre como no inspeccionables. Lo que no se puede descartar queda «no inspeccionable» e **impide el pase** |
| PV-R3-11 | DAT-PII-REPO | alta | `data/export.json` > 256 KiB con raíz objeto `{"pacientes_export": [...]}` | pass | CONFIRMADO | **fail** (pii_tabular) | Un JSON truncado que no se puede leer ya no se da por «configuración» por empezar con `{`. Se buscan claves y valores personales en lo leído; si no hay, queda no inspeccionable (sin pase). Se exceptúan los lockfiles y manifiestos (`package-lock.json`, `tsconfig.json`…) |
| PV-R3-12 | DAT-PII-REPO | alta | `data/registro.csv` versionado y borrado en el commit siguiente | pass | CONFIRMADO | **fail** (pii_tabular, «historial») | `inspeccionar_historial`: recorre `git rev-list --all --objects` (vía git_seguro). Las rutas confidenciales que solo están en el historial dan `trackeado_historial` (crítico, nuevo; mapea a DAT-PII-REPO). Los archivos de datos de commits anteriores se inspeccionan igual (blob acotado a 256 KiB, máx. 300 versiones). Si falla git o hay más versiones, no hay pase |
| PV-R3-13 | DAT-ESQUEMA-VERSIONADO | media | `migrations/0001_init.sql` = `-- TODO` | pass | CONFIRMADO | **fail** (migraciones_ausentes) | Un `.sql` cuenta como migración solo si tiene texto después de quitar los comentarios `--` y `/* */` |
| PV-R3-14 | OPS-HEALTH | media | `axios.get('/api/health')` en `web/monitor.js`, servidor sin ruta de salud | pass | CONFIRMADO | **fail** (health_ausente) | `RE_HEALTH` exige un receptor de servidor (`app`, `*router`, `*server`, `fastify`, `hono`, `r`, `e`, `g`, `mux`…). No acepta `axios`, `http`, `this.http`, `client`, `api` ni `ky` |
| PV-R3-15 | OPS-ERROR-TRACKING | baja | solo `@sentry/vite-plugin` (devDependency) | pass | CONFIRMADO | **fail** (error_tracking_ausente) | Se excluyen los paquetes de Sentry que solo sirven en el build (`*-plugin`, `cli`, `bundler-plugin-core`, `types`, `utils`) |
| R3.6-3 | SEG-DEPS-EXISTEN | media (N1) | `[dependency-groups]`, grupo dev de Poetry, `setup.py` y `-r deps/base.txt` con paquetes inventados | pass | CONFIRMADO | **fail** (inexistente) + sin pase | `registro_deps.py`: sigue los `-r` dentro del proyecto (un `-r` que no se puede seguir impide el pase) y lee `[dependency-groups]` (PEP 735), `[tool.poetry.group.*.dependencies]` y `[tool.poetry.dev-dependencies]`. `setup.py`, `setup.cfg` y `environment.yml`/`conda.yml` con dependencias pasan a `NO_CUBIERTOS` → no_evaluado. `setup.py` nunca se ejecuta |
| R3.6-4 | COD-TIPOS (sin conteo de archivos tipados) | baja | (el mismo fixture de PV-R3-02) | pass | CONFIRMADO (con PV-R3-02) | no_evaluado si tsc no tipa ≥ 1 archivo | `--listFiles`: el pase exige ≥ 1 archivo fuente del proyecto tipado (sin `node_modules` ni `.d.ts`) y registra cuántos en el mensaje |

**Resultado:** 17/17 CONFIRMADOS y 0 NO REPRODUCIBLES. Se corrigieron los 17, también los medios y bajos, porque todos eran de bajo costo. Ninguno de los 17 fixtures da `pass` después de la corrección. Cada uno da el defecto como `fail` o queda en `no_evaluado` con motivo. La única excepción es g03, donde SEG-SECRETO-REPO sigue en pass con razón: el secreto del bundle profundo ahora sale en SEG-SECRETO-BUNDLE, que pasa a `fail`.

## COD-TIPOS: riesgo de ejecutar binarios del repo auditado (decisión)

**Riesgo.** Hasta la ronda 3, `tipos.py` corría `npx --no-install tsc`, que resuelve y **ejecuta** cualquier `node_modules/.bin/tsc` del proyecto auditado. Un repositorio no confiable, o un `node_modules` manipulado, ejecuta así código arbitrario con los permisos del auditor. Además puede devolver código 0 para obtener el pase. Esto contradice la promesa del README de no ejecutar scripts del proyecto auditado.

**Decisión implementada (fail-closed):**

1. Se prefiere un tsc **confiable y ajeno al proyecto**: `AUDITOR_BIN_TSC`, o `tsc` del PATH, siempre que su ruta real no quede dentro del proyecto auditado. Un PATH que incluya `./node_modules/.bin` no lo vuelve confiable. tsc tipa los archivos; no ejecuta código del proyecto.
2. El `node_modules/.bin/tsc` del proyecto se ejecuta solo si se cumplen tres condiciones:
   - es un **enlace simbólico** cuya ruta real queda dentro de `node_modules/typescript/` del propio proyecto. Un archivo propio, o un enlace que apunta fuera, se rechaza;
   - `node_modules/typescript/package.json` declara `"name": "typescript"`;
   - el investigador declaró el proyecto confiable con `AUDITOR_CONFIAR_TSC_PROYECTO=1`.

   Si falla cualquiera de las tres, no se ejecuta nada y COD-TIPOS queda `no_evaluado` con el motivo.
3. El pase `sin_errores` exige ≥ 1 archivo fuente del proyecto tipado según `--listFiles`. Un binario que no tipa nada no da pase.

**Consecuencia para kine us (ESTIMACIÓN, no re-auditado):** en esta máquina no hay tsc global, así que el `pass` de COD-TIPOS de la corrida `1555` pasaría a `no_evaluado`. Para recuperarlo hay dos vías: indicar un tsc confiable (`AUDITOR_BIN_TSC=/ruta/a/tsc`) o declarar `AUDITOR_CONFIAR_TSC_PROYECTO=1` después de revisar su `node_modules`. **Decisión del investigador.**

## Regresión

- **Suite:** `python3 -m unittest discover -s tests` → **886 OK**. Antes eran 830; se sumaron las 56 de `test_pases_vacios_r4.py`.
  - Se actualizaron los datos de entrada de 9 pruebas antiguas (r1, r2, r3 y evidencia_pass) para registrar las claves nuevas en 0. Sin ellas, la regla fail-closed bloquea el pass, como corresponde.
  - Las 5 pruebas de `tipos` de `test_anexo_c.py` pasaron de `npx` falso a un tsc confiable externo falso.
- **App sembrada** (`bin/auditar all validacion/app-sembrada --modo estandar`; `validacion/metricas.py` sobre `hallazgos_todos.jsonl`; salida en `tests/.tmp/r4-app-sembrada/`):

| Métrica (IC95 % de Wilson) | Ronda 3 (cierre) | Ronda 4 |
|---|---|---|
| Sensibilidad SEG·N1 detectable en F1 | 23/23 = 1,00 (0,86-1,00) | **23/23 = 1,00 (0,86-1,00)** |
| Sensibilidad global | 57/67 = 0,85 (0,75-0,92) | **57/67 = 0,85 (0,75-0,92)** |
| FP en controles limpios | 0/56 (0,00-0,06) | **0/56 (0,00-0,06)** |
| VPP | 57/82 = 0,70 | 57/82 = 0,70 (0,59-0,78) |
| Estados pass / fail / no_evaluado | 3 / 27 / 115 | 3 / 27 / 115 |
| Nivel global / bloqueos | N0/N0 · 14 | N0/N0 · 14 |

Sin regresión. Los FN siguen siendo los mismos: D36, D41, D46, D48, D51 y D57-D61. Los 3 pass (COD-CI-BASICO, DAT-ESQUEMA-VERSIONADO e INF-INVENTARIO) se mantienen con evidencia.

## Limitaciones que quedan (no corregidas; riesgo bajo o medio)

1. **COD-CI-BASICO:**
   - `task`, `tox` y `nox` no leen su configuración: cuentan por el nombre completo de la tarea o sesión (`nox -s tests`).
   - `jest --passWithNoTests` sin tests cuenta como calidad.
2. **DAT-PII-REPO:**
   - No se inspeccionan los `.yaml`/`.xml`/`.txt` sin nombre ni carpeta sospechosos.
   - Un JSON con los registros anidados a más de un nivel (`{"a": {"pacientes": [...]}}`) se sigue tratando como configuración.
   - Los datos en prosa sin RUT ni email (nombres + diagnósticos en texto libre) solo bloquean el pase si el archivo es sospechoso, porque queda no inspeccionable.
3. **Rutas confidenciales por segmento** (`patients`, `pacientes`): el código bajo esas carpetas sigue sin escanearse para proteger la privacidad. El pase vacío está cerrado, pero el costo es un `no_evaluado` en proyectos clínicos con `src/patients/`. **Opciones para el investigador (GUÍA):**
   - (a) mantenerlo así;
   - (b) limitar los segmentos genéricos `patients`/`pacientes` a archivos de datos y dejar que el código se escanee;
   - (c) permitir que el creador declare esas rutas como código.
4. **SEG-DEPS-EXISTEN:** un `-r` anidado dentro de un archivo incluido que no se puede seguir no se informa (el de primer nivel sí).
5. **COD-TIPOS:** no se exige un umbral de cobertura (p. ej. ≥ 1 % del código o `checkJs`). Basta con ≥ 1 archivo tipado.
6. **kine us no se re-auditó** tras la ronda 4: los efectos esperados en sus 8 pass son una ESTIMACIÓN.
   - COD-TIPOS: probablemente `no_evaluado` (ver arriba).
   - DAT-PII-REPO: ahora depende también del historial y de los JSON grandes.
   - SEG-SECRETO-REPO: depende de si hay código en carpetas confidenciales.

## Archivos modificados

- `scripts/adaptadores/alcance.py`, `scripts/adaptadores/gitleaks.sh`, `scripts/adaptadores/osv.sh`, `catalogo/controles.toml` (PV-R3-01/03/04).
- `scripts/checks/tipos.py`, `scripts/ejecutar_scanners.sh` (PV-R3-02, R3.6-4).
- `scripts/checks/archivos_clave.py` (PV-R3-05/06/13/14/15).
- `scripts/checks/workflows.py` (PV-R3-07/08/09).
- `scripts/checks/datos_confidenciales.py` (PV-R3-10/11/12).
- `scripts/checks/registro_deps.py` (R3.6-3).
- Pruebas: `tests/test_pases_vacios_r4.py` (nuevo); ajustes en `tests/test_anexo_c.py`, `tests/test_pases_vacios_r1.py`, `tests/test_pases_vacios_r2.py`, `tests/test_pases_vacios_r3.py` y `tests/test_evidencia_pass.py`.
- `README.md`: ronda 4, runner de tipos y suite de 886 pruebas.
