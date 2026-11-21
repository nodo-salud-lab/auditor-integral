# 13 · Herramientas faltantes: recomendación con evidencia y fallbacks propios (Decisión 6)

**Fecha:** 2026-11-18 · **Sello:** GUÍA (procedimiento) + ESTIMACIÓN (coberturas) · **Prevalece:** `DECISIONES.md` #6.
**Alcance:** las 15 herramientas que hoy faltan en esta máquina (`command -v` → no encontrado, verificado el 2026-11-18): trivy, jscpd, knip, squawk, k6, hadolint, actionlint, checkov, lizard, playwright, lhci, nuclei, ZAP, syft, splinter. Instaladas y disponibles para los fallbacks: `semgrep 1.181.0`, `osv-scanner`, `gitleaks`, `zizmor`, `python3`, `node 22`/`npx`, `brew`, `pipx`, `docker`.

**Este informe no edita `config/`, `catalogo/` ni `scripts/`.** Los cambios sugeridos al catálogo y a `doctor.sh` están en el archivo aparte `investigacion/13-propuesta-fallbacks.toml`.

**Reglas de evidencia de este informe**
- Toda cifra de adopción tiene URL de API consultada el 2026-11-18. Las estrellas y descargas cambian a diario.
- **ESTIMACIÓN** = cobertura del fallback respecto a la herramienta real. Es un juicio de diseño (número de reglas reproducidas / intención del control) **no medido**. Se debe medir en F6 corriendo herramienta real y fallback sobre el mismo repositorio (ver §5).
- **NO VERIFICADO** = dato que no pude confirmar contra una fuente primaria.

---

## 1. Hallazgos de la verificación que cambian decisiones

1. **`brew install lizard` instala OTRO programa.** La fórmula Homebrew `lizard` es "Efficient compressor with very fast decompression" (homepage `github.com/inikep/lizard`, licencia BSD-2-Clause AND GPL-2.0-or-later) ([formulae.brew.sh/api/formula/lizard.json](https://formulae.brew.sh/api/formula/lizard.json)). El analizador de complejidad se instala con `pipx install lizard` (PyPI `lizard` 1.26.1, licencia MIT; [pypi.org/pypi/lizard/json](https://pypi.org/pypi/lizard/json)). `doctor.sh` ya usa `pipx install lizard`: correcto; no debe cambiarse a brew.
2. **Licencia de lizard:** GitHub la reporta como `NOASSERTION`/"Other", pero `LICENSE.txt` contiene el texto MIT ("Permission is hereby granted, free of charge…") con una salvedad de partes documentadas aparte ([repos/terryyin/lizard/contents/LICENSE.txt](https://github.com/terryyin/lizard/blob/master/LICENSE.txt)). PyPI declara MIT. Resuelve el "(revisar LICENSE)" de PLAN_MAESTRO §8.1: **MIT**, con la salvedad de revisar las excepciones del propio archivo (NO VERIFICADO cuáles son).
3. **El umbral de complejidad 15 tiene respaldo de facto:** lizard define `DEFAULT_CCN_THRESHOLD, DEFAULT_MAX_FUNC_LENGTH = 15, 1000` ([lizard_core/options.py, línea 12](https://github.com/terryyin/lizard/blob/master/lizard_core/options.py)). `umbrales.toml` lo tiene como `origen = "propuesta"`; puede pasar a `origen = "default_herramienta"` con esa URL (Decisión 2). Ver propuesta.
4. **jscpd usa `--min-tokens 50` y `--min-lines 5` por defecto** en su implementación actual en Rust (v5.4.3; tabla de opciones de [rust/jscpd/README.md](https://github.com/kucherenko/jscpd/blob/master/rust/jscpd/README.md) y [rust/npm/README.md](https://github.com/kucherenko/jscpd/blob/master/rust/npm/README.md); mismos valores en [README-v4.md](https://github.com/kucherenko/jscpd/blob/master/README-v4.md)). El fallback de duplicación debe calibrarse contra ambos valores. *(Corregido en verificación: la versión anterior citaba `rust/README.md`, donde `min_tokens: 50` aparece solo en un ejemplo de uso programático, no como default; y marcaba el mínimo de líneas como NO VERIFICADO, cuando sí está documentado: 5.)*
5. **`terrascan` (alternativa IaC) está archivado** (`archived: true`, último push 2025-11-20; [api.github.com/repos/tenable/terrascan](https://api.github.com/repos/tenable/terrascan)). No usar.
6. **`radon` (alternativa listada en COD-COMPLEJIDAD) no tiene push desde 2024-10-20** ([api.github.com/repos/rubik/radon](https://api.github.com/repos/rubik/radon)). Preferir lizard; para Python el fallback con `ast` lo reemplaza.
7. **splinter no es un binario:** es `splinter.sql`, un conjunto de vistas que se ejecuta contra la base ([README](https://github.com/supabase/splinter)). Requiere conexión a Postgres (o el MCP de Supabase, `get_advisors`, que expone los mismos lints). Sin conexión, el único camino es el análisis estático de migraciones (fallback §4.15).
8. **`doctor.sh` no lista nuclei, ZAP, syft ni splinter** (sí lista las otras 11). Se proponen las 4 líneas en el archivo de propuesta.
9. **Playwright y LHCI pueden correr vía `npx` porque node 22 está instalado**; faltan solo los navegadores (`npx playwright install chromium`). Su "fallback" estático cubre muy poco (§4.10, §4.11): conviene que `doctor` lo ofrezca como la instalación de mayor rendimiento.

---

## 2. Tabla resumen

Adopción: ★ = `stargazers_count` de `api.github.com/repos/<repo>`; descargas npm = última semana (2026-11-10 a 2026-11-16) de `api.npmjs.org/downloads/point/last-week/<pkg>`; PyPI = última semana de `pypistats.org/api/packages/<pkg>/recent`; Homebrew = instalaciones en 365 días de `formulae.brew.sh/api/formula/<f>.json`. Ninguno está archivado (salvo terrascan, descartado).

| Herramienta | Controles que cubre | Evidencia (★ · descargas · licencia · último push) | Instalación macOS | Fallback propio | Cobertura del fallback (ESTIMACIÓN) |
|---|---|---|---|---|---|
| **trivy** | SEG-DEPS-CVE-CRIT/ALTO (2.ª opción), INF-DOCKERFILE (2.ª), INF-IAC | 39.488 ★ · brew 146.032/año · Apache-2.0 · 2026-11-17 | `brew install trivy` | No hace falta para dependencias: **osv-scanner ya instalado** es la 1.ª opción. Para IaC/Dockerfile se delega en `check_dockerfile` y `check_iac` | Deps: ~90 % (osv-scanner, mismo origen de datos OSV para npm/PyPI). IaC/contenedor: ver checkov/hadolint. Escaneo de imagen construida: 0 % |
| **jscpd** | COD-DUPLICACION | 6.572 ★ · npm 5.834.860/sem · MIT · 2026-11-17 | `npm install -g jscpd` (o `brew install jscpd`, 1.801/año) | `check_duplicacion`: hash de ventanas de tokens normalizados (stdlib) | ~65 % de los clones tipo 1-2 de jscpd; % duplicado global ±2 pp |
| **knip** | COD-CICLOS-MUERTO | 12.688 ★ · npm 31.990.544/sem · ISC · 2026-11-17 | `npm install -D knip` (por proyecto) o `npx knip` | `check_deps_muertas`: grafo de imports (regex) vs `package.json`; archivos inalcanzables; ciclos | Deps sin uso/no declaradas: ~75 %; archivos sin uso: ~50 %; exports sin uso: 0 %; ciclos: ~80 % (equivalente a madge) |
| **squawk** | DAT-MIGRACIONES-SEGURAS, DAT-TIPOS | 1.267 ★ · npm `squawk-cli` 2.059.987/sem · Apache-2.0 · 2026-11-18 | `npm install -g squawk-cli` o `pipx install squawk-cli` | `check_migraciones_sql`: 14 reglas regex sobre sentencias SQL | ~14 de ~77-79 reglas (88 archivos en docs/docs; 9 son páginas no-regla: cli, code-formatter, github_app, locks, quick_start, rules-overview, safe_migrations, troubleshooting, web-frameworks; syntax-error y semantic-error son diagnósticos dudosos como "regla"), pero las de mayor riesgo: ~60 % de la intención del control |
| **k6** | ESC-SMOKE, ESC-CARGA-PROMEDIO, ESC-BREAKPOINT, ESC-SOAK-SPIKE, SEG-RATELIMIT (2.ª) | 32.342 ★ · brew 70.480/año · **AGPL-3.0** · 2026-11-17 | `brew install k6` | `check_humo_http`: smoke concurrente con `urllib` + `ThreadPoolExecutor` (solo URL autorizada) | ESC-SMOKE ~50 %; promedio/breakpoint/soak/spike: 0 % (`no_evaluado`) |
| **hadolint** | INF-DOCKERFILE | 12.541 ★ · brew 28.531/año · **GPL-3.0** · 2026-10-19 | `brew install hadolint` | `check_dockerfile`: 12 reglas regex alineadas a DL3002/3004/3006/3007/3020/3025/3008/3018/3013 + secretos y multi-stage | ~15 % de las reglas de hadolint (sin ShellCheck); ~80 % de la intención de INF-DOCKERFILE |
| **actionlint** | SEG-CICD (2.ª), COD-CI-BASICO (2.ª) | 4.419 ★ · brew 213.556/año · MIT · 2026-07-16 | `brew install actionlint` | **zizmor (instalado) cubre la parte de seguridad**; `check_workflows` añade sintaxis mínima y la verificación "CI corre lint/test" | Seguridad de SEG-CICD: ~85 % (zizmor). Validación sintáctica/tipos de expresiones de actionlint: ~20 % |
| **checkov** | INF-IAC | 9.163 ★ · PyPI 1.329.028/sem · brew 35.471/año · Apache-2.0 · 2026-11-17 | `pipx install checkov` (o `brew install checkov`) | `check_iac`: reglas semgrep locales (Terraform/HCL, YAML k8s, docker-compose) | ~5 % de los >1.000 checks de checkov (NO VERIFICADO el total actual); ~50 % de los misconfigs críticos típicos |
| **lizard** | COD-COMPLEJIDAD | 2.604 ★ · PyPI 546.662/sem · MIT (LICENSE.txt) · 2026-11-18 | `pipx install lizard` (**no** `brew install lizard`) | `check_complejidad`: Python con `ast` (McCabe exacto); JS/TS con regex + emparejamiento de llaves | Python ~95 %; JS/TS ~70 % (funciones flecha anidadas y JSX bajan precisión) |
| **playwright** (`playwright_ux`) | UX-FLUJO-FELIZ, AXE-CRIT, REFLOW, ESTADOS, ERRORES-VISIBLES, TECLADO, TACTIL, FOCO-OCULTO, CONSENTIMIENTO, SW-PWA, COD-E2E-TRAZA | 100.450 ★ · npm 175.273.259/sem · Apache-2.0 · 2026-11-18 | `npm install -D @playwright/test && npx playwright install chromium` (o `npm init playwright@latest`; [playwright.dev](https://playwright.dev/docs/intro)) | `check_ux_estatico`: análisis de HTML/JSX/CSS (html.parser + regex) | ~20 % del bloque UX en conjunto; FLUJO-FELIZ, REFLOW, ESTADOS, TECLADO, FOCO-OCULTO: 0 % (`no_evaluado`) |
| **lhci** | UX-LCP-LAB, UX-LIGHTHOUSE, INF-CACHE-CDN (2.ª) | 7.154 ★ · npm `@lhci/cli` 2.750.059/sem · Apache-2.0 · 2026-11-17 | `npm install -g @lhci/cli` | `check_presupuesto_build`: tamaño de bundle, recursos bloqueantes, imágenes sin dimensiones | ~15 % (proxy); LCP no se mide → UX-LCP-LAB `no_evaluado` |
| **nuclei** | SEG-DAST-PLANTILLAS, SEG-BFLA (2.ª) | 33.061 ★ · brew 18.220/año · MIT · 2026-11-17 | `brew install nuclei` | `check_exposicion_http`: ~25 rutas de exposición con firma de contenido (stdlib) | ~30 % de las plantillas de la categoría "exposures" relevantes a apps web; <5 % del total de plantillas |
| **ZAP** | SEG-DAST-PASIVO, SEG-COOKIES/CSRF/HEADERS/CORS/ERRORES (2.ª) | 16.216 ★ · cask `zap` 7.470/año · Apache-2.0 · 2026-11-16 | `brew install --cask zap` o Docker `ghcr.io/zaproxy/zaproxy:stable zap-baseline.py` ([zaproxy.org](https://www.zaproxy.org/docs/docker/baseline-scan/)) | `check_pasivo_http`: rastreo de 1 nivel + 14 reglas pasivas (stdlib) | ~35 % de las alertas pasivas más frecuentes; sin spider AJAX ni reglas de contenido profundo |
| **syft** | SEG-SBOM, COD-LICENCIAS | 9.918 ★ · brew 38.789/año · Apache-2.0 · 2026-11-16 | `brew install syft` | `check_sbom`: parseo de lockfiles → CycloneDX 1.5 mínimo + licencias desde metadatos instalados | npm/PyPI: ~75 % de componentes con licencia; binarios/imagenes: 0 % |
| **splinter** | DAT-RLS-ON, RLS-PERMISIVA, RLS-METADATA, SECDEF, GRANTS, PK-FK, FK-INDICE, HIGIENE | 292 ★ · sin registro de paquetes (SQL) · PostgreSQL · 2026-11-17 | No se instala: `psql "$DB_URL_SOLO_LECTURA" -f splinter.sql` (requiere `brew install libpq`) o MCP Supabase `get_advisors` | `check_rls_estatico`: análisis estático de `supabase/migrations/*.sql` | ~40 % (estado declarado en migraciones; cambios hechos en el dashboard no se ven); HIGIENE: 0 % |

**Licencias a vigilar (ESTIMACIÓN, no es asesoría legal):** k6 (AGPL-3.0) y hadolint (GPL-3.0) se invocan como binarios externos opcionales; no se embeben ni redistribuyen (PLAN_MAESTRO §8.1). Los fallbacks son código propio y no copian reglas de estas herramientas: se alinean con los **identificadores públicos** de reglas (p. ej. DL3007) solo para trazabilidad.

---

## 3. Contrato común de los fallbacks

### 3.1 Salida (`crudo/check_<nombre>.json`)

Se respeta el contrato ya implementado en `scripts/checks/comun.py` (`hallazgo()`, `pase()`, `resultado()`):

```json
{
  "check": "dockerfile",
  "version": "1",
  "estado": "ok",
  "motivo": null,
  "reemplaza": "hadolint",
  "cobertura": "parcial (fallback)",
  "hallazgos": [
    {
      "regla": "check:dockerfile.tag_latest",
      "archivo": "Dockerfile",
      "linea": 1,
      "mensaje": "FROM usa la etiqueta latest o no fija versión (equivale a hadolint DL3007/DL3006).",
      "evidencia": "FROM node:latest",
      "severidad_sugerida": "media"
    }
  ],
  "checks_pass": [
    {"regla": "check:dockerfile.add_vs_copy", "archivo": "Dockerfile", "mensaje": "No se usa ADD para archivos locales."}
  ]
}
```

- **Campos nuevos propuestos** (no existen hoy en `comun.py`): `reemplaza` (herramienta real que falta) y `cobertura` (`"parcial (fallback)"`). Decisión 6 exige que el hallazgo diga `cobertura: parcial (fallback)`; la forma más simple es que `normalizar/checks.py` copie `cobertura` del archivo a cada hallazgo y al `estado.json` del control. Ver propuesta.
- `regla` siempre `check:<nombre>.<subregla>`; `<nombre>` = nombre del script sin `.py`.
- `evidencia` ≤ 300 caracteres y pasada por `enmascarar()` cuando pueda contener valores (ENV/ARG, URLs con credenciales).
- `severidad_sugerida`: la final la fija el catálogo (§3.5 del plan: la herramienta puede subirla, no bajarla).
- **Pase solo si la subregla se evaluó de verdad.** Si no hay Dockerfile, no se emite pase: el control queda `no_aplica` por condición del catálogo, no por el fallback.
- Si la herramienta real está instalada, el fallback **no corre** (o corre y se descarta), para no duplicar fingerprints. Orden: herramienta real > fallback.

### 3.2 Invocación y límites

- Uso: `python3 -I scripts/checks/<nombre>.py PROYECTO DIR_CRUDO [--url URL]` (igual que `archivos_clave.py`). `-I` evita importar módulos plantados en el repo auditado.
- Recorrido con `comun.recorrer()` (excluye `node_modules`, `dist`, etc.). **Proyecto kine us herramienta (Decisión 3):** añadir `datos-reales` y `datos-abiertos` a las exclusiones del recorrido de todos los fallbacks; esos contenidos nunca se leen ni salen en `evidencia`.
- Tiempo máximo por fallback: `umbral.timeout_adaptador` de `umbrales.toml`.
- **Fallbacks de red** (`check_humo_http`, `check_exposicion_http`, `check_pasivo_http`): solo corren con `--url` declarada por el creador en la entrevista, solo contra `localhost`/`127.0.0.1`/`*.localhost` o un host de preview/staging que el creador confirme como suyo, con confirmación explícita en la corrida. Solo `GET`/`HEAD`, sin payloads de ataque, con tope de solicitudes. Sin `--url` → `estado = "no_evaluado"`, `motivo = "sin URL autorizada"`.

---

## 4. Especificación implementable por fallback

Notación: **R** = regla (subregla), **Sev** = severidad sugerida, **Pase** = qué se emite en `checks_pass` cuando la subregla se evaluó sin hallazgos.

### 4.1 trivy → no requiere fallback nuevo (delegación)

| Función de trivy | Sustituto ya disponible o propuesto | Cobertura (ESTIMACIÓN) |
|---|---|---|
| CVE de dependencias (`trivy fs`) | `osv-scanner` instalado (1.ª opción del catálogo) | ~90 % para npm/PyPI |
| Misconfig de Dockerfile (`trivy config`) | `check_dockerfile` (§4.6) | ~80 % de la intención |
| Misconfig IaC | `check_iac` (§4.8) | ~50 % de los críticos típicos |
| Escaneo de imagen construida | ninguno | 0 % → `no_evaluado` |
| Secretos | `gitleaks` instalado | ~100 % de la función equivalente |

Acción: `doctor` debe informar "trivy falta, pero su función de dependencias la cubre osv-scanner" para no generar falsa alarma.

### 4.2 jscpd → `check_duplicacion`

- **Entradas:** archivos de código (`.js .jsx .ts .tsx .mjs .cjs .py .vue .svelte .go .java .rb .php .css .scss`), excluyendo tests de fixtures, `*.min.*`, `*.d.ts`, `*-lock*`, migraciones generadas, y archivos > `comun.TAMANO_MAX`. Parámetros: `MIN_TOKENS = 50` y `MIN_LINEAS = 5` (ambos iguales a los defaults documentados de jscpd 5.x).
- **Regla (algoritmo, stdlib):**
  1. Tokenizar cada archivo con una regex única: `r"[A-Za-z_$][\w$]*|\d+(?:\.\d+)?|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|[{}()\[\];,.<>=!+\-*/%&|^~?:]+"`, descartando comentarios (`//…`, `/*…*/`, `#…` en Python) antes de tokenizar. Guardar la línea de cada token.
  2. **Normalización tipo 2:** identificadores → `I`, números → `N`, cadenas → `S`; palabras clave del lenguaje se conservan (lista fija por lenguaje).
  3. Ventana deslizante de `MIN_TOKENS` tokens: `h = hashlib.blake2b(" ".join(ventana).encode(), digest_size=8)`; índice `h → [(archivo, linea_ini, linea_fin)]`.
  4. Fusionar ventanas consecutivas que coinciden en el mismo par de archivos (extensión maximal del clon). Descartar clones con < `MIN_LINEAS` líneas o solapados consigo mismos.
  5. `dup_pct = lineas_duplicadas_únicas / lineas_de_código_totales × 100` (líneas no vacías ni solo comentario).
- **Subreglas:**
  - R `bloque_duplicado` · Sev `baja` · uno por par de clones (máx. 5 por archivo, "y N más"): `mensaje = "Bloque de 34 líneas duplicado con src/b.ts:120-153"`, `evidencia` = primeras 2 líneas del bloque.
  - R `porcentaje_global` · Sev `baja` (o `media` si > 2× umbral) · si `dup_pct > umbral.duplicacion_global` (5 %, propuesta). `archivo = null`, `evidencia = "dup=7.4 % (412/5.560 líneas)"`.
  - Pase `porcentaje_global` si `dup_pct ≤ umbral`.
- **Mapeo:** `check:duplicacion.*` → COD-DUPLICACION.
- **Limitaciones:** no detecta clones tipo 3 (con líneas insertadas); jscpd usa tokenizadores por lenguaje más finos. **Cobertura ~65 %** de clones y % global ±2 pp (ESTIMACIÓN; medir en F6).

### 4.3 knip → `check_deps_muertas`

- **Entradas:** `package.json` (raíz y workspaces de `workspaces`/`pnpm-workspace.yaml` leído con regex), archivos JS/TS/Vue/Svelte, `tsconfig.json` (`compilerOptions.paths`, leído con `json` tras quitar comentarios), configs conocidas (`vite.config.*`, `next.config.*`, `eslint.config.*`, `.eslintrc*`, `tailwind.config.*`, `postcss.config.*`, `vitest.config.*`, `playwright.config.*`, `babel.config.*`) y `scripts` de `package.json`.
- **Regla:**
  1. Extraer especificadores con `r"""(?:import\s[^'"]*?from\s*|import\s*\(\s*|require\s*\(\s*|export\s[^'"]*?from\s*|import\s+)['"]([^'"]+)['"]"""` y `@import`/`url()` en CSS.
  2. Paquete = especificador no relativo y sin alias: `@scope/nombre` o `nombre` (cortar en `/`). Quitar prefijo `node:` y módulos núcleo de Node (lista de `node -p "require('module').builtinModules"` volcada en una constante).
  3. Usados = imports ∪ binarios citados en `scripts` (`r"(?:^|&&|\|\||;)\s*(?:npx\s+)?([a-z@][\w@/.-]*)"` → paquete dueño del binario si coincide el nombre) ∪ paquetes citados en configs ∪ `@types/X` cuando `X` es usado ∪ plugins por convención (`eslint-plugin-*`, `@vitejs/plugin-*`, `prettier-plugin-*`) si aparece el nombre en cualquier config.
  4. **Grafo de archivos:** nodos = archivos; aristas = imports relativos resueltos (`.ts .tsx .js .jsx /index.*`) y alias de `paths`. Entradas = `main`, `module`, `exports`, `bin` de `package.json`, `index.html` (`<script type="module" src>`), `src/main.*`, `src/index.*`, rutas de frameworks (`app/**/page.*`, `pages/**`, `src/routes/**`), tests y configs.
- **Subreglas:**
  - R `dep_sin_uso` · Sev `baja` · dependencia en `dependencies` nunca usada (`archivo = "package.json"`, línea de la clave).
  - R `devdep_sin_uso` · Sev `info`.
  - R `dep_no_declarada` · Sev `media` · paquete importado que no está en ninguna sección de `package.json` (riesgo de dependencia fantasma; conecta con SEG-DEPS-EXISTEN).
  - R `archivo_inalcanzable` · Sev `baja` · archivo de código no alcanzable desde ninguna entrada (máx. 20, "y N más").
  - R `ciclo_imports` · Sev `baja` · ciclo detectado con DFS (Tarjan SCC de tamaño > 1); `evidencia = "a.ts → b.ts → a.ts"`.
  - Pases: `deps`, `archivos`, `ciclos` cuando se evaluaron sin hallazgos.
- **Mapeo:** `check:deps_muertas.*` → COD-CICLOS-MUERTO; `check:deps_muertas.dep_no_declarada` además → SEG-DEPS-EXISTEN (propuesta).
- **Limitaciones:** knip tiene ~100 plugins de frameworks; este fallback conoce ~10 convenciones. No detecta exports/tipos sin uso. **Cobertura:** deps ~75 %, archivos ~50 %, exports 0 %, ciclos ~80 % (ESTIMACIÓN).

### 4.4 squawk → `check_migraciones_sql`

- **Entradas:** `supabase/migrations/*.sql`, `prisma/migrations/**/migration.sql`, `migrations/**/*.sql`, `drizzle/**/*.sql`, `db/migrate/**/*.sql`, `alembic/versions/*.py` (solo cadenas dentro de `op.execute("…")` y llamadas `op.add_column(..., nullable=False)` vía `ast`).
- **Preproceso:** quitar comentarios `--` y `/* */`; separar sentencias por `;` respetando cadenas y bloques `$$…$$`/`$tag$…$tag$`; normalizar espacios; registrar línea inicial. Detectar si el archivo está en transacción (`BEGIN`) para la regla de concurrencia.
- **Subreglas** (nombre squawk equivalente entre paréntesis; reglas en [squawk docs](https://github.com/sbdchd/squawk/tree/master/docs/docs)):

| R | Regex (IGNORECASE, sobre la sentencia) | Sev | Squawk |
|---|---|---|---|
| `index_sin_concurrently` | `^CREATE\s+(UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY)` y la tabla no fue creada en el mismo archivo | alta | require-concurrent-index-creation |
| `drop_index_sin_concurrently` | `^DROP\s+INDEX\s+(?!CONCURRENTLY)` | media | require-concurrent-index-deletion |
| `concurrently_en_transaccion` | `CONCURRENTLY` dentro de un bloque `BEGIN…COMMIT` | alta | ban-concurrent-index-creation-in-transaction |
| `not_null_sin_default` | `ALTER\s+TABLE\s+\S+\s+ADD\s+(COLUMN\s+)?\S+\s+[^,;]*\bNOT\s+NULL\b` sin `\bDEFAULT\b` en la misma cláusula | alta | adding-required-field |
| `set_not_null` | `ALTER\s+COLUMN\s+\S+\s+SET\s+NOT\s+NULL` | media | adding-not-nullable-field |
| `drop_column` | `ALTER\s+TABLE\s+\S+\s+DROP\s+(COLUMN\s+)?(?!CONSTRAINT)\S+` | alta | ban-drop-column |
| `drop_table` | `^DROP\s+TABLE\b` | alta | ban-drop-table |
| `rename` | `RENAME\s+(COLUMN\s+)?\S+\s+TO\b` o `ALTER\s+TABLE\s+\S+\s+RENAME\s+TO` | media | renaming-column / renaming-table |
| `cambio_tipo` | `ALTER\s+COLUMN\s+\S+\s+(SET\s+DATA\s+)?TYPE\b` | media | changing-column-type |
| `fk_sin_not_valid` | `ADD\s+CONSTRAINT\s+\S+\s+FOREIGN\s+KEY` sin `NOT\s+VALID` (tabla preexistente) | media | adding-foreign-key-constraint |
| `check_sin_not_valid` | `ADD\s+CONSTRAINT\s+\S+\s+CHECK\b` sin `NOT\s+VALID` | media | constraint-missing-not-valid |
| `sin_lock_timeout` | archivo con `ALTER TABLE` y sin `SET\s+(LOCAL\s+)?lock_timeout` | baja | require-lock-timeout (squawk también tiene require-timeout-settings y require-statement-timeout) |
| `tipo_timestamp` | `\btimestamp\b(?!\s*with\s+time\s+zone)(?!tz)` en columnas nuevas | baja | prefer-timestamptz |
| `tipo_serial_int` | `\b(serial|int4?|integer)\b` como PK, o `\bvarchar\(\d+\)|\bchar\(` | baja | prefer-identity / prefer-bigint-over-int / prefer-text-field |

- **Pase:** `migraciones` cuando hay ≥ 1 archivo analizado y 0 hallazgos de severidad ≥ media.
- **Mapeo:** `check:migraciones_sql.tipo_*` → DAT-TIPOS; el resto → DAT-MIGRACIONES-SEGURAS.
- **Supuesto declarado:** la regla `index_sin_concurrently` no aplica a tablas creadas en la misma migración (tabla vacía, sin lock relevante). Las migraciones antiguas ya aplicadas generan ruido: se propone analizar solo las migraciones del último N commits o posteriores a una marca, configurable (ESTIMACIÓN; decide el investigador).
- **Cobertura ~60 %** de la intención del control (ESTIMACIÓN): sin parser real de Postgres, falla con SQL dinámico y `DO $$` bloques.

### 4.5 k6 → `check_humo_http`

- **Entradas:** `--url` autorizada (§3.2) y opcionalmente lista de rutas GET públicas (`/`, `/api/health` si `archivos_clave` detectó health). Parámetros por defecto (ESTIMACIÓN, alineados a un smoke típico): 5 usuarios virtuales concurrentes, 30 s, pausa 1 s entre solicitudes por usuario, tope 200 solicitudes.
- **Regla:** `concurrent.futures.ThreadPoolExecutor(max_workers=VU)`; cada worker hace `urllib.request.urlopen(Request(url, method="GET", headers={"User-Agent": "auditor-integral-smoke"}), timeout=10)`; mide `time.perf_counter()`; registra código y error. Calcula p50/p95 (`statistics.quantiles(n=20)[18]`) y tasa de error (`códigos ≥ 500` o excepción).
- **Subreglas:**
  - R `error_rate` · Sev `media` · tasa de error > 1 % (ESTIMACIÓN, valor típico de threshold `http_req_failed: rate<0.01`; **NO VERIFICADO** como norma).
  - R `p95` · Sev `media` · p95 > umbral SLO declarado en la entrevista; sin SLO declarado → solo se informa en `checks_pass` con el valor, sin fallar (no se inventa umbral).
  - R `inalcanzable` · Sev `alta` · 100 % de errores.
  - R `ratelimit_ausente` · Sev `info` · **no se ejecuta por defecto**: sondear rate limit sobre login requiere POST y puede bloquear cuentas; queda `no_evaluado` (SEG-RATELIMIT lo cubre semgrep).
  - Pase `smoke` con `mensaje = "5 VU · 30 s · 150 req · p95=180 ms · err=0 %"`.
- **Mapeo:** `check:humo_http.*` → ESC-SMOKE. ESC-CARGA-PROMEDIO, ESC-BREAKPOINT, ESC-SOAK-SPIKE, ESC-VOLUMEN-REALISTA quedan `no_evaluado` con motivo "requiere k6".
- **Limitación:** el GIL y el generador en la misma máquina sesgan la latencia a alta concurrencia; por eso el fallback **no** intenta breakpoint. **Cobertura ESC-SMOKE ~50 %**, resto 0 %.

### 4.6 hadolint → `check_dockerfile`

- **Entradas:** `Dockerfile`, `*.Dockerfile`, `Dockerfile.*`, `**/Containerfile`. Unir líneas con `\` final; registrar etapas (`FROM … AS nombre`).
- **Subreglas:**

| R | Regla | Sev | Equivale a |
|---|---|---|---|
| `tag_latest` | `^FROM\s+(--platform=\S+\s+)?([^\s:@]+)(:latest)?(\s|$)` sin `:tag` ni `@sha256` (ignorar `scratch` y referencias a etapas previas) | media | DL3006 / DL3007 |
| `usuario_root` | la última etapa no tiene `USER` o el último `USER` es `root`/`0` | media | DL3002 |
| `sudo` | `RUN\b.*\bsudo\b` | media | DL3004 |
| `add_vs_copy` | `^ADD\s+(?!https?://)(?!\S+\.(tar|tar\.gz|tgz|tar\.xz)\s)` | baja | DL3020 |
| `add_url` | `^ADD\s+https?://` | media | (buena práctica; ADD remoto sin checksum) |
| `cmd_shell_form` | `^(CMD|ENTRYPOINT)\s+(?!\[)` | baja | DL3025 |
| `apt_sin_pin` | `apt-get\s+install` con paquetes sin `=` | baja | DL3008 |
| `apk_sin_pin` | `apk\s+add` con paquetes sin `=` | baja | DL3018 |
| `pip_sin_pin` | `pip3?\s+install` con paquetes sin `==` y sin `-r` | baja | DL3013 |
| `secreto_en_env` | `^(ENV|ARG)\s+\S*(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY)\S*[=\s]+\S+` (valor enmascarado) | alta | (trivy/checkov: secretos en imagen) |
| `curl_pipe_sh` | `(curl|wget)[^|]*\|\s*(ba)?sh` | media | (buena práctica) |
| `sin_multistage` | un solo `FROM` y presencia de `npm (ci|install)`, `pip install`, `go build` o `cargo build` | baja | (intención INF-DOCKERFILE "multi-stage") |
| `copy_todo_sin_dockerignore` | `COPY\s+\.\s` y no existe `.dockerignore` | media | (riesgo de copiar `.env`) |

- **Pase:** uno por subregla evaluada sin hallazgos, con `archivo` = Dockerfile.
- **Alternativa con semgrep:** las mismas reglas pueden escribirse en `reglas/semgrep/dockerfile.yml` (`languages: [dockerfile]`; semgrep soporta Dockerfile, NO VERIFICADO para la versión 1.181 localmente). Se recomienda regex por simplicidad y velocidad.
- **Mapeo:** `check:dockerfile.*` → INF-DOCKERFILE; `secreto_en_env` además → SEG-SECRETO-REPO.
- **Cobertura:** ~15 % del total de reglas de hadolint (no incluye ShellCheck sobre `RUN`), **~80 % de la intención de INF-DOCKERFILE** (latest, root, multi-stage, secretos) (ESTIMACIÓN).

### 4.7 actionlint → `check_workflows` (complemento de zizmor)

zizmor ya cubre inyección de expresiones, permisos, acciones sin fijar a SHA, `pull_request_target` peligroso y credenciales persistidas. El fallback solo agrega lo que actionlint aporta y zizmor no:

- **Entradas:** `.github/workflows/*.yml|*.yaml`. Sin PyYAML (no es stdlib): análisis por líneas con indentación.
- **Subreglas:**
  - R `sin_on` / `sin_jobs` · Sev `media` · falta clave raíz `on:` (o `"on":`, `true:`) o `jobs:`.
  - R `job_sin_runs_on` · Sev `media` · bloque de job (indentación 2 bajo `jobs:`) sin `runs-on:` ni `uses:` (workflow reutilizable).
  - R `tabulador` · Sev `media` · tabulador en indentación (YAML inválido).
  - R `expresion_mal_cerrada` · Sev `media` · conteo desigual de `${{` y `}}` en una línea.
  - R `runner_obsoleto` · Sev `baja` · `runs-on:` con `ubuntu-18.04|ubuntu-20.04|macos-11|macos-12|windows-2019` (lista a mantener; fechas de retiro NO VERIFICADAS en este informe).
  - R `ci_sin_calidad` · Sev `media` · ningún `run:` del conjunto de workflows contiene `lint`, `test`, `tsc`, `typecheck`, `vitest`, `jest`, `pytest` o `npm run (lint|test|build)` → COD-CI-BASICO.
  - Pases: `sintaxis`, `ci_calidad`.
- **Mapeo:** `check:workflows.ci_*` → COD-CI-BASICO; el resto → SEG-CICD (junto con `zizmor:*`).
- **Cobertura:** seguridad de SEG-CICD ~85 % (zizmor); validación de sintaxis y tipos de actionlint ~20 % (ESTIMACIÓN).

### 4.8 checkov → `check_iac` (reglas semgrep locales + regex)

- **Entradas:** `**/*.tf`, `**/*.tfvars`, manifiestos k8s (`*.yaml` con `apiVersion:` y `kind:`), `docker-compose*.yml`, `compose*.yaml`, `fly.toml`, `render.yaml`, `vercel.json`, `netlify.toml`. Si no hay ninguno → no se emite nada (INF-IAC `no_aplica` por condición del catálogo).
- **Implementación:** `semgrep --config reglas/semgrep/iac/ --json --metrics=off` (reglas locales, sin registro remoto) para HCL/YAML; regex para TOML/JSON.
- **Subreglas:**

| R | Patrón | Sev |
|---|---|---|
| `tf_ingreso_abierto` | `cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"` en `ingress` con puerto 22/3389/5432/3306/6379/27017 | alta |
| `tf_bucket_publico` | `acl\s*=\s*"public-read(-write)?"` o `block_public_acls\s*=\s*false` | alta |
| `tf_sin_cifrado` | `encrypted\s*=\s*false` / `storage_encrypted\s*=\s*false` | media |
| `tf_bd_publica` | `publicly_accessible\s*=\s*true` | alta |
| `tf_secreto_literal` | `(password|secret|token)\s*=\s*"[^"$]{6,}"` (enmascarado) | alta |
| `k8s_privilegiado` | `privileged:\s*true` / `allowPrivilegeEscalation:\s*true` | alta |
| `k8s_host` | `host(Network|PID|IPC):\s*true` | alta |
| `k8s_sin_nonroot` | Deployment/Pod sin `runAsNonRoot:\s*true` | media |
| `k8s_sin_limites` | contenedor sin `resources:` → `limits:` | baja |
| `k8s_latest` | `image:\s*\S+(:latest)?\s*$` sin tag | media |
| `compose_puerto_bd` | `ports:` exponiendo `5432|3306|6379|27017` sin `127.0.0.1:` | media |
| `compose_privilegiado` | `privileged:\s*true` | alta |

- **Mapeo:** `check:iac.*` → INF-IAC.
- **Cobertura:** ~5 % del catálogo de checks de checkov; ~50 % de los misconfigs críticos típicos de un proyecto pequeño (ESTIMACIÓN).

### 4.9 lizard → `check_complejidad`

- **Entradas:** `.py` (vía `ast`), `.js .jsx .ts .tsx .mjs .cjs` (vía regex). Umbrales: `umbral.complejidad_ciclomatica_max` (15) y largo de función 1000 líneas (default lizard, verificado; demasiado laxo para el informe, se sugiere informar además > 80 líneas como `info`, ESTIMACIÓN).
- **Python (ast, McCabe):** por cada `FunctionDef`/`AsyncFunctionDef`/`Lambda`: `ccn = 1 + #(If, For, AsyncFor, While, ExceptHandler, With?no, IfExp, comprehension (cada `for` y cada `if`), match_case) + Σ(len(BoolOp.values) − 1) + #assert`. No contar funciones anidadas en la externa (se reportan aparte). Coincide con la definición de lizard salvo detalles (lizard cuenta `and/or` como tokens; mismo resultado).
- **JS/TS (regex):**
  1. Quitar comentarios, cadenas y template literals (reemplazar por `""` conservando saltos de línea).
  2. Detectar inicios de función: `function\s*\*?\s*\w*\s*\(`, métodos `^\s*(async\s+)?(static\s+)?[\w$]+\s*\([^)]*\)\s*(:\s*[^{]+)?\{`, flechas `(\([^)]*\)|[\w$]+)\s*(:\s*[^=]+)?=>\s*\{` (flechas sin llave: CCN del cuerpo de una expresión).
  3. Emparejar `{`/`}` para delimitar el cuerpo.
  4. `ccn = 1 + count(\bif\b|\bfor\b|\bwhile\b|\bcase\b|\bcatch\b|\?(?![.?])|&&|\|\||\?\?)` dentro del cuerpo, excluyendo cuerpos de funciones anidadas. Lizard también suma parámetros por defecto (README de lizard, sección "JavaScript and TypeScript parameters": cada parámetro por defecto o inicializador de desestructuración suma 1 al CCN, incluidos los anidados y los de desestructuración dentro del cuerpo): sumar `=` de nivel superior en la lista de parámetros y en patrones de desestructuración.
- **Subreglas:**
  - R `ccn_alta` · Sev `baja` (`media` si > 2× umbral) · `mensaje = "procesarPago (CCN 23 > 15)"`, `linea` = inicio.
  - R `funcion_larga` · Sev `info` · > 80 líneas (ESTIMACIÓN).
  - R `archivo_grande` · Sev `info` · > 500 líneas de código (ESTIMACIÓN; COD-COMPLEJIDAD menciona "tamaño de archivos").
  - Pase `ccn` con `mensaje = "142 funciones, CCN máx 12, media 2,8"`.
- **Mapeo:** `check:complejidad.*` → COD-COMPLEJIDAD.
- **Cobertura:** Python ~95 %, JS/TS ~70 % (ESTIMACIÓN).

### 4.10 playwright (`playwright_ux`) → `check_ux_estatico`

Sin navegador no hay medición de comportamiento; este fallback revisa **solo lo verificable en el código fuente**. Los controles dinámicos quedan `no_evaluado` con motivo "requiere Playwright (npx disponible)".

- **Entradas:** `index.html`, `public/*.html`, `dist/index.html` si existe, `*.jsx|*.tsx|*.vue|*.svelte|*.html`, CSS/SCSS, `manifest.json|*.webmanifest`.
- **Subreglas (con `html.parser` para HTML y regex para JSX):**

| R | Regla | Sev | Control |
|---|---|---|---|
| `html_sin_lang` | `<html` sin `lang=` | media | UX-LANG |
| `sin_viewport` | falta `<meta name="viewport"` o contiene `user-scalable=no` / `maximum-scale=1` | alta | UX-REFLOW (parcial) |
| `img_sin_alt` | `<img` sin `alt` (JSX: `<img(?![^>]*\balt=)[^>]*>`) | alta | UX-AXE-CRIT (parcial) |
| `input_sin_label` | `<input` (no `hidden|submit|button`) sin `id` referido por `<label for|htmlFor>`, sin `aria-label(ledby)` y no anidado en `<label>` | alta | UX-FORMULARIOS |
| `input_sin_autocomplete` | `type="(email|password|tel)"` o `name="(email|name|phone)"` sin `autoComplete/autocomplete` | baja | UX-FORMULARIOS |
| `boton_sin_nombre` | `<button[^>]*>\s*<(svg|img|i)\b[^>]*/?>\s*</button>` sin `aria-label` | alta | UX-AXE-CRIT (parcial) |
| `click_en_div` | `<(div|span)[^>]*onClick=` sin `role=` y sin `onKeyDown|tabIndex` | media | UX-TECLADO (parcial) |
| `tabindex_positivo` | `tabindex="[1-9]` / `tabIndex=\{[1-9]` | media | UX-TECLADO (parcial) |
| `outline_none` | CSS `outline\s*:\s*(none|0)` sin regla `:focus-visible` en el mismo archivo | media | UX-TECLADO / UX-FOCO-OCULTO (parcial) |
| `ancho_fijo` | CSS `(min-)?width\s*:\s*([4-9]\d\d|\d{4,})px` fuera de `@media` | baja | UX-REFLOW (parcial) |
| `objetivo_pequeno` | CSS de `button|a|[role=button]` con `(height|width)\s*:\s*(1\d|2[0-3]|\d)px` | baja | UX-TACTIL (parcial) |
| `tracker_sin_consentimiento` | `<script` de `googletagmanager|google-analytics|connect.facebook.net|hotjar|clarity.ms` en `index.html` sin atributo `type="text/plain"` ni gestor de consentimiento conocido | media | UX-CONSENTIMIENTO (parcial) |
| `manifest_incompleto` | manifest sin `name`, `icons`, `start_url` o `display` | baja | UX-SW-PWA (parcial) |
| `fetch_sin_catch` | `fetch\(` o `axios\.` en componente sin `catch`/`try` ni estado `error` en el archivo | media | UX-ESTADOS (parcial, heurística) |

- **Mapeo:** propuesta de nuevas reglas `check:ux_estatico.<sub>` en cada control indicado; **ninguna subregla emite pase de un control dinámico** (AXE-CRIT, REFLOW, TECLADO, ESTADOS no pueden quedar `pass` por este fallback; quedan `no_evaluado` si no hay hallazgos). Esto evita sobreestimar el nivel (Decisión 6: "cobertura parcial").
- **Cobertura:** ~20 % del bloque UX en conjunto; UX-FLUJO-FELIZ, UX-REFLOW, UX-ESTADOS, UX-TECLADO, UX-FOCO-OCULTO, UX-ERRORES-VISIBLES, COD-E2E-TRAZA: 0 % como verificación (ESTIMACIÓN). axe-core detecta en navegador mucho más que estas reglas estáticas.

### 4.11 lhci → `check_presupuesto_build`

- **Entradas:** carpeta de build si existe (`dist/`, `build/`, `.next/static/`, `out/`); si no existe, **no se construye** (construir ejecuta código del proyecto) → `no_evaluado`. Además `index.html`.
- **Subreglas:**
  - R `js_inicial_pesado` · Sev `media` · suma gzip (`gzip.compress`) de los `<script src>` y `modulepreload` de `index.html` > 170 KB (ESTIMACIÓN; valor de referencia de presupuesto de JS móvil **NO VERIFICADO** contra fuente primaria en este informe).
  - R `asset_grande` · Sev `baja` · imagen > 200 KB o JS/CSS individual > 500 KB sin comprimir (ESTIMACIÓN).
  - R `imagen_formato_antiguo` · Sev `info` · `.png|.jpe?g` > 100 KB sin variante `.webp|.avif`.
  - R `script_bloqueante` · Sev `media` · `<script src>` en `<head>` sin `defer|async|type="module"`.
  - R `img_sin_dimensiones` · Sev `baja` · `<img` sin `width` y `height` (riesgo CLS).
  - R `fuente_sin_swap` · Sev `baja` · `@font-face` sin `font-display`.
  - R `sin_cache_hash` · Sev `info` · assets en build sin hash en el nombre (`[.-][a-f0-9]{8,}\.`) → INF-CACHE-CDN.
  - Pase `presupuesto` con tamaños medidos.
- **Mapeo:** `check:presupuesto_build.*` → UX-LIGHTHOUSE (parcial) e INF-CACHE-CDN (parcial). **UX-LCP-LAB nunca pasa por fallback** (LCP solo se mide en navegador).
- **Cobertura:** ~15 % (ESTIMACIÓN).

### 4.12 nuclei → `check_exposicion_http`

- **Entradas:** `--url` autorizada (§3.2). Solo `GET`, tope 40 solicitudes, 1 solicitud/200 ms.
- **Regla:** para cada ruta, `GET` sin seguir redirecciones a otro host; hallazgo solo si el código es 200 **y** el cuerpo cumple la firma (evita falsos positivos de SPA que devuelven `index.html` para todo: comparar además contra el hash del cuerpo de una ruta aleatoria inexistente `/__auditor_<uuid4>`).

| R | Ruta(s) | Firma en el cuerpo | Sev |
|---|---|---|---|
| `git_expuesto` | `/.git/config`, `/.git/HEAD` | `[core]` / `ref: refs/` | critica |
| `env_expuesto` | `/.env`, `/.env.local`, `/.env.production` | `^[A-Z_]+=.+` en ≥ 2 líneas (valores nunca guardados en evidencia: solo nombres de clave) | critica |
| `sourcemap` | `<bundle>.js.map` (de los `<script src>` de `/`) | `"sources"` y `"mappings"` | media |
| `backup` | `/backup.zip`, `/db.sql`, `/dump.sql`, `/backup.sql` | `Content-Type` binario/zip o `CREATE TABLE` | alta |
| `ds_store` | `/.DS_Store` | bytes `\x00\x00\x00\x01Bud1` | baja |
| `panel_admin` | `/admin`, `/wp-admin/`, `/phpmyadmin/`, `/_admin` | 200 sin redirección a login y distinto del fallback SPA | media (→ SEG-BFLA, triage LLM) |
| `debug` | `/debug`, `/__debug__/`, `/actuator/env`, `/server-status`, `/phpinfo.php` | firmas conocidas (`Apache Server Status`, `phpinfo()`, `"propertySources"`) | alta |
| `swagger_publico` | `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql` (introspección no se envía) | `"openapi"` / `"swagger"` | info |
| `supabase_service_key_en_bundle` | (lo cubre gitleaks sobre `dist/`) | — | — |

- **Mapeo:** `check:exposicion_http.*` → SEG-DAST-PLANTILLAS; `panel_admin` → SEG-BFLA.
- **Cobertura:** ~30 % de las plantillas "exposures" relevantes a una app web pequeña; < 5 % del total de plantillas de nuclei (ESTIMACIÓN).

### 4.13 ZAP baseline → `check_pasivo_http`

- **Entradas:** `--url` autorizada. Rastreo de 1 nivel: `GET /` + hasta 20 enlaces del mismo origen (`html.parser`, `<a href>`, `<form action>` sin enviar el formulario) + una ruta inexistente para provocar 404.
- **Subreglas pasivas** (sobre cabeceras y cuerpo de cada respuesta):

| R | Regla | Sev | Control |
|---|---|---|---|
| `sin_csp` | falta `Content-Security-Policy` en documentos HTML | media | SEG-HEADERS |
| `csp_insegura` | CSP con `'unsafe-inline'` en `script-src` o `*` | baja | SEG-HEADERS |
| `sin_hsts` | HTTPS sin `Strict-Transport-Security` | media | SEG-HEADERS |
| `sin_nosniff` | falta `X-Content-Type-Options: nosniff` | baja | SEG-HEADERS |
| `sin_antiframe` | falta `frame-ancestors` en CSP y `X-Frame-Options` | media | SEG-HEADERS |
| `cookie_sin_flags` | `Set-Cookie` de sesión (`sess|sid|token|auth|jwt` en el nombre) sin `HttpOnly`, `Secure` (en HTTPS) o `SameSite` | media | SEG-COOKIES |
| `cors_comodin` | `Access-Control-Allow-Origin: *` con `Access-Control-Allow-Credentials: true`, o origen reflejado al enviar `Origin: https://auditor.invalid` | alta | SEG-CORS |
| `version_servidor` | `Server`/`X-Powered-By` con número de versión | baja | SEG-HEADERS |
| `traza_en_error` | cuerpo del 404/500 con `Traceback|at \S+ \(.*:\d+:\d+\)|Exception in|SQLSTATE|stack` | media | SEG-ERRORES |
| `contenido_mixto` | página HTTPS que carga `src="http://` | media | SEG-HEADERS |
| `form_sin_csrf` | `<form method="post">` sin input oculto con `csrf|_token|authenticity` cuando hay cookie de sesión | baja (heurística, requiere triage) | SEG-CSRF |
| `password_autocomplete` | `<input type="password"` en HTTP o dentro de `<form>` con `action` a HTTP | media | SEG-COOKIES/UX-FORMULARIOS |
| `cache_sensible` | respuesta con `Set-Cookie` de sesión sin `Cache-Control: no-store` | baja | INF-CACHE-CDN |
| `info_en_comentarios` | comentarios HTML con `TODO|password|api[_-]?key|internal` | info | SEG-ERRORES |

- **Mapeo:** `check:pasivo_http.*` → SEG-DAST-PASIVO y, por subregla, a los controles de la tabla (complementa el adaptador `headers` del catálogo; si `headers` ya existe, `sin_csp/sin_hsts/sin_nosniff/sin_antiframe` se fusionan por fingerprint).
- **Cobertura:** ~35 % de las alertas pasivas más frecuentes de ZAP baseline; sin spider AJAX, sin las reglas de análisis de contenido (p. ej. divulgación de PII) (ESTIMACIÓN).

### 4.14 syft → `check_sbom`

- **Entradas:** `package-lock.json` (v2/v3: `packages`), `pnpm-lock.yaml` (regex de claves `/<nombre>@<versión>` o `<nombre>@<versión>:`), `yarn.lock` (regex de cabeceras de bloque y `version "x"`), `requirements*.txt` (`==`), `uv.lock`/`poetry.lock` (`tomllib`), `Pipfile.lock` (`json`). Licencias: `node_modules/<pkg>/package.json` → `license`, y `site-packages/*.dist-info/METADATA` → `License-Expression`/`License:`/clasificadores, **solo si ya están instalados** (no se instala nada).
- **Salida adicional:** `crudo/sbom.cdx.json` CycloneDX 1.5 mínimo: `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name","version","purl":"pkg:npm/<n>@<v>","licenses":[{"license":{"id":…}}]}]}`.
- **Subreglas:**
  - R `sbom_no_versionado` · Sev `baja` · no existe SBOM en el repo/release (`*.cdx.json`, `*.spdx.json`, `sbom*`) ni paso de CI que lo genere (`syft|cdxgen|cyclonedx` en workflows) → SEG-SBOM.
  - R `licencia_copyleft` · Sev `media` · dependencia de producción con `GPL-|AGPL-|SSPL|LGPL-` (LGPL `baja`) cuando el modelo declarado es propietario/SaaS (pregunta de entrevista) → COD-LICENCIAS.
  - R `licencia_desconocida` · Sev `baja` · sin licencia o `UNLICENSED`/`SEE LICENSE IN`.
  - R `proyecto_sin_licencia` · Sev `info` · el repo no tiene `LICENSE*` ni `license` en `package.json`.
  - Pase `sbom_generado` con `mensaje = "412 componentes, 96 % con licencia"`.
- **Mapeo:** `check:sbom.sbom_*` → SEG-SBOM; `check:sbom.licencia_*` y `proyecto_*` → COD-LICENCIAS.
- **Cobertura:** npm/PyPI ~75 % de componentes con licencia resuelta si `node_modules` existe; ~30 % sin él (solo nombres/versiones); binarios e imágenes 0 % (ESTIMACIÓN).

### 4.15 splinter → `check_rls_estatico`

**Primero, el camino real (sin instalar nada nuevo):** si el MCP de Supabase está conectado al proyecto, `get_advisors` (solo lectura) entrega los mismos lints de splinter → cobertura completa, con confirmación del creador. Si hay `DATABASE_URL` de solo lectura y `psql`: `psql -f splinter.sql`. El fallback estático solo corre si ninguno de los dos está disponible.

- **Entradas:** `supabase/migrations/*.sql` en orden lexicográfico (orden de aplicación), `supabase/seed.sql` excluido (puede tener datos; además Decisión 3 sobre confidencialidad). Se reconstruye un **estado acumulado**: tablas creadas/eliminadas, `ENABLE ROW LEVEL SECURITY`, políticas, funciones, grants, índices.
- **Subreglas** (lint de splinter equivalente):

| R | Regla sobre el estado acumulado | Sev | Lint splinter | Control |
|---|---|---|---|---|
| `rls_deshabilitado` | tabla en `public` (o esquema expuesto) sin `ALTER TABLE … ENABLE ROW LEVEL SECURITY` posterior | critica | 0013 | DAT-RLS-ON |
| `rls_sin_politica` | RLS habilitado y 0 políticas | info | 0008 | DAT-RLS-PERMISIVA |
| `politica_siempre_true` | `CREATE POLICY … (USING|WITH CHECK)\s*\(\s*true\s*\)` para `UPDATE|DELETE|INSERT|ALL` (o SELECT en tabla con columnas de usuario) | critica | 0024 | DAT-RLS-PERMISIVA |
| `politica_user_metadata` | política con `user_metadata` o `raw_user_meta_data` | alta | 0015 | DAT-RLS-METADATA |
| `secdef_sin_search_path` | `SECURITY DEFINER` sin `SET search_path` en la misma definición | alta | 0011 | DAT-SECDEF |
| `secdef_ejecutable_anon` | función `SECURITY DEFINER` sin `REVOKE EXECUTE … FROM (public|anon)` posterior | alta | 0028/0029 | DAT-SECDEF |
| `auth_users_expuesto` | vista en `public` que hace `FROM auth.users` | critica | 0002 | DAT-GRANTS |
| `grant_anon_amplio` | `GRANT (ALL|INSERT|UPDATE|DELETE) … TO anon` | alta | — (DAT-GRANTS) | DAT-GRANTS |
| `sin_pk` | `CREATE TABLE` sin `PRIMARY KEY` | media | 0004 | DAT-PK-FK |
| `fk_sin_indice` | `REFERENCES t(col)` / `FOREIGN KEY (col)` sin índice cuya primera columna sea `col` | media | 0001 | DAT-FK-INDICE |
| `vista_security_definer` | vista sin `security_invoker = true` en `public` (Postgres 15+) | alta | 0010 | DAT-RLS-ON |
| `bucket_publico` | `insert into storage.buckets … public … true` | media | 0025 (parcial) | DAT-BUCKETS |

- **Mapeo:** `check:rls_estatico.*` → controles de la tabla.
- **Limitación crítica:** el estado real de la BD puede diferir de las migraciones (cambios desde el dashboard, migraciones no versionadas). Por eso, con el fallback, **DAT-RLS-ON y DAT-RLS-PERMISIVA pueden quedar en `fail`, pero nunca en `pass` sin `checks_pass` explícito "verificado contra migraciones" y aviso de cobertura parcial**. Propuesta: que `gates.py` trate un `pass` de un control crítico de DAT que provenga solo de fallback como `manual_pendiente` hasta confirmar con advisors (decide el investigador).
- **Cobertura:** ~40 % (ESTIMACIÓN); DAT-HIGIENE (índices sin uso, bloat, autovacuum) 0 %: requiere estadísticas de la BD viva.

---

## 5. Cómo medir la cobertura real (para F6)

Las coberturas de este informe son **ESTIMACIÓN**. Protocolo propuesto (GUÍA; decide el investigador):

1. Repositorios de prueba: Juice Shop (brazo B) y kine us herramienta (brazo C, excluyendo `datos-reales/` y `datos-abiertos/`), más 2-3 repos públicos pequeños con Dockerfile y migraciones Supabase.
2. Para cada par (herramienta real, fallback): correr ambos sobre el mismo commit, normalizar a (archivo, línea ± 3, categoría).
3. Métricas: sensibilidad del fallback = hallazgos de la herramienta reproducidos / hallazgos de la herramienta (por categoría equivalente); precisión = hallazgos del fallback confirmados por la herramienta o por revisión humana / hallazgos del fallback; concordancia del estado del control (`pass`/`fail`) con kappa de Cohen. IC95 % por Wilson (proporciones) — estudio piloto, sin umbral de aprobación (Decisión 8).
4. Reemplazar cada ESTIMACIÓN de §2 por el valor medido y su IC95 %.

---

## 6. Orden de implementación sugerido (por valor / esfuerzo)

1. `check_migraciones_sql` y `check_rls_estatico` (riesgo alto en DAT, sin red, stdlib).
2. `check_dockerfile`, `check_complejidad`, `check_duplicacion` (stdlib, deterministas, baratos).
3. `check_deps_muertas`, `check_sbom`.
4. `check_workflows`, `check_iac` (pocos proyectos objetivo tienen IaC).
5. `check_ux_estatico`, `check_presupuesto_build`.
6. Fallbacks de red (`check_pasivo_http`, `check_exposicion_http`, `check_humo_http`): al final y siempre detrás de confirmación y URL autorizada.

## 7. Fuentes consultadas (2026-11-18)

- GitHub REST API `repos/<owner>/<repo>`: aquasecurity/trivy, kucherenko/jscpd, webpro-nl/knip, sbdchd/squawk, grafana/k6, hadolint/hadolint, rhysd/actionlint, bridgecrewio/checkov, terryyin/lizard, microsoft/playwright, GoogleChrome/lighthouse-ci, projectdiscovery/nuclei, zaproxy/zaproxy, anchore/syft, supabase/splinter, rubik/radon, tenable/terrascan, pahen/madge, jendrikseipp/vulture.
- npm: https://api.npmjs.org/downloads/point/last-week/{jscpd,knip,@lhci/cli,playwright,squawk-cli,madge}
- PyPI: https://pypistats.org/api/packages/{lizard,checkov,vulture}/recent ; https://pypi.org/pypi/lizard/json
- Homebrew: https://formulae.brew.sh/api/formula/{trivy,jscpd,k6,hadolint,actionlint,checkov,lizard,nuclei,syft}.json ; https://formulae.brew.sh/api/cask/zap.json
- Reglas: hadolint README (tabla DL3002/3004/3006/3007/3008/3013/3018/3020/3025) https://github.com/hadolint/hadolint ; squawk docs https://github.com/sbdchd/squawk/tree/master/docs/docs ; splinter lints https://github.com/supabase/splinter/tree/main/lints ; lizard `lizard_core/options.py` y LICENSE.txt ; jscpd `rust/README.md` y `rust/npm/README.md`.
- Instalación: https://www.zaproxy.org/docs/docker/baseline-scan/ ; https://playwright.dev/docs/intro ; https://grafana.com/docs/k6/latest/set-up/install-k6/ ; squawk README ; actionlint README.

---

## Verificación

Verificador escéptico, 2026-11-18. Consultas en vivo con `gh api`, `curl` a APIs públicas (npm, PyPI/pypistats, Homebrew). Ninguna edición en `config/`, `catalogo/` ni `scripts/`.

| # | Afirmación | Fuente consultada | Resultado |
|---|---|---|---|
| 1 | ★, licencia, último push y no-archivado de las 15 herramientas (p. ej. trivy 39.488 ★, playwright 100.450 ★, k6 32.342 ★ AGPL-3.0, hadolint 12.541 ★ GPL-3.0, splinter 292 ★ PostgreSQL) | `gh api repos/<owner>/<repo>` (17 repos) | **Confirmado** (todos los valores coinciden exactamente) |
| 2 | terrascan archivado, último push 2025-11-20; radon sin push desde 2024-10-20 | https://api.github.com/repos/tenable/terrascan ; https://api.github.com/repos/rubik/radon | **Confirmado** |
| 3 | `brew install lizard` instala un compresor (inikep/lizard, BSD-2-Clause AND GPL-2.0-or-later); PyPI lizard 1.26.1 MIT | https://formulae.brew.sh/api/formula/lizard.json ; https://pypi.org/pypi/lizard/json | **Confirmado** |
| 4 | lizard `DEFAULT_CCN_THRESHOLD, DEFAULT_MAX_FUNC_LENGTH = 15, 1000` | https://github.com/terryyin/lizard/blob/master/lizard_core/options.py (línea 12) | **Confirmado** |
| 5 | LICENSE.txt de lizard es MIT "except as documented below" | https://github.com/terryyin/lizard/blob/master/LICENSE.txt | **Confirmado** (las excepciones siguen sin detallarse: NO VERIFICADO) |
| 6 | lizard suma parámetros por defecto al CCN en JS/TS | https://github.com/terryyin/lizard (README, "JavaScript and TypeScript parameters") | **Confirmado y precisado**: también suman inicializadores de desestructuración |
| 7 | jscpd default `min_tokens: 50` (fuente: rust/README.md) | https://github.com/kucherenko/jscpd/blob/master/rust/jscpd/README.md | **Corregido**: el valor 50 es correcto, pero la fuente citada era un ejemplo de API; default real documentado en la tabla de opciones de rust/jscpd/README.md (v5.4.3). `--min-lines` default = 5 (antes NO VERIFICADO) |
| 8 | squawk: ~75 reglas, ~13 páginas no-regla | `gh api repos/sbdchd/squawk/contents/docs/docs` (88 archivos) | **Corregido**: 9 páginas no-regla → ~77-79 reglas. Equivalencia de `sin_lock_timeout` corregida a `require-lock-timeout` |
| 9 | Números de lints de splinter (0001, 0002, 0004, 0008, 0010, 0011, 0013, 0015, 0024, 0025, 0028, 0029) | `gh api repos/supabase/splinter/contents/lints` | **Confirmado** (nombres coinciden con la regla descrita) |
| 10 | IDs hadolint DL3002/3004/3006/3007/3008/3013/3018/3020/3025 y su significado | README de https://github.com/hadolint/hadolint | **Confirmado** |
| 11 | Descargas npm semana 2026-11-10/16: jscpd 5.834.860; knip 31.990.544; playwright 175.273.259; squawk-cli 2.059.987; @lhci/cli 2.750.059 | https://api.npmjs.org/downloads/point/last-week/<pkg> | **Confirmado** |
| 12 | PyPI última semana: checkov 1.329.028; lizard 546.662 | https://pypistats.org/api/packages/{checkov,lizard}/recent | **Confirmado** |
| 13 | Homebrew instalaciones 365 d: trivy 146.032; k6 70.480; hadolint 28.531; actionlint 213.556; checkov 35.471; nuclei 18.220; syft 38.789; jscpd 1.801; cask zap 7.470 | https://formulae.brew.sh/api/formula/<f>.json ; https://formulae.brew.sh/api/cask/zap.json | **Confirmado**. Precisión: Homebrew declara k6 como `AGPL-3.0-or-later` y hadolint como `GPL-3.0-only` |
| 14 | Presupuesto de JS inicial 170 KB gzip; threshold `http_req_failed rate<0.01` como norma; fechas de retiro de runners | — | Sin cambio: siguen **NO VERIFICADO** (correctamente marcados) |
| 15 | Coberturas de los fallbacks (%) | — | Siguen siendo **ESTIMACIÓN** no medida; no verificables hasta F6 (§5) |

**Correcciones aplicadas:** §1 punto 4 (fuente y default de líneas de jscpd), §2 fila squawk (conteo de reglas), §4.2 (MIN_LINEAS ahora respaldado), §4.4 (equivalencia `require-lock-timeout`), §4.9 (desestructuración en lizard); `13-propuesta-fallbacks.toml` sección D (fuente de `duplicacion_min_tokens` corregida y nuevo `duplicacion_min_lineas`). El archivo TOML se validó con `tomllib`.
