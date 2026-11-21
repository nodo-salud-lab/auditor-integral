#!/usr/bin/env python3
"""archivos_clave — presencia o ausencia de archivos que un proyecto listo para producción necesita
(PLAN_MAESTRO §3.2). Informa AUSENCIAS como hallazgos y PRESENCIAS como checks_pass.

Subregla (hallazgo / pase)                     → control (vía mapea_reglas del catálogo)
  readme_ausente | readme_sin_arranque / readme → COD-REPRO
  git_sin_repo | git_sin_versionar / git       → COD-REPRO  (ronda 2: el pase exige ≥ 1 archivo del proyecto en
                                                 el índice de git, no solo estar dentro de un work tree)
  env_ejemplo_ausente / env_ejemplo            → SEG-ENV-EJEMPLO
  env_comiteado | env_no_ignorado / env_ignorado → SEG-ENV-EJEMPLO
  lockfile_ausente / lockfile                  → SEG-LOCKFILE  (ronda 2: lockfile_vacio, lockfile_invalido,
                                                 lockfile_ignorado, lockfile_host_no_permitido / lockfile_valido,
                                                 lockfile_versionado, lockfile_ci, lockfile_hosts; el catálogo exige
                                                 los cuatro pases últimos)
  ci_ausente / ci                              → COD-CI-BASICO  (ronda 1: el pase `ci` exige que algún `run:` de
                                                 .github/workflows ejecute lint/typecheck/tests —workflows.calidad_ci—;
                                                 un CI que no lo hace, o que no es de GitHub Actions, no da pase)
  tests_ausentes / tests                       → COD-TESTS-HUMO
  health_ausente / health                      → OPS-HEALTH          (solo si hay servidor; ronda 2: ruta registrada)
  migraciones_ausentes / migraciones           → DAT-ESQUEMA-VERSIONADO (solo si hay base de datos; ronda 2: ≥ 1
                                                 migración real, no .gitkeep ni README)
  doc_agente_ausente | doc_agente_vacio / doc_agente, doc_agente_readme → COD-DOC-AGENTE (ronda 2: documento
                                                 con contenido y README de arranque, ambos exigidos)
  error_tracking_ausente / error_tracking      → OPS-ERROR-TRACKING
  secreto_en_env → SEG-SECRETO-REPO; secreto_en_env_local (ronda 6: .env ignorado y sin historial) → SEG-SECRETO-LOCAL

Git se consulta en solo lectura. Uso: archivos_clave.py PROYECTO DIR_CRUDO
Ronda 4 (investigacion/16): .env* reales de cualquier carpeta (no solo la raíz) para env_comiteado/env_no_ignorado y
secreto_en_env (PV-R3-05); env_ejemplo exige un ejemplo con variables que declare las que el código lee por nombre
literal (PV-R3-06); un .sql de migración con solo comentarios no es migración (PV-R3-13); la ruta de salud tiene que
registrarse en un objeto de servidor, no en un cliente HTTP (PV-R3-14), y fuera de tests y fixtures
(autoauditoría 2026-11-20); los plugins de build de Sentry no son
error tracking (PV-R3-15).
"""
import fnmatch
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(1, str(Path(__file__).resolve().parent.parent))
import comun  # noqa: E402
import env_publicas  # noqa: E402
import git_seguro  # noqa: E402
import workflows  # noqa: E402

NOMBRE = "archivos_clave"
EXT_CODIGO = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".php", ".java", ".kt", ".rs"}
LOCKFILES_NODE = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock", "npm-shrinkwrap.json")
LOCKFILES_PY = ("uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock", "requirements.lock")
EJEMPLOS_ENV = (".env.example", ".env.sample", ".env.template", ".env.dist", "example.env", ".env.local.example")
DOCS_AGENTE = ("CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules",
               ".github/copilot-instructions.md", ".cursor/rules")
CI = (".github/workflows", ".gitlab-ci.yml", ".circleci/config.yml", "azure-pipelines.yml",
      "bitbucket-pipelines.yml", "Jenkinsfile", ".buildkite", ".woodpecker.yml", ".drone.yml")
# Ronda 4 (PV-R3-15): paquetes de Sentry que solo sirven en el build (subida de sourcemaps, CLI, tipos): no son un SDK.
ERROR_TRACKING_NO_SDK = re.compile(r"^@sentry/(.+-plugin|bundler-plugin-core|cli|types|utils|"
                                   r"babel-plugin-component-annotate)$|^@sentry/.*-plugin$", re.I)
ERROR_TRACKING = re.compile(r"^(@sentry/|sentry-sdk|sentry_sdk|@bugsnag/|bugsnag|rollbar|@rollbar/|"
                            r"honeybadger|@honeybadger-io/|@highlight-run/|highlight-io|logrocket|"
                            r"dd-trace|@datadog/browser-rum|newrelic|@appsignal/|raygun|posthog)", re.I)
MIGRACIONES = ("supabase/migrations", "prisma/migrations", "migrations", "alembic/versions", "drizzle",
               "db/migrate", "database/migrations", "migrate")
# Ronda 6 (stack): el README de una CLI/librería Python, Rust, Go o con make/just/docker también es «de arranque»; antes
# solo se leía el primer README* por orden alfabético (README.es.md antes que README.md) y faltaban pipx, pytest, etc.
RE_ARRANQUE = re.compile(
    r"\b(npm|pnpm|yarn|bun)\s+(i|install|ci|run\s+\w+|dev|start|test)\b|\bpip3?\s+install\b|"
    r"\bpython3?\s+-m\s+(pip\s+install|venv|\w+)|\bpipx\s+(install|run)\b|\buvx?\s+(sync|run|pip\s+install|tool\s+install)\b|"
    r"\buvx\s+\w+|\bpoetry\s+(install|run|sync)\b|\bpdm\s+(install|sync|run)\b|\bhatch\s+(run|shell)\b|"
    r"\bpipenv\s+(install|sync|run)\b|\bconda\s+env\s+create\b|"
    r"\bdocker[ -]compose\s+(up|run|build)\b|\bdocker\s+(build|run)\b|"
    r"\bnpx\s+\w+|\bcargo\s+(run|build|install|test)\b|\bgo\s+(run|build|install|test)\b|\bflask\s+run\b|"
    r"\buvicorn\s+\w+|\bgunicorn\s+\w+|\bstreamlit\s+run\b|\bdeno\s+(run|task)\b", re.I | re.M)
# Palabras que también son prosa («make sure», «just a moment», «we use pytest»): solo cuentan dentro de código
# (bloque ``` … ```, `en línea`, línea con prompt `$ ` o indentada con 4 espacios).
RE_ARRANQUE_EN_CODIGO = re.compile(r"(?:^|[\s;&|(])(?:make|just)[ \t]+[\w-]+|(?:^|[\s;&|(])(?:pytest|tox|nox)\b", re.M)
RE_CODIGO_MD = re.compile(r"```.*?```|~~~.*?~~~|`[^`\n]+`|^(?: {4}|\t|[ \t]*[$>] ).*$", re.S | re.M)


def hay_arranque(texto):
    """True si el README trae un comando de instalación o arranque (ronda 6: también Python, Rust, Go, make/just)."""
    texto = texto or ""
    if RE_ARRANQUE.search(texto):
        return True
    return any(RE_ARRANQUE_EN_CODIGO.search(m.group(0).strip("`~")) for m in RE_CODIGO_MD.finditer(texto))
RE_SERVIDOR = re.compile(
    r"\bexpress\s*\(\)|from\s+['\"]express['\"]|require\(['\"]express['\"]\)|\bfastify\s*\(|"
    r"from\s+['\"](hono|koa|@nestjs/core)['\"]|\bFastAPI\s*\(|\bFlask\s*\(__name__|"
    r"export\s+(async\s+)?function\s+(GET|POST)\b|http\.createServer\(", re.I)
# Ronda 2: el pase exige una RUTA de salud registrada (método de router, decorador, comparación con req.url o una ruta
# por archivo), no cualquier literal 'status'/'ping' del código (claves JSON, campos, fetch del cliente).
# Ronda 6 (stack): también nombres en español (/salud, /estado, /vivo, /listo) y /healthz, /livez, /readyz, /ping.
NOMBRES_HEALTH = (r"(?:_?health|healthz|healthcheck|health-check|livez|liveness|readyz|readiness|ready|status|ping|"
                  r"salud|estado|estado-salud|vivo|listo|chequeo)")
# Ronda 4 (PV-R3-14): el método tiene que llamarse sobre un objeto de servidor (app, router, server, fastify, hono, r, e,
# g, mux…), no sobre un cliente HTTP (axios.get, http.get, this.http.get, client.get, api.get, ky.get).
RECEPTOR_SERVIDOR = r"(?<![\w.$])(?:\w*(?:app|router|server)|r|e|g|mux|fastify|hono|srv|engine|routes?)"
RE_HEALTH = re.compile(
    r"""(?:""" + RECEPTOR_SERVIDOR + r"""\s*\.\s*(?:get|head|all|route|use|handle|handlefunc|any)\s*\(\s*|"""
    r"""@[\w.]+\.(?:get|head|route|api_route)\s*\(\s*|"""
    r"""\b(?:url|pathname|path)\s*===?\s*)['"`]/(?:api/)?(?:v\d+/)?""" + NOMBRES_HEALTH + r"""/?['"`]"""
    r"""|@(?:Get|Head|Controller)\s*\(\s*['"`]/?""" + NOMBRES_HEALTH + r"""['"`]"""
    r"""|\b(?:re_)?path\s*\(\s*r?['"]\^?/?(?:api/)?""" + NOMBRES_HEALTH + r"""/?\$?['"]""", re.I)
RE_RUTA_HEALTH_ARCHIVO = re.compile(
    r"(^|/)(app|pages|routes|api)/(.+/)?" + NOMBRES_HEALTH + r"(/(route|index|\+server))?\.[cm]?[jt]sx?$", re.I)
RE_ENV_EN_CODIGO = re.compile(r"process\.env|import\.meta\.env|os\.environ|os\.getenv|Deno\.env|\$env/")
DEPS_SERVIDOR = re.compile(r"^(express|fastify|koa|hono|@nestjs/core|@hapi/hapi|fastapi|flask|django|"
                           r"starlette|aiohttp|sanic)$", re.I)
DEPS_BD = re.compile(r"^(pg|postgres|mysql2?|@supabase/supabase-js|@prisma/client|prisma|drizzle-orm|"
                     r"knex|sequelize|typeorm|mongoose|sqlalchemy|psycopg2?(-binary)?|asyncpg|django|"
                     r"sqlmodel|tortoise-orm|peewee|better-sqlite3|kysely)$", re.I)


def _git(proyecto, *args):
    """git sobre el repo auditado sin ejecutar nada definido en su .git/config (ver git_seguro)."""
    return git_seguro.ejecutar(proyecto, *args)


def _en_repo(proyecto):
    codigo, salida = _git(proyecto, "rev-parse", "--is-inside-work-tree")
    return codigo == 0 and salida.strip() == "true"


def _hay_versionados(proyecto):
    """True si ≥ 1 archivo del proyecto está en el índice de git (ronda 2: estar dentro del work tree de un repo padre,
    en una carpeta ignorada o sin `git add`, no es estar bajo control de versiones)."""
    codigo, salida = _git(proyecto, "ls-files", "-z", "--", ".")
    return codigo == 0 and bool((salida or "").strip("\0").strip())


def _con_contenido(ruta):
    """True si el archivo (o, si es carpeta, alguno de sus archivos) tiene texto que no es solo espacios."""
    ruta = Path(ruta)
    if ruta.is_dir():
        return any(_con_contenido(p) for p in sorted(ruta.rglob("*")) if p.is_file() and not p.is_symlink())
    return bool((comun.leer(ruta) or "").strip())


def _existe(proyecto, rel):
    return (Path(proyecto) / rel).exists()


def _package_json(proyecto):
    p = Path(proyecto) / "package.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except (OSError, json.JSONDecodeError):
        return {}


def _deps_declaradas(proyecto, pkg):
    nombres = set()
    if isinstance(pkg, dict):
        for s in ("dependencies", "devDependencies", "optionalDependencies"):
            if isinstance(pkg.get(s), dict):
                nombres.update(pkg[s])
    for nombre in ("requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile"):
        texto = comun.leer(Path(proyecto) / nombre) if _existe(proyecto, nombre) else None
        if texto:
            nombres.update(m.group(1) for m in re.finditer(r"^\s*['\"]?([A-Za-z0-9][A-Za-z0-9._-]*)", texto, re.M))
    return nombres


def _ignorado_por_gitignore(proyecto, rel):
    """Sin repo git: interpretación simple del .gitignore de la raíz."""
    texto = comun.leer(Path(proyecto) / ".gitignore") or ""
    ignorado = False
    for linea in texto.splitlines():
        l = linea.strip()
        if not l or l.startswith("#"):
            continue
        neg = l.startswith("!")
        patron = l[1:] if neg else l
        patron = patron.lstrip("/").rstrip("/")
        if fnmatch.fnmatch(rel, patron) or fnmatch.fnmatch(Path(rel).name, patron):
            ignorado = not neg
    return ignorado


# Ronda 3 (h_env): secretos privados en .env* (no ejemplos). gitleaks no reconoce contraseñas de nombre genérico ni
# JWT de Supabase con role service_role; sin esto SEG-SECRETO-REPO pasaba con DB_PASSWORD=… en el working tree.
VALORES_DE_RELLENO = re.compile(
    r"^(change[_-]?me|changeit|secret|password|passwd|contrase(ñ|n)a|postgres|admin|root|test|example|ejemplo|"
    r"dummy|placeholder|xxx+|\*+|todo|none|null|undefined|localhost|default|demo)$|your[_-]|tu[_-]|<.*>|\{\{", re.I)
RE_URL_CON_CLAVE = re.compile(r"^[a-z][a-z0-9+.-]*://[^:/@\s]+:([^@\s]+)@", re.I)


def _env_local_ignorado(proyecto, rel, en_repo):
    """Ronda 6 (DECISIONES.md #12, integración): True solo si el .env está en un repo git, NO está versionado, git lo
    ignora (check-ignore) y nunca tuvo historial (git log --all vacío). Ante cualquier fallo de git → False
    (fail-closed: el hallazgo sigue siendo secreto_en_env y cuenta para SEG-SECRETO-REPO)."""
    if not en_repo:
        return False
    cod, _ = _git(proyecto, "ls-files", "--error-unmatch", "--", rel)
    if cod != 1:  # 0 = versionado; None = git no corrió
        return False
    cod, _ = _git(proyecto, "check-ignore", "-q", "--", rel)
    if cod != 0:
        return False
    cod, salida = _git(proyecto, "log", "--all", "--format=%H", "-n", "1", "--", rel)
    return cod == 0 and not (salida or "").strip()


def _secretos_en_env(proyecto, envs, falta, en_repo=False):
    """Hallazgo secreto_en_env (→ SEG-SECRETO-REPO) por cada variable de un .env* real con forma de credencial
    privada (sk_live_, JWT service_role…) o con nombre sensible (PASSWORD, SECRET, TOKEN, SERVICE_ROLE…) y un valor
    que no es de relleno. Nunca se copia el valor.
    Ronda 6 (DECISIONES.md #12): si el .env está ignorado por git y nunca se versionó, la subregla es
    secreto_en_env_local (severidad baja → SEG-SECRETO-LOCAL): sigue visible, no pide rotar ni limpiar historial y no
    bloquea, con el mismo criterio que gitleaks (secreto-local-ignorado)."""
    for p in envs:
        texto = comun.leer(p)
        if texto is None:
            continue
        local = _env_local_ignorado(proyecto, comun.rel(proyecto, p), en_repo)
        for n, linea in enumerate(texto.splitlines(), 1):
            if linea.lstrip().startswith("#"):
                continue
            m = env_publicas.RE_ENV_LINEA.match(linea)
            if not m:
                continue
            var, valor = m.group(1), env_publicas._limpiar_valor(m.group(2))
            if (not valor or valor.lower() in env_publicas.MARCADORES_VACIO or comun.es_referencia_variable(valor)
                    or VALORES_DE_RELLENO.search(valor)):
                continue
            tipo = comun.tipo_secreto(valor)
            url = RE_URL_CON_CLAVE.match(valor)
            if url and VALORES_DE_RELLENO.search(url.group(1)):
                url = None
            sensible = env_publicas.nombre_sensible(var) and len(valor) >= 8 and not valor.startswith(
                ("http://", "https://")) or bool(url)
            if not (tipo or sensible):
                continue
            critica = bool(tipo) or bool(re.search(r"SERVICE_?ROLE|PRIVATE", var, re.I))
            if local:
                falta("secreto_en_env_local", f"{comun.rel(proyecto, p)} guarda {var} con un valor que parece una "
                      "credencial privada" + (f" ({tipo})" if tipo else "") + ": secreto local no versionado (ignorado "
                      "por git y sin historial): no hace falta rotar ni git filter-repo; no lo versione ni lo copie "
                      "al build.", "baja", comun.rel(proyecto, p), n, f"{var}=<valor oculto, {len(valor)} caracteres>")
                continue
            falta("secreto_en_env", f"{comun.rel(proyecto, p)} guarda {var} con un valor que parece una credencial privada"
                  + (f" ({tipo})" if tipo else "") + ": si el archivo se versiona, se comparte o se copia al build, "
                  "queda expuesta. Moverla a un gestor de secretos o a las variables del hosting y rotarla si ya "
                  "salió del equipo.", "critica" if critica else "alta", comun.rel(proyecto, p), n,
                  f"{var}=<valor oculto, {len(valor)} caracteres>")


EXT_MIGRACION = {".sql", ".js", ".ts", ".mjs", ".cjs", ".py", ".rb", ".go", ".php", ".java", ".kt", ".cs", ".exs"}


def _migraciones_reales(carpeta):
    """True si hay ≥ 1 migración real (código o SQL no vacío), no solo .gitkeep, README o migration_lock.toml."""
    for p in sorted(carpeta.rglob("*")):
        if len(p.relative_to(carpeta).parts) > 3 or not p.is_file() or p.is_symlink():
            continue
        if p.suffix.lower() == ".sql":
            # Ronda 4 (PV-R3-13): un .sql con solo comentarios (`-- TODO`) no es una migración.
            if _sql_sin_comentarios(comun.leer(p) or "").strip():
                return True
        elif p.suffix.lower() in EXT_MIGRACION and _con_contenido(p):
            return True
    return False


def _sql_sin_comentarios(texto):
    return re.sub(r"--[^\n]*", "", re.sub(r"/\*.*?\*/", "", texto, flags=re.S))


# Hosts de registro permitidos (los alias npm/yarn de lockfile-lint, más PyPI). Un host desconocido (registro privado,
# git, tarball de GitHub) no se reporta como defecto, pero impide el pase lockfile_hosts (no se puede verificar).
HOSTS_PERMITIDOS = {"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org"}
RE_URL_LOCK = re.compile(
    r"""(?:"resolved"\s*:\s*"|\bresolved\s+"|\btarball:\s*|\bregistry\s*=\s*"|\burl\s*=\s*"|"url"\s*:\s*")"""
    r"""(https?)://([^/"'\s:]+)""")
RE_REGISTRO_CONFIG = re.compile(r"""^\s*(?:@[\w-]+:)?registry\s*=\s*(https?)://([^/"'\s:]+)""", re.M)
RE_INSTALACION_REPRODUCIBLE = re.compile(
    r"\bnpm\s+(ci|clean-install|install-clean)\b|\bpnpm\s+(i|install)\b|"
    r"\b(yarn|bun|pnpm)\b[^;&|]*--(frozen-lockfile|immutable)\b|\bbun\s+ci\b|"
    r"\buv\s+sync\b[^;&|]*--(locked|frozen)\b|\bpoetry\s+(install|sync)\b|\bpipenv\s+(install\b[^;&|]*--deploy|sync)\b|"
    r"\bpdm\s+(sync|install\b[^;&|]*--frozen-lockfile)\b|\bpip3?\s+install\b[^;&|]*-r\s+\S*\.lock\b")


GESTORES_INSTALACION = frozenset({"npm", "pnpm", "yarn", "bun", "uv", "poetry", "pipenv", "pdm", "pip", "pip3",
                                  "python", "python3", "corepack"})


def es_instalacion_reproducible(toks):
    """True si el comando simple (tokens) ES una instalación desde el lockfile (npm ci, --frozen-lockfile…), no un
    echo/printf que la menciona (ronda 3, PV-R2-04)."""
    toks = workflows._sin_prefijos(list(toks))
    return bool(toks) and toks[0] in GESTORES_INSTALACION and bool(RE_INSTALACION_REPRODUCIBLE.search(" ".join(toks)))


def _lockfile_valido(nombre, texto):
    """(valido, invalido_json): estructura mínima del lockfile. invalido_json = JSON que no se puede leer."""
    if nombre in ("package-lock.json", "npm-shrinkwrap.json", "Pipfile.lock"):
        try:
            d = json.loads(texto)
        except json.JSONDecodeError:
            return False, True
        if not isinstance(d, dict):
            return False, False
        if nombre == "Pipfile.lock":
            return isinstance(d.get("_meta"), dict) and ("default" in d or "develop" in d), False
        return isinstance(d.get("lockfileVersion"), int) and isinstance(
            d.get("packages") or d.get("dependencies"), dict), False
    if nombre == "yarn.lock":
        return bool(re.search(r"^\s+(version|resolution)\b", texto, re.M)), False
    if nombre == "pnpm-lock.yaml":
        return bool(re.search(r"^lockfileVersion\s*:", texto, re.M)), False
    if nombre == "bun.lock":
        return '"lockfileVersion"' in texto, False
    if nombre in ("uv.lock", "poetry.lock", "pdm.lock"):
        return bool(re.search(r"^\[\[package\]\]|^\[metadata\]|^version\s*=", texto, re.M)), False
    if nombre == "requirements.lock":
        return bool(re.search(r"^\s*[A-Za-z0-9][\w.-]*\s*==", texto, re.M)), False
    return False, False  # bun.lockb (binario) u otro: no verificable en estático


def _paquetes_fijados(nombre, texto):
    """Nombres de paquetes que el lockfile fija (ronda 3, PV-R2-05): un lockfile con solo la raíz o solo la línea
    lockfileVersion no fija nada. None si el formato no se puede leer en estático."""
    if nombre in ("package-lock.json", "npm-shrinkwrap.json"):
        try:
            d = json.loads(texto)
        except json.JSONDecodeError:
            return set()
        fijados = set()
        for clave, info in ((d.get("packages") or {}) if isinstance(d, dict) else {}).items():
            if clave and isinstance(info, dict) and "node_modules/" in clave:
                fijados.add(clave.rsplit("node_modules/", 1)[1])
        for clave, info in ((d.get("dependencies") or {}) if isinstance(d, dict) else {}).items():
            if isinstance(info, dict) and info.get("version"):
                fijados.add(clave)
        return fijados
    if nombre == "Pipfile.lock":
        try:
            d = json.loads(texto)
        except json.JSONDecodeError:
            return set()
        return {k for s in ("default", "develop") for k in ((d.get(s) or {}) if isinstance(d, dict) else {})}
    if nombre == "yarn.lock":
        return {m.group(1) for m in re.finditer(r'^"?(@?[^@\s"]+)@', texto, re.M)}
    if nombre == "pnpm-lock.yaml":
        return {m.group(1) for m in re.finditer(r"^\s{2,}['\"]?/?(@?[^@\s:'\"/][^@\s:'\"]*)(?:@|['\"]?:)", texto, re.M)
                if m.group(1) not in ("dependencies", "devDependencies", "optionalDependencies", "specifier",
                                      "version", "resolution", "engines", "cpu", "os", "importers", "packages",
                                      "snapshots", "settings", "lockfileVersion")}
    if nombre == "bun.lock":
        return set(re.findall(r'^\s+"(@?[^"@]+)":\s*\[', texto, re.M))
    if nombre in ("uv.lock", "poetry.lock", "pdm.lock"):
        return set(re.findall(r'^name\s*=\s*"([^"]+)"', texto, re.M))
    if nombre == "requirements.lock":
        return set(re.findall(r"^\s*([A-Za-z0-9][\w.-]*)\s*==", texto, re.M))
    return None


def _deps_directas_npm(pkg):
    nombres = set()
    if isinstance(pkg, dict):
        for s in ("dependencies", "devDependencies", "optionalDependencies"):
            if isinstance(pkg.get(s), dict):
                for k, v in pkg[s].items():
                    if not str(v).startswith(("file:", "link:", "workspace:", "portal:")):
                        nombres.add(k)
    return nombres


# Lockfiles que guardan la URL de descarga de cada paquete: sin ninguna URL no hay hosts que verificar.
LOCKFILES_CON_URL = ("package-lock.json", "npm-shrinkwrap.json")


def python_sin_deps_runtime(proyecto):
    """Ronda 6 (stack): motivo (texto) si el proyecto Python declara en pyproject.toml una lista de dependencias de
    runtime VACÍA ([project] dependencies = [] y sin dependencias de Poetry fuera de python), sin requirements*.txt /
    Pipfile / setup.py con dependencias; None en cualquier otro caso (incluida la duda: pyproject ilegible, campo
    `dynamic` con dependencies, setup.py presente). Las optional-dependencies (dev, test) no son de runtime."""
    import tomllib
    proyecto = Path(proyecto)
    try:
        datos = tomllib.loads(comun.leer(proyecto / "pyproject.toml") or "")
    except (tomllib.TOMLDecodeError, ValueError):
        return None
    proy = datos.get("project") if isinstance(datos.get("project"), dict) else None
    poetry = ((datos.get("tool") or {}).get("poetry") or {}) if isinstance(datos.get("tool"), dict) else {}
    if proy is None and not poetry:
        return None
    if proy is not None:
        if "dependencies" in (proy.get("dynamic") or []) or not isinstance(proy.get("dependencies", []), list):
            return None
        if proy.get("dependencies"):
            return None
    if isinstance(poetry, dict) and any(k.lower() != "python" for k in (poetry.get("dependencies") or {})):
        return None
    for nombre in ("setup.py", "setup.cfg", "Pipfile"):
        if _existe(proyecto, nombre):
            return None
    for req in sorted(proyecto.glob("requirements*.txt")) + sorted(proyecto.glob("requirements*.in")):
        if re.search(r"(?i)dev|test|lint|doc", req.name):
            continue
        if any(l.strip() and not l.strip().startswith("#") for l in (comun.leer(req) or "").splitlines()):
            return None
    return ("pyproject.toml declara una lista vacía de dependencias de runtime ([project] dependencies = []) y no hay "
            "requirements/Pipfile/setup.py con dependencias: no hay versiones que fijar en un lockfile (las "
            "optional-dependencies de desarrollo no se instalan con el paquete)")


def _revisar_lockfiles(proyecto, locks, en_repo, versionados, ok, falta, pkg=None):
    """SEG-LOCKFILE (ronda 2). Pases: lockfile (presente y no vacío), lockfile_valido, lockfile_versionado,
    lockfile_ci y lockfile_hosts; el catálogo exige los cuatro últimos (pases_requeridos).
    Ronda 3 (PV-R2-05): lockfile_valido exige que fije ≥ 1 paquete si el proyecto declara dependencias, y todas las
    directas de package.json (si no fija ninguna → hallazgo lockfile_incompleto; si faltan algunas → sin pase y
    sin hallazgo, con la lista en el resultado: `lockfile_desincronizado`); lockfile_hosts exige ≥ 1 paquete fijado y, en
    package-lock / npm-shrinkwrap, ≥ 1 URL resuelta (sin nada resuelto no hay hosts verificados).
    Ronda 3 (PV-R2-04): lockfile_ci usa el análisis por comandos de workflows (un `npm ci` dentro de un echo, tras
    `true ||`, después de `exit 0` o enmascarado con `|| npm install` no cuenta)."""
    estados = {"valido": True, "versionado": True, "hosts": True}
    directas = _deps_directas_npm(pkg)
    desincronizados = []
    presentes = []
    for nombre in locks:
        crudo = (proyecto / nombre).read_bytes() if nombre.endswith(".lockb") else None
        texto = comun.leer(proyecto / nombre) if crudo is None else ""
        if (crudo is not None and not crudo.strip()) or (crudo is None and not (texto or "").strip()):
            falta("lockfile_vacio", f"El lockfile {nombre} está vacío: no fija ninguna versión y la instalación no es "
                  "reproducible.", "alta", nombre)
            estados = {k: False for k in estados}
            continue
        presentes.append(nombre)
        valido, invalido = _lockfile_valido(nombre, texto or "")
        if invalido:
            falta("lockfile_invalido", f"El lockfile {nombre} no es JSON válido: el gestor de paquetes no puede usarlo.",
                  "alta", nombre)
        fijados = _paquetes_fijados(nombre, texto or "")
        if valido and fijados is not None and nombre in LOCKFILES_NODE:
            faltan = sorted(d for d in directas if d not in fijados)
            if directas and not fijados:
                falta("lockfile_incompleto", f"El lockfile {nombre} no fija ningún paquete aunque package.json declara "
                      f"{len(directas)} dependencia(s): en la práctica es un lockfile vacío y la instalación no es "
                      "reproducible.", "alta", nombre)
                valido = False
            elif faltan:
                # Desincronización parcial: sin pase lockfile_valido (no se demuestra la reproducibilidad), pero sin
                # hallazgo (decisión pendiente del investigador: en la app sembrada L56 declara limpio este lockfile).
                desincronizados.append(f"{nombre}: {', '.join(faltan[:8])}{' …' if len(faltan) > 8 else ''}")
                valido = False
        if not fijados:
            estados["hosts"] = False  # nada fijado: no hay hosts que verificar (ronda 3)
        estados["valido"] = estados["valido"] and valido
        if versionados:
            cod, _ = _git(proyecto, "ls-files", "--error-unmatch", "--", nombre)
            if cod != 0:
                estados["versionado"] = False
                cod_ign, _ = _git(proyecto, "check-ignore", "-q", "--", nombre)
                if cod_ign == 0:
                    falta("lockfile_ignorado", f"{nombre} está en .gitignore: el lockfile no se versiona y cada "
                          "instalación (también la de CI) resuelve versiones distintas.", "alta", nombre)
        else:
            estados["versionado"] = False
        hosts = [(m.group(1), m.group(2).lower()) for m in RE_URL_LOCK.finditer(texto or "")]
        for cfg in (".npmrc", ".yarnrc", ".yarnrc.yml"):
            hosts += [(m.group(1), m.group(2).lower()) for m in RE_REGISTRO_CONFIG.finditer(
                comun.leer(proyecto / cfg) or "")] if _existe(proyecto, cfg) else []
        inseguros = sorted({h for esquema, h in hosts if esquema == "http"})
        if inseguros:
            falta("lockfile_host_no_permitido", f"{nombre} descarga paquetes por http (sin TLS): "
                  f"{', '.join(inseguros[:5])}. Un intermediario puede cambiar el paquete.", "alta", nombre)
        if crudo is not None or inseguros or any(h not in HOSTS_PERMITIDOS for _, h in hosts):
            estados["hosts"] = False
        if nombre in LOCKFILES_CON_URL and not any(True for _ in RE_URL_LOCK.finditer(texto or "")):
            estados["hosts"] = False  # ronda 3: ninguna URL resuelta, ningún host verificado
    if not presentes:
        return desincronizados
    ok("lockfile", f"Lockfile presente ({', '.join(presentes)}).", presentes[0])
    if estados["valido"]:
        ok("lockfile_valido", f"Lockfile con estructura válida ({', '.join(presentes)}).", presentes[0])
    if estados["versionado"]:
        ok("lockfile_versionado", "El lockfile está versionado en git.", presentes[0])
    if estados["hosts"]:
        ok("lockfile_hosts", "El lockfile solo resuelve paquetes por https desde registros permitidos "
           f"({', '.join(sorted(HOSTS_PERMITIDOS))}).", presentes[0])
    reproducible, con_frozen, _ = workflows.evaluar_ci(proyecto, es_instalacion_reproducible)
    if reproducible is True:
        ok("lockfile_ci", f"El CI instala desde el lockfile de forma reproducible ({con_frozen[0]}:{con_frozen[1]}).",
           con_frozen[0])
    return desincronizados


SUFIJOS_EJEMPLO_ENV = (".example", ".sample", ".template", ".dist", ".defaults", ".schema")
RE_VAR_EJEMPLO = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", re.M)
RE_VAR_LEIDA = re.compile(
    r"\bprocess\.env\.([A-Z_][A-Z0-9_]*)|\bprocess\.env\[\s*['\"]([A-Z_][A-Z0-9_]*)['\"]\s*\]|"
    r"\bimport\.meta\.env\.([A-Z_][A-Z0-9_]*)|\bos\.environ\[\s*['\"]([A-Z_][A-Z0-9_]*)['\"]\s*\]|"
    r"\bos\.(?:environ\.get|getenv)\(\s*['\"]([A-Z_][A-Z0-9_]*)['\"]|\bDeno\.env\.get\(\s*['\"]([A-Z_][A-Z0-9_]*)['\"]")
# Variables que pone el entorno de ejecución, el sistema operativo o el bundler (no se configuran a mano).
# Ronda 6 (stack): constantes integradas de Vite (import.meta.env.PROD/DEV/MODE/BASE_URL/SSR), NODE_ENV y variables del
# sistema que lee una CLI (XDG_*, EDITOR, LANG/LC_*, TERM…) no son variables que el proyecto deba documentar.
VARS_DEL_ENTORNO = frozenset({
    "NODE_ENV", "MODE", "DEV", "PROD", "SSR", "BASE_URL", "CI", "HOME", "PATH", "PWD", "OLDPWD",
    "VERCEL", "VERCEL_ENV", "VERCEL_URL", "NETLIFY", "TZ", "LANG", "LANGUAGE", "LC_ALL", "LC_MESSAGES", "LC_CTYPE",
    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "EDITOR", "VISUAL",
    "PAGER", "SHELL", "USER", "USERNAME", "LOGNAME", "TERM", "COLORTERM", "TMPDIR", "TEMP", "TMP", "NO_COLOR",
    "FORCE_COLOR", "COLUMNS", "LINES", "HOSTNAME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PYTHONPATH",
    "PYTHONHASHSEED", "VIRTUAL_ENV", "GITHUB_ACTIONS", "GITHUB_WORKSPACE", "RUNNER_OS", "SYSTEMROOT", "COMSPEC"})
# Lecturas de entorno que NO son por nombre literal (process.env[clave], os.environ.get(var), os.environ completo).
RE_ENV_DINAMICO = re.compile(
    r"\bprocess\.env\s*\[\s*(?!['\"])|\bos\.(?:environ\.get|getenv)\(\s*(?!['\"])|\bos\.environ\s*\[\s*(?!['\"])|"
    r"\bimport\.meta\.env\s*\[\s*(?!['\"])|\bDeno\.env\.get\(\s*(?!['\"])")
# Carga de un .env o de configuración por entorno (dotenv, pydantic-settings, environs, decouple, envalid, t3-env…).
RE_CARGA_ENV = re.compile(
    r"\bdotenv\b|load_dotenv|\bpydantic_settings\b|\bBaseSettings\b|\benvirons\b|\bdecouple\b|\benvalid\b|"
    r"@t3-oss/env|\bdjango-environ\b|\bimport\s+environ\b|['\"]\$env/(?:static|dynamic)/")
# Desestructuración: const { API_KEY, DB_URL: url } = process.env  /  import.meta.env
RE_ENV_DESESTRUCTURADO = re.compile(r"\{([^{}]{1,500})\}\s*=\s*(?:process\.env|import\.meta\.env)\b")


def _es_env_real(nombre):
    return nombre == ".env" or (nombre.startswith(".env.") and not nombre.endswith(SUFIJOS_EJEMPLO_ENV))


def _variables_ejemplo(ruta):
    return set(RE_VAR_EJEMPLO.findall(comun.leer(ruta) or ""))


def _variables_leidas(textos):
    """Nombres de variables de entorno que el código lee por nombre literal (process.env.X, os.getenv('X')…)."""
    salida = set()
    for t in textos.values():
        for m in RE_VAR_LEIDA.finditer(t):
            salida.add(next(g for g in m.groups() if g))
        for m in RE_ENV_DESESTRUCTURADO.finditer(t):
            salida.update(x for x in re.findall(r"(?:^|,)\s*([A-Z_][A-Z0-9_]*)\b", m.group(1)))
    return salida - VARS_DEL_ENTORNO


def uso_de_entorno(textos, hay_env_real):
    """(usa_env, motivo, dinamicos). Ronda 6 (stack): exigir .env.example solo si el proyecto lee variables propias
    por nombre (no las del sistema ni las constantes del bundler), carga un .env (dotenv y similares) o tiene un .env
    real. El código de tests y fixtures no cuenta (sus variables son perillas de la prueba). Las lecturas dinámicas
    (process.env[clave]) no se pueden atribuir: no encienden la exigencia, pero se devuelven para que el resultado
    las muestre (sin hallazgo ni pase: el control queda sin pase explícito, fail-closed)."""
    propios = {r: t for r, t in textos.items() if not comun.es_test_o_fixture(r)}
    leidas = _variables_leidas(propios)
    carga = sorted(r for r, t in propios.items() if RE_CARGA_ENV.search(t))
    dinamicos = sorted(r for r, t in propios.items() if RE_ENV_DINAMICO.search(t))
    if hay_env_real:
        return True, "hay archivos .env reales", dinamicos
    if leidas:
        return True, f"el código lee {len(leidas)} variable(s) propia(s) por nombre", dinamicos
    if carga:
        return True, f"el código carga configuración de entorno ({carga[0]})", dinamicos
    return False, ("el código no lee variables de entorno propias por nombre (solo del sistema o constantes del "
                   "bundler, p. ej. import.meta.env.PROD o XDG_CONFIG_HOME), no carga un .env y no hay .env reales"
                   ), dinamicos


def analizar(proyecto):
    proyecto = Path(proyecto)
    H, P = [], []

    def falta(sub, mensaje, sev, archivo=None, linea=None, evid=""):
        H.append(comun.hallazgo(NOMBRE, sub, archivo, linea, mensaje, evid, sev))

    def ok(sub, mensaje, archivo=None):
        P.append(comun.pase(NOMBRE, sub, mensaje, archivo))

    pkg = _package_json(proyecto)
    deps = _deps_declaradas(proyecto, pkg)
    codigo = [p for p in comun.recorrer(proyecto, extensiones=EXT_CODIGO)]
    textos = {}
    for p in codigo:
        t = comun.leer(p)
        if t is not None:
            textos[comun.rel(proyecto, p)] = t
    en_repo = _en_repo(proyecto)
    notas_env = {}

    # --- README con instrucciones de arranque ---
    # Ronda 6 (stack): se miran TODOS los README* de la raíz (README.md, README.es.md…); basta uno con arranque.
    readmes = [p for p in sorted(proyecto.iterdir()) if p.is_file() and p.name.lower().startswith("readme")]
    con_arranque = next((p for p in sorted(readmes, key=lambda x: (x.name.lower() not in ("readme.md", "readme"),
                                                                   x.name.lower()))
                         if hay_arranque(comun.leer(p))), None)
    readme = con_arranque or (readmes[0] if readmes else None)
    if readme is None:
        falta("readme_ausente", "No hay README: nadie (ni otra IA) sabe cómo instalar y arrancar el proyecto.", "alta")
    elif con_arranque is None:
        falta("readme_sin_arranque", "El README no tiene instrucciones de instalación ni de arranque (ningún comando "
              "como 'npm install', 'pip install', 'pipx install', 'uv sync', 'make', 'cargo run' o 'docker compose "
              "up').", "alta", readme.name)
    else:
        ok("readme", "README con comandos de instalación/arranque.", readme.name)
        ok("doc_agente_readme", "README de arranque presente (parte de COD-DOC-AGENTE).", readme.name)

    # --- repositorio git ---
    versionados = en_repo and _hay_versionados(proyecto)
    if versionados:
        ok("git", "El proyecto está bajo control de versiones (git).")
    elif en_repo:
        falta("git_sin_versionar", "El proyecto está dentro de un repositorio git, pero ninguno de sus archivos está "
              "versionado (carpeta ignorada por el repo padre o sin `git add`): no hay historial propio ni forma de "
              "volver atrás.", "alta")
    else:
        falta("git_sin_repo", "El proyecto no es un repositorio git: no hay historial ni forma de volver atrás.", "alta")

    # --- .env.example y .env fuera de git ---
    envs = [p for p in comun.recorrer(proyecto) if _es_env_real(p.name)]
    usa_env, motivo_env, env_dinamicos = uso_de_entorno(textos, bool(envs) or _existe(proyecto, ".env"))
    ejemplo = next((e for e in EJEMPLOS_ENV if _existe(proyecto, e)), None)
    if ejemplo:
        # Ronda 4 (PV-R3-06): el pase exige que el ejemplo declare variables y, al menos, las que el código lee por
        # nombre literal. Un ejemplo vacío o incompleto no da pase (tampoco hallazgo: puede ser deuda menor).
        declaradas = _variables_ejemplo(proyecto / ejemplo)
        leidas = _variables_leidas(textos)
        faltan = sorted(leidas - declaradas)
        if declaradas and not faltan:
            ok("env_ejemplo", f"Existe {ejemplo} con las variables necesarias ({len(declaradas)} declaradas; "
               f"{len(leidas)} leídas por el código, todas declaradas).", ejemplo)
    elif usa_env:
        falta("env_ejemplo_ausente", f"El proyecto usa variables de entorno ({motivo_env}) pero no hay .env.example: "
              "quien lo clone no sabe qué configurar y tiende a copiar el .env real.", "media")
    else:
        # Sin hallazgo ni pase: SEG-ENV-EJEMPLO queda sin pase explícito (no_evaluado), con el motivo visible aquí.
        notas_env["env_ejemplo_no_requerido"] = motivo_env + (
            f"; lecturas dinámicas sin nombre literal en: {', '.join(env_dinamicos[:5])}" if env_dinamicos else "")
    # Ronda 4 (PV-R3-05): los .env* reales de CUALQUIER carpeta (monorepos: packages/api/.env, backend/.env), no solo
    # los de la raíz; sin dependencias ni carpetas de build (comun.recorrer).
    problema_env = False
    for p in envs:
        rel = comun.rel(proyecto, p)
        if en_repo:
            cod, _ = _git(proyecto, "ls-files", "--error-unmatch", "--", rel)
            if cod == 0:
                falta("env_comiteado", f"{rel} está versionado en git: sus secretos quedan en el historial "
                      "aunque se borre después. Sacarlo del repo, agregarlo a .gitignore y rotar las claves.",
                      "critica", rel, None, rel)
                problema_env = True
                continue
            cod, _ = _git(proyecto, "check-ignore", "-q", "--", rel)
            ignorado = cod == 0
        else:
            ignorado = _ignorado_por_gitignore(proyecto, rel)
        if not ignorado:
            falta("env_no_ignorado", f"{rel} no está en .gitignore: el próximo commit lo subirá con sus secretos.",
                  "alta", rel, None, rel)
            problema_env = True
    if envs and not problema_env:
        ok("env_ignorado", "Los archivos .env están fuera de git.")
    _secretos_en_env(proyecto, envs, falta, en_repo)

    # --- lockfile (ronda 2: contenido, versionado, instalación reproducible en CI y hosts) ---
    necesita_lock = pkg is not None or _existe(proyecto, "pyproject.toml")
    locks = [l for l in LOCKFILES_NODE + LOCKFILES_PY if _existe(proyecto, l) and (proyecto / l).is_file()]
    desincronizados = []
    lock_no_requerido = None
    if locks:
        desincronizados = _revisar_lockfiles(proyecto, locks, en_repo, versionados, ok, falta, pkg) or []
    elif necesita_lock:
        lock_no_requerido = None if pkg is not None else python_sin_deps_runtime(proyecto)
        if lock_no_requerido:
            # Ronda 6 (stack): librería/CLI Python sin dependencias de runtime → nada que fijar. Sin hallazgo ni pase
            # (SEG-LOCKFILE queda sin pase explícito); el motivo queda en el resultado.
            notas_env["lockfile_no_requerido"] = lock_no_requerido
        else:
            falta("lockfile_ausente", "No hay lockfile: cada instalación puede traer versiones distintas "
                  "(y comprometidas) de las dependencias.", "alta")

    # --- CI ---
    ci = next((c for c in CI if _existe(proyecto, c)), None)
    if ci and ci == ".github/workflows" and not any((proyecto / ci).glob("*.y*ml")):
        ci = None
    if ci == ".github/workflows":
        calidad, leidos = workflows.calidad_ci(proyecto)
        if calidad:
            ok("ci", f"El CI ejecuta lint, typecheck o tests ({', '.join(leidos[:3])}).", ci)
        # sin calidad: el hallazgo ci_sin_calidad lo emite el check workflows (corre siempre)
    elif ci:
        pass  # CI de otra plataforma: sin verificación semántica no hay pase (fail-closed)
    else:
        falta("ci_ausente", "No hay integración continua: nada verifica lint, tipos ni tests antes de publicar.", "media")

    # --- tests ---
    script_test = ""
    if isinstance(pkg, dict) and isinstance(pkg.get("scripts"), dict):
        script_test = str(pkg["scripts"].get("test", ""))
    script_valido = bool(script_test) and "no test specified" not in script_test
    hay_tests = any(re.search(r"(\.(test|spec)\.[cm]?[jt]sx?$|(^|/)test_[^/]+\.py$|_test\.(py|go)$|(^|/)__tests__/)", r)
                    for r in textos)
    if hay_tests or script_valido:
        ok("tests", "Hay tests automatizados." if hay_tests else f"Script de test: {script_test[:80]}")
    else:
        falta("tests_ausentes", "No hay tests ni script 'test': ningún flujo crítico está verificado automáticamente.",
              "media", "package.json" if pkg is not None else None)

    # --- health (solo si hay servidor) ---
    servidor = [r for r, t in textos.items() if RE_SERVIDOR.search(t)]
    if servidor or any(DEPS_SERVIDOR.match(d) for d in deps):
        # El pase solo cuenta código del proyecto: una ruta /health escrita en un test o en un fixture (p. ej. el
        # proyecto temporal que arma un test) no demuestra que el servidor la exponga. La detección de `servidor`
        # (que activa la obligación) sí mira todo el árbol, para no perder recall (fail-closed).
        con_health = next((r for r, t in textos.items() if not comun.es_test_o_fixture(r)
                           and (RE_HEALTH.search(t) or RE_RUTA_HEALTH_ARCHIVO.search(r))), None)
        if con_health:
            ok("health", "Existe un endpoint de health check.", con_health)
        else:
            falta("health_ausente", "El servidor no expone /health: el hosting no puede saber si la app está viva "
                  "ni reiniciarla.", "media", servidor[0] if servidor else None)

    # --- migraciones (solo si hay base de datos) ---
    usa_bd = any(DEPS_BD.match(d) for d in deps) or _existe(proyecto, "supabase") or _existe(proyecto, "prisma")
    if usa_bd:
        mig = next((m for m in MIGRACIONES if (proyecto / m).is_dir() and _migraciones_reales(proyecto / m)), None)
        vacia = next((m for m in MIGRACIONES if (proyecto / m).is_dir()), None)
        if mig:
            ok("migraciones", f"Esquema versionado en {mig}/.", mig)
        elif vacia:
            falta("migraciones_ausentes", f"Hay base de datos y existe {vacia}/, pero sin ninguna migración real (solo "
                  "marcadores como .gitkeep, archivos vacíos o README): el esquema no se puede reconstruir.", "alta",
                  vacia)
        else:
            falta("migraciones_ausentes", "Hay base de datos pero no migraciones en el repo: el esquema solo existe "
                  "en producción y no se puede reconstruir ni revisar.", "alta")

    # --- documentación para agentes ---
    docs = [d for d in DOCS_AGENTE if _existe(proyecto, d)]
    doc = next((d for d in docs if _con_contenido(proyecto / d)), None)
    if doc:
        ok("doc_agente", f"Documentación para agentes ({doc}).", doc)
    elif docs:
        falta("doc_agente_vacio", f"{docs[0]} existe pero está vacío: no documenta la arquitectura ni las reglas del "
              "proyecto.", "baja", docs[0])
    else:
        falta("doc_agente_ausente", "No hay CLAUDE.md/AGENTS.md: cada sesión de IA parte sin conocer la arquitectura "
              "ni las reglas del proyecto.", "baja")

    # --- error tracking ---
    if deps or textos:
        tracker = next((d for d in sorted(deps) if ERROR_TRACKING.match(d) and not ERROR_TRACKING_NO_SDK.match(d)),
                       None)
        if tracker:
            ok("error_tracking", f"Error tracking instalado ({tracker}).")
        else:
            falta("error_tracking_ausente", "No hay error tracking (Sentry o similar): los errores de los usuarios "
                  "pasan sin que nadie se entere.", "media")

    res = comun.resultado(H, P)
    if desincronizados:
        res["lockfile_desincronizado"] = desincronizados
    if notas_env:
        # Ronda 6 (stack): obligaciones que no aplican al tipo de proyecto, con su motivo (sin hallazgo ni pase).
        res["no_requerido"] = dict(sorted(notas_env.items()))
    return res


if __name__ == "__main__":
    sys.exit(comun.main_check(NOMBRE, analizar))
