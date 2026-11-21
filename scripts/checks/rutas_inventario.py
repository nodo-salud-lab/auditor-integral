#!/usr/bin/env python3
"""rutas_inventario — inventario ruta → handler → consulta → ¿auth? ¿filtra por usuario dueño? (PLAN_MAESTRO §3.2;
§9 «4a Autorización»; F3). Insumo del digest de autorización (scripts/digest.py) para el revisor-autorizacion.

Reconoce (heurística estática por regex, sin ejecutar nada):
  express      <app|router|server|fastify|…Router|…App>.<get|post|put|patch|delete|all>('/ruta', …)
  next-app     app/**/route.(js|ts) y src/app/**: export (async) function GET|POST|… / export const GET = …
  next-pages   pages/api/**: export default handler; métodos por req.method === 'X' (si no hay, ANY)
  fastapi      @<x>.get|post|put|patch|delete('/ruta') en archivos que importan fastapi
  flask        @<x>.route('/ruta', methods=[…]) (por defecto GET) y @<x>.get(…) en archivos con flask
  supabase     .from('tabla').select|insert|update|delete|upsert(…) con o sin .eq('user_id', …)

Por fila: framework, ruta, metodo, archivo, linea, auth, filtra_por_usuario, tiene_param_id, service_role,
consultas (llamadas a BD dentro del handler), tabla/operacion (supabase), sospechosa y motivos:
  id_sin_pertenencia         ruta con parámetro (:id, [id], {id}, <id>) o consulta por id sin filtro por el dueño
  mutacion_sin_auth          POST/PUT/PATCH/DELETE/ANY sin middleware, decorador ni chequeo de sesión
  mutacion_sin_filtro_dueno  update/delete/upsert de Supabase sin filtro por la columna del dueño
  service_role               el archivo usa la clave service_role (salta RLS)
  admin_sin_rol              ruta o archivo de administración sin chequeo de rol visible (BFLA)
Las señales son heurísticas (ESTIMACIÓN): «auth» y «filtra_por_usuario» se buscan por nombres habituales
(requireAuth, Depends(get_current_user), userId: req.user.id, .eq('user_id', …), auth.uid()…). Una señal ausente
deja la fila sospechosa: el juicio es del revisor-autorizacion (LLM) sobre el digest, no de este script.

Garantías:
- NUNCA da pass por sí mismo: checks_pass siempre vacío (SEG-IDOR y SEG-BFLA son no_demostrable_estatico; sin juicio
  del revisor quedan no_evaluado).
- Ronda 6 (stack): emite DOS hallazgos deterministas (antes marcaba la fila sospechosa y el informe decía «parte
  determinista sin hallazgos»):
    ruta_admin_sin_auth  alta   ruta cuyo nombre (ruta o archivo) indica administración o depuración (admin, debug,
                                internal, interno) sin ninguna señal de auth en el servidor: ni middleware/decorador/
                                chequeo de sesión en el handler, ni middleware de auth global (app.use(auth) /
                                app.use('/admin', auth, …), middleware.(js|ts) de Next con auth, before_request de Flask
                                con chequeo de sesión, APIRouter/FastAPI/include_router con dependencies=[Depends(auth)]).
                                Si se detecta auth global, no hay hallazgo (la fila sigue en el inventario).
    entorno_expuesto     media  una respuesta HTTP devuelve el entorno completo (process.env / os.environ /
                                dict(os.environ)), no una variable concreta.
  Ninguno bloquea por sí mismo; el mapeo a controles lo decide el catálogo.
- Solo lee código fuente: salta node_modules, dist/build, lockfiles, código de tests y rutas CONFIDENCIALES de
  config/confidencial.toml (se cuentan solo por nombre en alcance.codigo_confidencial; su contenido no se lee).
- No copia código: cada fila lleva archivo:línea; los fragmentos los arma digest.py ya enmascarados.
- Sin rutas ni consultas reconocidas → estado no_evaluado (nunca no_aplica: un framework no soportado no es
  evidencia de que no haya endpoints). El motivo distingue (F3-C): «sin backend detectado (SPA)» si no hay
  dependencias de servidor conocidas (package.json, requirements*.txt, pyproject.toml, Pipfile) ni carpetas de
  servidor (server/, api/, pages/api/, app/**/route.*, supabase/functions/, functions/), y «framework no
  reconocido» (con las señales encontradas) en otro caso. Ninguno de los dos es evidencia de ausencia.
Alcance (también en el .meta.json): archivos_fuente, rutas, consultas, sospechosas, codigo_confidencial,
omitidos_tamano, omitidos_tope.

Uso: rutas_inventario.py PROYECTO DIR_CRUDO   → DIR_CRUDO/check_rutas_inventario.json (+ .meta.json)
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402
import datos_confidenciales  # noqa: E402

NOMBRE = "rutas_inventario"
EXT_JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
EXT_PY = {".py"}
MAX_ARCHIVOS = 5000
MAX_LINEAS_HANDLER = 60
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "poetry.lock",
             "Pipfile.lock", "uv.lock", "Cargo.lock", "Gemfile.lock", "composer.lock", "go.sum"}
DIRS_TEST = {"test", "tests", "__tests__", "__mocks__", "spec", "e2e", "cypress", "playwright"}
RE_ARCHIVO_TEST = re.compile(r"\.(test|spec)\.[a-z]+$|^test_.*\.py$|_test\.py$|^conftest\.py$", re.I)

METODOS_MUTACION = {"POST", "PUT", "PATCH", "DELETE", "ALL", "ANY"}
RE_RECEPTOR = re.compile(r"^(app|router|server|routes|r|api|fastify|hono|\w*Router|\w*router|\w*App|\w*app)$")
RECEPTORES_CLIENTE = {"axios", "http", "https", "fetch", "client", "request", "superagent", "ky", "got", "instance",
                      "api_client", "apiClient", "$http", "httpClient", "map", "params", "searchParams", "headers",
                      "cache", "store", "localStorage", "sessionStorage", "formData", "url", "query"}
RE_EXPRESS = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*(['\"`])(/[^'\"`]*)\3")
RE_USE = re.compile(r"\b[A-Za-z_$][\w$]*\s*\.\s*use\s*\(([^)]*)\)")
RE_AUTH_MW = re.compile(
    r"(?i)\b(?:auth\w*|\w*Auth\w*|require\w*(?:auth|user|login|admin|role|session)\w*|is(?:auth\w*|loggedin|admin)\w*|"
    r"ensure\w*(?:auth|login|user)\w*|protect\w*|verify\w*(?:token|jwt|session|user)\w*|passport\.authenticate|"
    r"jwt\w*|clerk\w*|checkJwt|authorize\w*|guard\w*|login_required|jwt_required|roles?_required|"
    r"permission_required|requires_\w+)\b")
RE_AUTH_HANDLER = re.compile(
    r"getServerSession|getSession\s*\(|\bauth\s*\(\s*\)|currentUser\s*\(|getAuth\s*\(|auth\.getUser|"
    r"\breq\.user\b|\brequest\.user\b|\breq\.auth\b|jwt\.verify|verifyToken|verifyIdToken|getToken\s*\(|"
    r"requireAuth|requireUser|isAuthenticated|\bsession\.user\b|\bcurrent_user\b|get_current_user|"
    r"Depends\(\s*\w*(?:auth|user)\w*|auth\.uid\(\)")
RE_FILTRO_DUENO = re.compile(
    r"(?i)\b(?:user_?id|owner_?id|usuario_?id|author_?id|created_?by|profile_?id|tenant_?id|propietario_?id)\b\s*(?:===?|[:=])"
    r"|\.eq\(\s*['\"](?:user_id|owner_id|usuario_id|author_id|created_by|profile_id|tenant_id|propietario_id)['\"]"
    r"|auth\.uid\(\)")
RE_SERVICE_ROLE = re.compile(r"service_role|SERVICE_ROLE|serviceRole")
RE_ADMIN = re.compile(r"(?i)(?:^|[/_.\-])admin")
RE_ROL = re.compile(r"(?i)\b(?:require_?role|has_?role|check_?role|roles?_required|is_?admin|require_?admin|admin_?only|"
                    r"authorize|permission|can\(|ability|rol(?:e|es)?\s*(?:===?|!==?|in\b|\.includes))")
RE_PARAM = re.compile(r":\w+|\[[^\]]+\]|\{[^}]+\}|<[^>]+>")
RE_CONSULTA = re.compile(
    r"\.(?:query|execute|raw|findOne|findUnique|findFirst|findMany|findAll|findById|findByPk|findOneAndUpdate|"
    r"updateOne|updateMany|deleteOne|deleteMany|destroy|create|insert|upsert|filter|filter_by|get|delete|update|"
    r"select)\s*\(|\b(?:SELECT|INSERT|UPDATE|DELETE)\s+")
RE_SUPA_FROM = re.compile(r"\.from\(\s*(['\"`])([\w.\-]+)\1\s*\)")
RE_SUPA_OP = re.compile(r"\.(select|insert|update|delete|upsert)\s*\(")
RE_SUPA_FILTRO = re.compile(r"\.(?:eq|match|in|neq|is)\(\s*['\"`]([\w.]+)['\"`]")
COLUMNAS_DUENO = {"user_id", "owner_id", "usuario_id", "author_id", "created_by", "profile_id", "tenant_id",
                  "propietario_id"}
RE_NEXT_APP = re.compile(r"(?:^|/)app/(.*?)/?route\.(?:js|jsx|ts|tsx|mjs)$")
RE_NEXT_PAGES = re.compile(r"(?:^|/)pages/api/(.+)\.(?:js|jsx|ts|tsx|mjs)$")
RE_NEXT_METODO = re.compile(
    r"^\s*export\s+(?:async\s+function\s+|function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", re.M)
RE_PAGES_METODO = re.compile(r"""(?:req\.method\s*===?\s*|case\s+)['"](GET|POST|PUT|PATCH|DELETE)['"]""")
RE_PY_RUTA = re.compile(r"^\s*@(\w+)\.(get|post|put|patch|delete|route)\(\s*['\"]([^'\"]*)['\"](.*)$")
RE_PY_METHODS = re.compile(r"methods\s*=\s*[\[(]([^\])]*)[\])]")
DEPS_SERVIDOR_JS = {"express", "fastify", "koa", "@koa/router", "koa-router", "hapi", "@hapi/hapi", "restify",
                    "@nestjs/core", "next", "nuxt", "@sveltejs/kit", "@remix-run/node", "@remix-run/server-runtime",
                    "hono", "elysia", "h3", "nitropack", "@trpc/server", "apollo-server", "@apollo/server", "polka",
                    "micro", "sails", "loopback", "@loopback/core", "feathers", "@feathersjs/feathers", "astro",
                    "@supabase/functions-js", "firebase-functions", "@vercel/node", "@netlify/functions",
                    "serverless", "aws-lambda", "@cloudflare/workers-types", "wrangler"}
DEPS_SERVIDOR_PY = {"fastapi", "flask", "django", "starlette", "sanic", "aiohttp", "tornado", "bottle", "pyramid",
                    "quart", "litestar", "falcon", "uvicorn", "gunicorn"}
CARPETAS_SERVIDOR = ("server", "api", "backend", "functions", "supabase/functions", "pages/api", "src/pages/api",
                     "src/server", "src/api", "netlify/functions", "api_server")
RE_ROUTE_ARCHIVO = re.compile(r"(?:^|/)app/(?:.*/)?route\.(?:js|jsx|ts|tsx|mjs)$")
RE_REQ_PY = re.compile(r"^\s*([A-Za-z0-9_.\-]+)", re.M)
# Ronda 6 (stack): nombre de administración o depuración en la ruta o en el archivo.
RE_NOMBRE_SENSIBLE = re.compile(r"(?i)(?:^|[/_.\-])(admin\w*|debug|_debug|__debug__|internal|interno|depuracion)"
                                r"(?=$|[/_.\-\[{:<])")
RE_USE_RECEPTOR = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(\s*(?:(['\"`])([^'\"`]*)\2\s*,)?([^)]*)\)")
RECEPTORES_APP = {"app", "server", "fastify", "api", "hono", "application", "srv"}
RE_MIDDLEWARE_NEXT = re.compile(r"(?:^|/)(?:src/)?middleware\.(?:js|ts|mjs)$")
RE_AUTH_NEXT_MW = re.compile(r"withAuth|clerkMiddleware|authMiddleware|getToken\s*\(|\bauth\s*\(|getSession|"
                             r"supabase\.auth\.getUser|updateSession|NextResponse\.redirect\([^)]*login", re.I)
RE_BEFORE_REQUEST = re.compile(r"^\s*@(\w+)\.before_(?:app_)?request\b", re.M)
RE_AUTH_BEFORE = re.compile(r"current_user|login_required|session\.get\(|session\[|abort\(\s*40[13]|verify_jwt|"
                            r"jwt_required|g\.user|request\.authorization|Unauthorized|Forbidden", re.I)
RE_DEPENDENCIAS_FASTAPI = re.compile(r"(?:APIRouter|FastAPI|include_router)\s*\([^)]*dependencies\s*=\s*\[[^\]]*"
                                     r"Depends\(\s*\w*(?:auth|user|admin|current|token|verify)\w*", re.I | re.S)
# Llamada o decorador de auth/rol en el archivo de la ruta (requireAdmin(req, res), @admin_required, checkSession()…).
RE_AUTH_LLAMADA = re.compile(r"(?i)\b(?:require|ensure|check|verify|assert|get|with)_?\w*(?:auth|user|admin|session|login|"
                             r"role|token)\w*\s*\(|^\s*@\w*(?:login_required|admin_required|roles?_required|jwt_required|"
                             r"requires_auth|auth_required|permission_required)\b", re.M)
RE_ENV_COMPLETO = re.compile(r"\.\.\.\s*process\.env\b|\bprocess\.env(?![\w$.\[?])|\bdict\(\s*os\.environ\s*\)|"
                             r"\bos\.environ\.copy\(\)|\*\*\s*os\.environ\b(?![.\[])|\bos\.environ(?![\w.\[])")
RE_RESPUESTA = re.compile(r"\b(?:res|reply|response|resp|ctx)\s*(?:\.\s*status\s*\([^)]*\))?\s*\.\s*(?:json|send|end|write)\s*\(|"
                          r"\bjsonify\s*\(|\bJSONResponse\s*\(|\bNextResponse\.json\s*\(|\bResponse\.json\s*\(|"
                          r"\bc\.json\s*\(|\bctx\.body\s*=|\bmake_response\s*\(")


def _es_test(rel):
    partes = rel.split("/")
    return any(p.lower() in DIRS_TEST for p in partes[:-1]) or bool(RE_ARCHIVO_TEST.search(partes[-1]))


def _linea(texto, pos):
    return texto.count("\n", 0, pos) + 1


def _consultas(lineas, desde, hasta):
    """Llamadas a BD dentro del handler (líneas 1-based [desde, hasta]); máximo 5, sin copiar código."""
    res = []
    for n in range(desde, min(hasta, len(lineas)) + 1):
        m = RE_CONSULTA.search(lineas[n - 1])
        if m:
            res.append({"linea": n, "llamada": m.group(0).strip(" .(")[:30]})
            if len(res) >= 5:
                break
    return res


def _fila(framework, ruta, metodo, archivo, linea, region, auth_extra=False, handler=None, service_role=False,
          lineas=None, desde=None, hasta=None, args=""):
    auth = bool(auth_extra or RE_AUTH_HANDLER.search(region))
    filtra = bool(RE_FILTRO_DUENO.search(region))
    param = bool(ruta and RE_PARAM.search(ruta))
    motivos = []
    if param and not filtra:
        motivos.append("id_sin_pertenencia")
    if metodo in METODOS_MUTACION and not auth:
        motivos.append("mutacion_sin_auth")
    if service_role:
        motivos.append("service_role")
    if (RE_ADMIN.search(ruta or "") or RE_ADMIN.search(archivo)) and not RE_ROL.search(f"{args}\n{region}"):
        motivos.append("admin_sin_rol")
    return {"framework": framework, "ruta": ruta, "metodo": metodo, "archivo": archivo, "linea": linea,
            "handler": handler, "auth": auth, "filtra_por_usuario": filtra, "tiene_param_id": param,
            "service_role": service_role, "consultas": _consultas(lineas, desde, hasta) if lineas else [],
            "tabla": None, "operacion": None, "sospechosa": bool(motivos), "motivos": sorted(motivos)}


# ------------------------------------------------------------------------------------------------- JS / TS
def _express(rel, texto, lineas, service_role):
    filas = []
    matches = [m for m in RE_EXPRESS.finditer(texto)
               if m.group(1) not in RECEPTORES_CLIENTE and RE_RECEPTOR.match(m.group(1))]
    usos_auth = [m.start() for m in RE_USE.finditer(texto) if RE_AUTH_MW.search(m.group(1))]
    for i, m in enumerate(matches):
        linea = _linea(texto, m.start())
        fin = _linea(texto, matches[i + 1].start()) - 1 if i + 1 < len(matches) else len(lineas)
        fin = max(linea, min(fin, linea + MAX_LINEAS_HANDLER))
        region = "\n".join(lineas[linea - 1:fin])
        resto = texto[m.end():m.end() + 300]
        corte = re.search(r"=>|\bfunction\b|\(\s*req\b|\(\s*request\b|\(\s*c\b\s*\)", resto)
        argumentos = resto[:corte.start()] if corte else resto.split("\n", 1)[0]
        auth_mw = bool(RE_AUTH_MW.search(argumentos)) or any(p < m.start() for p in usos_auth)
        filas.append(_fila("express", m.group(4), m.group(2).upper(), rel, linea, region, auth_mw,
                           service_role=service_role, lineas=lineas, desde=linea, hasta=fin, args=argumentos))
    return filas


def _ruta_next(segmento):
    partes = [p for p in segmento.split("/") if p and not (p.startswith("(") and p.endswith(")")) and not p.startswith("@")]
    return "/" + "/".join(partes)


def _next_app(rel, texto, lineas, service_role):
    m = RE_NEXT_APP.search(rel)
    if not m:
        return []
    ruta = _ruta_next(m.group(1))
    metodos = list(RE_NEXT_METODO.finditer(texto))
    filas = []
    for i, mm in enumerate(metodos):
        linea = _linea(texto, mm.start())
        fin = _linea(texto, metodos[i + 1].start()) - 1 if i + 1 < len(metodos) else len(lineas)
        fin = max(linea, min(fin, linea + MAX_LINEAS_HANDLER))
        region = "\n".join(lineas[linea - 1:fin])
        filas.append(_fila("next-app", ruta, mm.group(1), rel, linea, region, handler=mm.group(1),
                           service_role=service_role, lineas=lineas, desde=linea, hasta=fin))
    return filas


def _next_pages(rel, texto, lineas, service_role):
    m = RE_NEXT_PAGES.search(rel)
    if not m:
        return []
    ruta = "/api/" + m.group(1)
    if ruta.endswith("/index"):
        ruta = ruta[:-len("/index")] or "/api"
    region = "\n".join(lineas[:MAX_LINEAS_HANDLER * 3])
    metodos = sorted({mm.group(1) for mm in RE_PAGES_METODO.finditer(texto)})
    linea_def = _linea(texto, texto.find("export default")) if "export default" in texto else 1
    if not metodos:
        return [_fila("next-pages", ruta, "ANY", rel, linea_def, region, service_role=service_role, lineas=lineas,
                      desde=1, hasta=len(lineas))]
    filas = []
    for met in metodos:
        mm = re.search(rf"""['"]{met}['"]""", texto)
        filas.append(_fila("next-pages", ruta, met, rel, _linea(texto, mm.start()) if mm else linea_def, region,
                           service_role=service_role, lineas=lineas, desde=1, hasta=len(lineas)))
    return filas


def _supabase(rel, texto, service_role):
    filas = []
    for m in RE_SUPA_FROM.finditer(texto):
        cadena = texto[m.end():m.end() + 400]
        corte = re.search(r";|\n\s*\n|\.from\(", cadena)
        if corte:
            cadena = cadena[:corte.start()]
        op = RE_SUPA_OP.search(cadena)
        if not op:
            continue  # Array.from('…'), storage.from('bucket'), etc.
        operacion = op.group(1)
        columnas = [c.group(1) for c in RE_SUPA_FILTRO.finditer(cadena)]
        filtra = any(c.split(".")[-1] in COLUMNAS_DUENO for c in columnas) or "auth.uid()" in cadena
        por_id = any(c == "id" or (c.endswith("_id") and c not in COLUMNAS_DUENO) for c in columnas)
        motivos = []
        if operacion != "insert" and por_id and not filtra:
            motivos.append("id_sin_pertenencia")
        if operacion in ("update", "delete", "upsert") and not filtra:
            motivos.append("mutacion_sin_filtro_dueno")
        if service_role:
            motivos.append("service_role")
        filas.append({"framework": "supabase", "ruta": None, "metodo": None, "archivo": rel,
                      "linea": _linea(texto, m.start()), "handler": None, "auth": None, "filtra_por_usuario": filtra,
                      "tiene_param_id": por_id, "service_role": service_role, "consultas": [],
                      "tabla": m.group(2), "operacion": operacion, "filtros": sorted(set(columnas)),
                      "sospechosa": bool(motivos), "motivos": sorted(motivos)})
    return filas


# ------------------------------------------------------------------------------------------------- Python
def _python(rel, texto, lineas, service_role):
    bajo = texto.lower()
    framework = "fastapi" if "fastapi" in bajo else ("flask" if "flask" in bajo else None)
    if framework is None:
        return []
    filas = []
    n = 0
    while n < len(lineas):
        m = RE_PY_RUTA.match(lineas[n])
        if not m:
            n += 1
            continue
        # bloque de decoradores contiguo (antes y después) y línea del def
        ini = n
        while ini > 0 and lineas[ini - 1].lstrip().startswith("@"):
            ini -= 1
        j = n + 1
        while j < len(lineas) and lineas[j].lstrip().startswith("@"):
            j += 1
        decoradores = "\n".join(lineas[ini:j])
        k = j
        while k < len(lineas) and not lineas[k].rstrip().endswith(":"):  # firma en varias líneas
            k += 1
        firma = "\n".join(lineas[j:k + 1])
        fin = k + 1
        while fin < len(lineas) and fin < k + MAX_LINEAS_HANDLER and (not lineas[fin].strip() or lineas[fin][:1].isspace()):
            fin += 1
        region = "\n".join(lineas[j:fin])
        otros_decoradores = "\n".join(x for x in decoradores.splitlines() if not RE_PY_RUTA.match(x))
        auth = bool(RE_AUTH_MW.search(otros_decoradores) or re.search(r"Depends\(\s*\w*(?:auth|user|current)\w*", firma))
        verbo = m.group(2)
        if verbo == "route":
            mm = RE_PY_METHODS.search(m.group(4))
            metodos = sorted({x.strip().strip("'\"").upper() for x in mm.group(1).split(",") if x.strip()}) if mm else ["GET"]
            fw = "flask"
        else:
            metodos = [verbo.upper()]
            fw = framework
        handler = re.search(r"def\s+(\w+)", firma)
        for met in metodos:
            filas.append(_fila(fw, m.group(3), met, rel, n + 1, region, auth, handler.group(1) if handler else None,
                               service_role=service_role, lineas=lineas, desde=j + 1, hasta=fin,
                               args=decoradores + "\n" + firma))
        n = j
    return filas


# ------------------------------------------------------------------------------------------------- SPA o backend
def senales_backend(proyecto):
    """Señales de que el proyecto tiene backend: dependencias de servidor conocidas y carpetas/archivos de servidor.
    Lista vacía → se trata como SPA sin backend (solo para el motivo; el estado sigue no_evaluado)."""
    proyecto = Path(proyecto)
    conf = datos_confidenciales.cargar()
    senales = set()

    def legible(p):  # nunca se lee un manifiesto dentro de una ruta confidencial
        return not datos_confidenciales.es_confidencial(comun.rel(proyecto, p), conf)
    for p in comun.recorrer(proyecto, nombres={"package.json"}):
        if not legible(p):
            continue
        try:
            datos = json.loads(comun.leer(p) or "{}")
        except ValueError:
            continue
        for clave in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = datos.get(clave) if isinstance(datos, dict) else None
            for d in (deps or {}) if isinstance(deps, dict) else ():
                if d in DEPS_SERVIDOR_JS:
                    senales.add(f"dependencia {d}")
    nombres_py = {"requirements.txt", "requirements-dev.txt", "requirements.in", "pyproject.toml", "Pipfile",
                  "setup.py", "setup.cfg"}
    for p in comun.recorrer(proyecto, nombres=nombres_py):
        if not legible(p):
            continue
        texto = (comun.leer(p) or "").lower()
        for d in DEPS_SERVIDOR_PY:
            if re.search(rf"(?<![\w-]){re.escape(d)}(?![\w-])", texto):
                senales.add(f"dependencia {d}")
    for c in CARPETAS_SERVIDOR:
        q = proyecto / c
        if q.is_dir() and not q.is_symlink():
            senales.add(f"carpeta {c}/")
    for p in comun.recorrer(proyecto, extensiones=EXT_JS):
        rel = comun.rel(proyecto, p)
        if not legible(p):  # ni el nombre de un archivo dentro de una ruta confidencial llega al motivo
            continue
        if RE_ROUTE_ARCHIVO.search(rel) and not _es_test(rel):
            senales.add(f"archivo {rel}")
            break
    return sorted(senales)


# ------------------------------------------------------------------------------------------------- hallazgos (ronda 6)
def auth_global(textos):
    """Señales de auth que protegen rutas desde fuera del handler. Devuelve {"js": bool, "next": bool,
    "flask_app": bool, "flask_archivos": set, "fastapi": bool, "fastapi_archivos": set, "detalle": [..]}."""
    g = {"js": False, "next": False, "flask_app": False, "flask_archivos": set(), "fastapi": False,
         "fastapi_archivos": set(), "detalle": []}
    for rel, texto in textos.items():
        if rel.endswith(tuple(EXT_JS)):
            for m in RE_USE_RECEPTOR.finditer(texto):
                receptor, ruta, args = m.group(1), m.group(3), m.group(4) or ""
                if not RE_AUTH_MW.search(args):
                    continue
                if (ruta is None and receptor in RECEPTORES_APP) or (ruta and RE_NOMBRE_SENSIBLE.search(ruta)):
                    g["js"] = True
                    g["detalle"].append(f"{rel}:{_linea(texto, m.start())}")
            if RE_MIDDLEWARE_NEXT.search(rel) and RE_AUTH_NEXT_MW.search(texto):
                g["next"] = True
                g["detalle"].append(rel)
        else:
            for m in RE_BEFORE_REQUEST.finditer(texto):
                cuerpo = "\n".join(texto[m.end():].splitlines()[:20])
                if RE_AUTH_BEFORE.search(cuerpo) or RE_AUTH_MW.search(cuerpo):
                    if m.group(1) == "app":
                        g["flask_app"] = True
                    g["flask_archivos"].add(rel)
                    g["detalle"].append(f"{rel}:{_linea(texto, m.start())}")
            for m in RE_DEPENDENCIAS_FASTAPI.finditer(texto):
                if "include_router" in m.group(0) or re.match(r"FastAPI", m.group(0)):
                    g["fastapi"] = True
                g["fastapi_archivos"].add(rel)
                g["detalle"].append(f"{rel}:{_linea(texto, m.start())}")
    return g


def _protegida_global(fila, g):
    fw = fila["framework"]
    if fw == "express":
        return g["js"]
    if fw.startswith("next"):
        return g["next"] or g["js"]
    if fw == "flask":
        return g["flask_app"] or fila["archivo"] in g["flask_archivos"]
    if fw == "fastapi":
        return g["fastapi"] or fila["archivo"] in g["fastapi_archivos"]
    return False


def hallazgos_rutas(inventario, textos):
    """Ronda 6: ruta_admin_sin_auth (alta) y entorno_expuesto (media). Devuelve (hallazgos, auth_global)."""
    g = auth_global(textos)
    hallazgos, vistos = [], set()
    for f in inventario:
        if f["framework"] == "supabase" or f["auth"]:
            continue
        texto = textos.get(f["archivo"]) or ""
        if RE_AUTH_HANDLER.search(texto) or RE_AUTH_LLAMADA.search(texto):
            continue  # hay una señal de auth en el archivo de la ruta (el juicio fino es del revisor-autorizacion)
        nombre = RE_NOMBRE_SENSIBLE.search(f["ruta"] or "") or RE_NOMBRE_SENSIBLE.search(f["archivo"])
        if not nombre or _protegida_global(f, g):
            continue
        clave = (f["archivo"], f["ruta"], f["metodo"])
        if clave in vistos:
            continue
        vistos.add(clave)
        hallazgos.append(comun.hallazgo(
            NOMBRE, "ruta_admin_sin_auth", f["archivo"], f["linea"],
            f"La ruta {f['metodo']} {f['ruta']} es de {nombre.group(1).lower()} (por su nombre o su archivo) y no tiene "
            "ninguna señal de autenticación en el servidor (ni middleware, decorador o chequeo de sesión en el handler, "
            "ni middleware de auth global): cualquiera que conozca la URL puede usarla. Un chequeo solo en el frontend "
            "no protege la API.", f"{f['framework']} {f['metodo']} {f['ruta']}", "alta"))
    for rel, texto in sorted(textos.items()):
        for m in RE_ENV_COMPLETO.finditer(texto):
            inicio = max(texto.rfind(";", 0, m.start()), texto.rfind("\n\n", 0, m.start()), m.start() - 400, 0)
            if not RE_RESPUESTA.search(texto[inicio:m.start()]):
                continue
            linea = _linea(texto, m.start())
            if (rel, linea) in vistos:
                continue
            vistos.add((rel, linea))
            hallazgos.append(comun.hallazgo(
                NOMBRE, "entorno_expuesto", rel, linea,
                "Una respuesta HTTP incluye el entorno completo del proceso (process.env / os.environ): expone claves, "
                "tokens y URLs de bases de datos a quien llame a la ruta. Devolver solo los campos necesarios.",
                m.group(0), "media"))
    return hallazgos, g


# ------------------------------------------------------------------------------------------------- análisis
def analizar(proyecto):
    proyecto = Path(proyecto)
    conf = datos_confidenciales.cargar()
    inventario = []
    alcance = {"archivos_fuente": 0, "rutas": 0, "consultas": 0, "sospechosas": 0, "codigo_confidencial": 0,
               "omitidos_tamano": 0, "omitidos_tope": 0}
    vistos = 0
    textos = {}
    for p in comun.recorrer(proyecto, extensiones=EXT_JS | EXT_PY):
        rel = comun.rel(proyecto, p)
        if p.name in LOCKFILES or _es_test(rel):
            continue
        if datos_confidenciales.es_confidencial(rel, conf):
            alcance["codigo_confidencial"] += 1  # solo por nombre: su contenido no se lee
            continue
        if vistos >= MAX_ARCHIVOS:
            alcance["omitidos_tope"] += 1
            continue
        texto = comun.leer(p)
        if texto is None:
            alcance["omitidos_tamano"] += 1
            continue
        vistos += 1
        alcance["archivos_fuente"] += 1
        textos[rel] = texto
        lineas = texto.splitlines()
        sr = bool(RE_SERVICE_ROLE.search(texto))
        if p.suffix.lower() in EXT_PY:
            inventario += _python(rel, texto, lineas, sr)
            continue
        filas = _next_app(rel, texto, lineas, sr) or _next_pages(rel, texto, lineas, sr) or _express(rel, texto, lineas, sr)
        inventario += filas
        inventario += _supabase(rel, texto, sr)
    inventario.sort(key=lambda f: (f["archivo"], f["linea"], f["metodo"] or "", f["framework"]))
    alcance["rutas"] = sum(1 for f in inventario if f["framework"] != "supabase")
    alcance["consultas"] = sum(1 for f in inventario if f["framework"] == "supabase")
    alcance["sospechosas"] = sum(1 for f in inventario if f["sospechosa"])
    por_fw = {}
    for f in inventario:
        por_fw[f["framework"]] = por_fw.get(f["framework"], 0) + 1
    incompleto = [k for k in ("codigo_confidencial", "omitidos_tamano", "omitidos_tope") if alcance[k]]
    hallazgos, g = hallazgos_rutas(inventario, textos)
    if not inventario:
        senales = senales_backend(proyecto)
        if senales:
            causa = (f"framework no reconocido (señales de backend: {', '.join(senales[:6])}"
                     + (f" y {len(senales) - 6} más" if len(senales) > 6 else "") + ")")
        else:
            causa = ("sin backend detectado (SPA): no hay dependencias de servidor conocidas ni carpetas server/, "
                     "api/, pages/api/ o app/**/route.*")
        res = comun.resultado(hallazgos, estado="no_evaluado", motivo=(
            f"{causa}; no se reconocieron rutas (Express, Next, FastAPI, Flask) ni consultas Supabase; SEG-IDOR y "
            "SEG-BFLA quedan no_evaluado (no es evidencia de que no haya endpoints)"))
    else:
        motivo = (f"inventario incompleto: {', '.join(f'{k}={alcance[k]}' for k in incompleto)}"
                  if incompleto else None)
        res = comun.resultado(hallazgos, motivo=motivo)
    res.update(inventario=inventario, alcance=alcance, resumen={"por_framework": dict(sorted(por_fw.items())),
                                                                 "incompleto": incompleto,
                                                                 "auth_global": sorted(g["detalle"])[:20]})
    return res


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    codigo = comun.main_check(NOMBRE, analizar, argv)
    if len(argv) == 2:
        crudo = Path(argv[1])
        try:
            datos = json.loads((crudo / f"check_{NOMBRE}.json").read_text(encoding="utf-8"))
            ruta_meta = crudo / f"check_{NOMBRE}.meta.json"
            meta = json.loads(ruta_meta.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return codigo
        if isinstance(datos.get("alcance"), dict):
            meta["alcance"] = datos["alcance"]  # estado.alcance_herramientas lo lee de meta.alcance
            comun.escribir_json(ruta_meta, meta)
    return codigo


if __name__ == "__main__":
    sys.exit(main())
