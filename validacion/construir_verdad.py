"""Genera validacion/verdad-terreno.toml ubicando cada línea por patrón (regex).

Uso: python3 validacion/construir_verdad.py  (gate y severidad se leen de catalogo/controles.toml).
Los argumentos gate/severidad de d() son informativos; manda el catálogo.
"""
import re
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
APP = RAIZ / "app-sembrada"
FECHA = "2026-11-18"

V_GL = "gitleaks 8.30.1"
V_SG = "semgrep 1.181.0 p/owasp-top-ten"
V_ZZ = "zizmor 1.32.0 (persona regular, --offline)"
V_OSV = "osv-scanner 2.7.0"

# (control, archivo, patron|None, gate, severidad, detectable, razon, verificada, extra)
D = []


def d(control, archivo, patron, gate, sev, det, razon, verif, **extra):
    D.append((control, archivo, patron, gate, sev, det, razon, verif, extra))


ENVP = "env_publicas.py (F1): prefijo VITE_ con nombre sensible"
REG = "registro_deps.py (F1): el nombre no existe en el registro npm"
ARCH = "archivos_clave.py (F1)"
AGT = "config_agentes.py (F1)"
OWN_AUTH = "regla semgrep propia prevista en el plan (§3.2: auth en cliente)"
OWN_SR = "regla semgrep propia prevista en el plan (§3.2: service_role)"
OWN_AMT = "regla semgrep propia prevista en el plan (§3.2: amount de req.body)"
NO_REGLA = "p/owasp-top-ten no lo detectó en la verificación y no hay regla propia especificada en el plan; candidata a regla propia"

# --- SEG-SECRETO-REPO (N1) ---
for pat, regla in [
    (r"^VITE_OPENAI_API_KEY=", "openai-api-key"),
    (r"^VITE_SUPABASE_SERVICE_ROLE_KEY=", "jwt"),
    (r"^VITE_STRIPE_SECRET_KEY=", "stripe-access-token"),
    (r"^STRIPE_SECRET_KEY=", "stripe-access-token"),
    (r"^SUPABASE_SERVICE_ROLE_KEY=", "jwt"),
    (r"^SENDGRID_API_KEY=", "sendgrid-api-token"),
]:
    d("SEG-SECRETO-REPO", ".env", pat, "N1", "critica", True, "gitleaks sobre el working tree (.env comiteado)", f"{V_GL}: {regla}")
d("SEG-SECRETO-REPO", "server/config.js", r"sk_live_Nj9Z", "N1", "critica", True, "gitleaks: clave Stripe live como fallback en código", f"{V_GL}: stripe-access-token")
d("SEG-SECRETO-REPO", "server/config.js", r"ghp_", "N1", "critica", True, "gitleaks: token GitHub clásico", f"{V_GL}: github-pat")
d("SEG-SECRETO-REPO", "server/almacenamiento.js", r"accessKeyId: 'AKIA", "N1", "critica", True, "gitleaks: clave de acceso AWS", f"{V_GL}: aws-access-token")
d("SEG-SECRETO-REPO", "server/almacenamiento.js", r"secretAccessKey:", "N1", "critica", True, "gitleaks: regla genérica por palabra clave", f"{V_GL}: generic-api-key")
d("SEG-SECRETO-REPO", "src/lib/pagos.js", r"const STRIPE_SK = ", "N1", "critica", True, "gitleaks: clave Stripe live en código del cliente", f"{V_GL}: stripe-access-token")
d("SEG-SECRETO-REPO", ".mcp.json", r"\"SUPABASE_SERVICE_ROLE_KEY\": \"eyJ", "N1", "critica", True, "gitleaks: JWT service_role en configuración MCP", f"{V_GL}: jwt")
# --- SEG-SECRETO-BUNDLE (N1) ---
B = "dist/assets/index-7c1e9a4b.js"
d("SEG-SECRETO-BUNDLE", B, r"const Hm=bf\(", "N1", "critica", True, "gitleaks sobre dist/: JWT service_role en el bundle", f"{V_GL}: jwt")
d("SEG-SECRETO-BUNDLE", B, r"const Ab=\"sk_live_", "N1", "critica", True, "gitleaks sobre dist/: clave Stripe live en el bundle", f"{V_GL}: stripe-access-token")
d("SEG-SECRETO-BUNDLE", B, r"apiKey:\"sk-", "N1", "critica", True, "gitleaks sobre dist/: clave OpenAI en el bundle", f"{V_GL}: openai-api-key")
# --- SEG-ENV-PUBLICAS (N1) ---
d("SEG-ENV-PUBLICAS", ".env", r"^VITE_SUPABASE_SERVICE_ROLE_KEY=", "N1", "critica", True, ENVP, "no aplica (check propio de F1 aún no construido)")
d("SEG-ENV-PUBLICAS", ".env", r"^VITE_OPENAI_API_KEY=", "N1", "alta", True, ENVP, "no aplica (check propio de F1 aún no construido)")
d("SEG-ENV-PUBLICAS", ".env", r"^VITE_STRIPE_SECRET_KEY=", "N1", "critica", True, ENVP, "no aplica (check propio de F1 aún no construido)")
# --- SEG-ENV-EJEMPLO (N1) ---
d("SEG-ENV-EJEMPLO", ".env.example", None, "N1", "media", True, ARCH + ": falta .env.example", "verificado por inspección: el archivo no existe", ausencia=True, falta_archivo=True)
# --- SEG-DEPS-EXISTEN (N1) ---
for p in ["express-secure-session-kit", "react-stripe-checkout-hooks-v2", "supabase-rls-helper-pro", "vite-plugin-env-guardian"]:
    d("SEG-DEPS-EXISTEN", "package.json", rf"\"{re.escape(p)}\":", "N1", "critica", True, REG,
      f"curl https://registry.npmjs.org/{p} → HTTP 404 ({FECHA})", paquete=p)
# --- SEG-DEPS-CVE-CRIT (N2) ---
for p, cvss in [("ejs", "9.8"), ("handlebars", "9.8"), ("lodash", "9.1"), ("minimist", "9.8"), ("shell-quote", "9.8")]:
    d("SEG-DEPS-CVE-CRIT", "package-lock.json", rf"\"node_modules/{re.escape(p)}\":", "N2", "critica", True,
      "osv-scanner sobre package-lock.json", f"{V_OSV}: CVSS máx {cvss} ({FECHA})", paquete=p)
# --- SEG-DEPS-CVE-ALTO (N4) ---
for p, cvss in [("axios", "8.6"), ("jsonwebtoken", "8.1")]:
    d("SEG-DEPS-CVE-ALTO", "package-lock.json", rf"\"node_modules/{re.escape(p)}\":", "N4", "alta", True,
      "osv-scanner sobre package-lock.json", f"{V_OSV}: CVSS máx {cvss} ({FECHA})", paquete=p)
# --- SEG-SAST-INY (N2) ---
d("DAT-SQL-CONCATENADO", "server/rutas/usuarios.js", r"WHERE email = '\" \+ req\.query\.email", "N2", "critica", False, NO_REGLA, "ninguna (semgrep p/owasp-top-ten: sin hallazgo)")
d("DAT-SQL-CONCATENADO", "server/rutas/reportes.js", r"= \$\{req\.params\.anio\}", "N2", "critica", False, NO_REGLA, "ninguna (semgrep p/owasp-top-ten: sin hallazgo)")
d("SEG-SAST-INY", "server/rutas/reportes.js", r"eval\(req\.body\.formula\)", "N2", "critica", True, "semgrep p/owasp-top-ten", f"{V_SG}: code-string-concat")
d("SEG-SAST-INY", "server/rutas/reportes.js", r"exec\('pdftotext", "N2", "critica", False, NO_REGLA, "ninguna (semgrep p/owasp-top-ten: sin hallazgo)")
d("SEG-SAST-INY", "src/components/Comentario.jsx", r"dangerouslySetInnerHTML", "N2", "alta", True, "semgrep p/owasp-top-ten", f"{V_SG}: react-dangerouslysetinnerhtml")
d("SEG-LLM-SALIDA", "src/components/RespuestaIA.jsx", r"dangerouslySetInnerHTML", "N2", "alta", False, NO_REGLA + " (HTML de salida de LLM)", "ninguna (semgrep p/owasp-top-ten: sin hallazgo)")
# --- SEG-AUTH-CLIENTE (N2) ---
d("SEG-AUTH-CLIENTE", "src/components/RutaPrivada.jsx", r"localStorage\.getItem\('esAdmin'\)", "N2", "critica", True, OWN_AUTH, "no aplica (regla propia aún no escrita)")
d("SEG-AUTH-CLIENTE", "src/pages/Login.jsx", r"localStorage\.setItem\('esAdmin'", "N2", "critica", True, OWN_AUTH, "no aplica (regla propia aún no escrita)")
d("SEG-AUTH-CLIENTE", "src/lib/supabaseAdmin.js", r"VITE_SUPABASE_SERVICE_ROLE_KEY", "N2", "critica", True, OWN_SR + "; alias: service_role en el cliente", "no aplica (regla propia aún no escrita)")
# --- SEG-PAGOS-* (N2) ---
d("SEG-PAGOS-SERVIDOR", "server/rutas/pagos.js", r"amount: req\.body\.monto", "N2", "critica", True, OWN_AMT, "no aplica (regla propia aún no escrita)")
d("SEG-PAGOS-FIRMA", "server/rutas/pagos.js", r"const evento = req\.body", "N2", "critica", False, "webhook sin verificación de firma: no hay regla en F1", "ninguna")
# --- SEG-AGENTES-IA (N2) ---
d("SEG-AGENTES-IA", ".mcp.json", r"\"SUPABASE_SERVICE_ROLE_KEY\": \"eyJ", "N2", "critica", True, AGT + ": service_role en servidor MCP", "no aplica (check propio de F1 aún no construido)")
d("SEG-AGENTES-IA", ".claude/settings.json", r"bypassPermissions", "N2", "alta", True, AGT + ": defaultMode bypassPermissions", "no aplica (check propio de F1 aún no construido)")
d("SEG-AGENTES-IA", ".claude/settings.json", r"\"Bash\(\*\)\"", "N2", "alta", True, AGT + ": Bash(*) permitido", "no aplica (check propio de F1 aún no construido)")
d("SEG-AGENTES-IA", ".claude/settings.json", r"mcp__supabase__execute_sql", "N2", "alta", True, AGT + ": SQL arbitrario vía MCP con service_role", "no aplica (check propio de F1 aún no construido)")
# --- SEG-LLM-CLAVE (N1, condicional llm) ---
d("SEG-LLM-CLAVE", "src/lib/ia.js", r"apiKey: import\.meta\.env\.VITE_OPENAI_API_KEY", "N1", "critica", False, "llamada al LLM desde el navegador: sin regla propia especificada (la variable sí la cubre SEG-ENV-PUBLICAS)", "ninguna")
# --- SEG-ERRORES (N3) ---
d("SEG-ERRORES", "server/rutas/pagos.js", r"\} catch \(e\) \{\}", "N3", "media", False, "catch vacío en el pago: sin regla verificada en F1", "ninguna (semgrep p/owasp-top-ten: sin hallazgo)")
d("SEG-ERRORES", "server/index.js", r"stack: err\.stack", "N3", "media", False, "stack trace en la respuesta: sin regla verificada en F1", "ninguna (semgrep p/owasp-top-ten: sin hallazgo)")
# --- SEG-CORS (N3) ---
d("SEG-CORS", "server/index.js", r"origin: '\*', credentials: true", "N3", "alta", False, "CORS * con credenciales: sin regla verificada en F1", "ninguna (semgrep p/owasp-top-ten: sin hallazgo)")
# --- SEG-CICD (N3) ---
P = ".github/workflows/preview.yml"
d("SEG-CICD", P, r"^  pull_request_target:", "N3", "alta", True, "zizmor dangerous-triggers", f"{V_ZZ}: dangerous-triggers")
d("SEG-CICD", P, r"^permissions: write-all", "N3", "media", False, "zizmor solo lo informa con --persona auditor; el adaptador F1 usa la persona por defecto", f"{V_ZZ}: sin hallazgo (sí con --persona auditor: excessive-permissions)")
d("SEG-CICD", P, r"uses: actions/checkout@v4", "N3", "media", True, "zizmor unpinned-uses", f"{V_ZZ}: unpinned-uses; {V_SG}: github-actions-mutable-action-tag")
d("SEG-CICD", P, r"ref: \$\{\{ github\.event\.pull_request\.head\.sha", "N3", "critica", True, "checkout del head en pull_request_target: semgrep pull-request-target-code-checkout y zizmor artipacked (informan la línea 13, dentro de ±3)", f"{V_SG}: pull-request-target-code-checkout; {V_ZZ}: artipacked")
d("SEG-CICD", P, r"uses: actions/setup-node@v4", "N3", "media", True, "zizmor unpinned-uses", f"{V_ZZ}: unpinned-uses")
d("SEG-CICD", P, r"amondnet/vercel-action@master", "N3", "alta", True, "zizmor unpinned-uses (acción de terceros en rama)", f"{V_ZZ}: unpinned-uses")
d("SEG-CICD", ".github/workflows/triage.yml", r"github\.event\.issue\.title", "N3", "alta", True, "zizmor template-injection", f"{V_ZZ}: template-injection; {V_SG}: run-shell-injection")
# --- No detectables en F1 (F2/F3) ---
d("SEG-IDOR", "server/rutas/citas.js", r"FROM citas WHERE id = \$1", "N2", "critica", False, "IDOR: requiere juicio del agente revisor-autorizacion (F3)", "ninguna")
d("SEG-BFLA", "server/rutas/admin.js", r"router\.get\('/pacientes'", "N2", "critica", False, "ruta admin sin control en servidor: revisor-autorizacion (F3)", "ninguna")
d("SEG-BFLA", "server/rutas/admin.js", r"router\.post\('/rol'", "N2", "critica", False, "cambio de rol sin control en servidor: revisor-autorizacion (F3)", "ninguna")
d("SEG-RATELIMIT", "server/rutas/auth.js", r"router\.post\('/login'", "N2", "alta", False, "sin límite de intentos: rutas_inventario.py + juicio (F3)", "ninguna")
d("ESC-LLM-TOPE", "src/lib/ia.js", r"chat\.completions\.create", "N2", "alta", False, "LLM sin max_tokens: sin regla en F1", "ninguna")
M = "supabase/migrations/20250114120000_inicial.sql"
d("DAT-RLS-ON", M, r"create table public\.pacientes", "N2", "critica", False, "tabla sin RLS: splinter/esquema_resumen.py (F2)", "ninguna")
d("DAT-RLS-PERMISIVA", M, r"for all using \(true\)", "N2", "critica", False, "política USING(true): splinter/esquema_resumen.py (F2)", "ninguna")
d("DAT-MIGRACIONES-SEGURAS", "supabase/migrations/20250302090000_indice_citas.sql", r"^create index citas_paciente_id_idx", "N3", "media", False, "CREATE INDEX sin CONCURRENTLY en tabla existente: squawk (F2)", "ninguna")
# --- COD / OPS (ausencias) ---
d("COD-REPRO", "README.md", None, "N1", "alta", True, ARCH + ": README sin instrucciones de instalación ni arranque", "verificado por inspección")
d("COD-TESTS-HUMO", "tests/", None, "N2", "alta", True, ARCH + ": no hay tests ni script test en package.json", "verificado por inspección", ausencia=True, falta_archivo=True)
d("OPS-HEALTH", "server/index.js", None, "N2", "media", True, ARCH + ": no existe ruta /health", "verificado por inspección", ausencia=True)

# ---------------- LIMPIOS ----------------
L = []


def l(control, archivo, patron, razon, **extra):
    L.append((control, archivo, patron, razon, extra))


l("SEG-SECRETO-REPO", ".env", r"^VITE_SUPABASE_ANON_KEY=", "clave publicable de Supabase: pública por diseño (gitleaks crudo la marca como generic-api-key: prueba el filtro)")
l("SEG-SECRETO-REPO", ".env", r"^VITE_STRIPE_PUBLISHABLE_KEY=", "pk_live es publicable (gitleaks crudo la marca como generic-api-key: prueba el filtro)")
l("SEG-SECRETO-REPO", "server/config.js", r"databaseUrl: process\.env\.DATABASE_URL", "lee del entorno, sin literal")
l("SEG-SECRETO-REPO", "server/config.js", r"supabaseServiceKey: process\.env", "nombre sensible pero sin literal")
l("SEG-SECRETO-REPO", "server/config.js", r"stripeWebhookSecret: process\.env", "nombre sensible pero sin literal")
l("SEG-SECRETO-REPO", ".mcp.json", r"\"CONTEXT7_API_KEY\": \"\$\{CONTEXT7_API_KEY\}\"", "referencia a variable, no literal")
l("SEG-SECRETO-REPO", "package-lock.json", r"\"integrity\": \"sha512-", "hash de integridad, no secreto (primera ocurrencia)")
l("SEG-SECRETO-REPO", "src/lib/supabaseClient.js", r"const supabaseAnonKey = import\.meta\.env", "clave anon leída del entorno")
l("SEG-SECRETO-BUNDLE", "dist/assets/index-7c1e9a4b.js", r"Fu=\"sb_publishable_", "clave publicable en el bundle: correcto")
l("SEG-SECRETO-BUNDLE", "dist/assets/index-7c1e9a4b.js", r"const Ip=\"pk_live_", "clave publicable de Stripe en el bundle: correcto")
l("SEG-SECRETO-BUNDLE", "dist/index.html", r"<script type=\"module\"", "HTML del bundle sin secretos")
l("SEG-ENV-PUBLICAS", ".env", r"^VITE_APP_NOMBRE=", "nombre no sensible")
l("SEG-ENV-PUBLICAS", ".env", r"^VITE_SUPABASE_URL=", "URL pública")
l("SEG-ENV-PUBLICAS", ".env", r"^VITE_SUPABASE_ANON_KEY=", "ANON es pública por diseño (no debe tratarse como KEY sensible)")
l("SEG-ENV-PUBLICAS", ".env", r"^VITE_STRIPE_PUBLISHABLE_KEY=", "PUBLISHABLE es pública por diseño")
for p in ["@supabase/supabase-js", "dompurify", "express", "react", "zod", "@vitejs/plugin-react"]:
    l("SEG-DEPS-EXISTEN", "package.json", rf"\"{re.escape(p)}\":", "paquete real publicado en npm", paquete=p)
for p in ["express", "react", "dompurify", "pg", "stripe", "vite"]:
    l("SEG-DEPS-CVE-CRIT", "package-lock.json", rf"\"node_modules/{re.escape(p)}\":", f"osv-scanner 2.7.0 sin vulnerabilidades ({FECHA})", paquete=p)
l("DAT-SQL-CONCATENADO", "server/rutas/usuarios.js", r"WHERE id = \$1', \[req\.usuario\.id\]", "consulta parametrizada")
l("DAT-SQL-CONCATENADO", "server/rutas/reportes.js", r"extract\(month from fecha\) = \$2", "consulta parametrizada")
l("DAT-SQL-CONCATENADO", "server/rutas/profesionales.js", r"especialidad = \$1\) LIMIT 50", "consulta parametrizada")
l("DAT-SQL-CONCATENADO", "server/rutas/pagos.js", r"WHERE s\.id = \$1 AND s\.paciente_id = \$2", "consulta parametrizada")
l("SEG-SAST-INY", "src/components/NotaClinica.jsx", r"dangerouslySetInnerHTML=\{\{ __html: limpio \}\}", "HTML sanitizado con DOMPurify (prueba FP de la regla react)")
l("SEG-SAST-INY", "src/components/TarjetaProfesional.jsx", r"\{profesional\.biografia\}", "texto escapado por React")
l("SEG-SAST-INY", "src/utils/formato.js", r"return JSON\.parse\(texto\)", "JSON.parse en vez de eval")
l("SEG-AUTH-CLIENTE", "server/middleware/auth.js", r"supabase\.auth\.getUser\(token\)", "verificación del JWT en el servidor")
l("SEG-AUTH-CLIENTE", "src/pages/Perfil.jsx", r"supabase\.auth\.getUser\(\)", "sesión real de Supabase; RLS protege los datos")
l("SEG-AUTH-CLIENTE", "src/lib/supabaseClient.js", r"export const supabase = createClient", "cliente con clave anon")
l("SEG-AUTH-CLIENTE", "server/rutas/auth.js", r"const supabase = createClient\(config\.supabaseUrl, config\.supabaseServiceKey\)", "service_role usado en el servidor: correcto")
l("SEG-PAGOS-SERVIDOR", "server/rutas/pagos.js", r"amount: rows\[0\]\.precio_sesion", "monto tomado de la BD")
l("SEG-ERRORES", "server/rutas/pagos.js", r"console\.error\('Error creando el cobro'", "error registrado y respuesta genérica")
l("SEG-ERRORES", "server/rutas/profesionales.js", r"console\.error\('Error listando profesionales'", "error registrado y respuesta genérica")
l("SEG-ERRORES", "src/utils/formato.js", r"console\.warn\('Preferencias inválidas", "catch con manejo explícito")
l("SEG-CORS", "server/rutas/profesionales.js", r"cors\(\{ origin: 'https://agendakine\.cl' \}\)", "origen explícito sin credenciales")
W = ".github/workflows/lint.yml"
l("SEG-CICD", W, r"^  pull_request:", "disparador seguro")
l("SEG-CICD", W, r"^  contents: read", "permisos mínimos")
l("SEG-CICD", W, r"actions/checkout@08eba0b", "acción fijada a SHA con persist-credentials: false")
l("SEG-CICD", W, r"run: npm ci --ignore-scripts", "run sin expresiones de contexto")
l("SEG-AGENTES-IA", ".mcp.json", r"@upstash/context7-mcp@1\.0\.14", "servidor MCP con versión fija y clave por variable")
l("SEG-AGENTES-IA", ".claude/settings.json", r"\"Read\(\./src/\*\*\)\"", "permiso de lectura acotado")
l("SEG-AGENTES-IA", ".claude/settings.json", r"\"Read\(\./\.env\)\"", "deny de lectura de .env")
l("SEG-IDOR", "server/rutas/citas.js", r"WHERE paciente_id = \$1 ORDER BY", "filtra por el usuario autenticado")
l("DAT-RLS-ON", M, r"alter table public\.perfiles enable row level security", "RLS activado")
l("DAT-RLS-PERMISIVA", M, r"for select using \(auth\.uid\(\) = id\)", "política por dueño")
l("DAT-RLS-PERMISIVA", M, r"for select using \(auth\.uid\(\) = paciente_id\)", "política por dueño")
l("DAT-MIGRACIONES-SEGURAS", M, r"create index comentarios_creado_en_idx", "índice sobre tabla recién creada en la misma migración")
l("SEG-LOCKFILE", "package-lock.json", None, "lockfile presente")


import tomllib
with open(RAIZ.parent / "catalogo" / "controles.toml", "rb") as fh:
    CAT = {c["id"]: c for c in tomllib.load(fh)["control"]}


def del_catalogo(control):
    if control not in CAT:
        raise SystemExit(f"control fuera del catálogo: {control}")
    return CAT[control]


def ubicar(archivo, patron):
    lineas = (APP / archivo).read_text(encoding="utf-8").splitlines()
    hits = [i + 1 for i, s in enumerate(lineas) if re.search(patron, s)]
    if not hits:
        raise SystemExit(f"patrón no encontrado: {archivo} {patron}")
    return hits[0]


def q(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def reservado(n):
    return n % 10 in (3, 6, 9)


out = []
out.append("""# Verdad de terreno del brazo A (app sembrada) — auditor-integral
# Generado el %s. Fuente de la app: validacion/app-sembrada/ (AgendaKine, Vite+React+Supabase+Express).
#
# CONVENCIONES
# - control: ID canónico de catalogo/controles.toml (fuente única, §4.3). gate y severidad se copian del
#   catálogo (gate y severidad_base) al generar este archivo; si el catálogo cambia, regenerar.
#   El SQL concatenado va a DAT-SQL-CONCATENADO (N1) y el HTML de salida LLM a SEG-LLM-SALIDA, según el catálogo.
# - archivo: ruta relativa a app-sembrada/. linea: 1-based; se omite en defectos de ausencia o de archivo completo.
# - patron: regex que DEBE coincidir con la línea indicada (tests/test_verdad_terreno.py lo verifica;
#   si alguien edita la app, el test falla hasta regenerar las líneas).
# - ausencia = true: el defecto es que algo falta; coincide por control sin exigir archivo.
#   falta_archivo = true: además el archivo indicado no existe en la app (lo verifica el test).
# - paquete: para dependencias; el hallazgo debe mencionar el nombre del paquete.
# - detectable_en_F1: true si (a) una herramienta de F1 (gitleaks, semgrep p/owasp-top-ten, osv-scanner, zizmor
#   persona por defecto) lo detectó en la verificación de siembra, o (b) lo cubre un check/regla propia que el
#   plan especifica explícitamente para F1 (env_publicas, registro_deps, archivos_clave, config_agentes; reglas
#   semgrep: auth en cliente, service_role, amount de req.body). En otro caso false con su razón.
# - deteccion_verificada: qué herramienta cruda lo marcó al sembrar (%s). LIMITACIÓN: quien sembró corrió las
#   herramientas crudas (no el auditor) para comprobar que la siembra es detectable; esto rompe parcialmente el
#   cegamiento de §11.5 y se declara.
# - reservado: criterio fijo y documentado: número del id (D07 → 7, L13 → 13) con n %% 10 ∈ {3, 6, 9}
#   (≈ 30 %%). Los reservados no se miran durante el desarrollo; solo para la medición final (§11.5 paso 5).
# - Todos los secretos de la app son CANARIOS FALSOS generados al azar; ninguno es válido.
""" % (FECHA, FECHA))

for n, (control, archivo, patron, gate, sev, det, razon, verif, extra) in enumerate(D, 1):
    out.append("[[defecto]]")
    out.append(f"id = \"D{n:02d}\"")
    out.append(f"control = {q(control)}")
    out.append(f"archivo = {q(archivo)}")
    if patron is not None:
        out.append(f"linea = {ubicar(archivo, patron)}")
        out.append(f"patron = {q(patron)}")
    if extra.get("ausencia"):
        out.append("ausencia = true")
    if extra.get("falta_archivo"):
        out.append("falta_archivo = true")
    if extra.get("paquete"):
        out.append(f"paquete = {q(extra['paquete'])}")
    c = del_catalogo(control)
    out.append(f"gate = {q(c['gate'])}")
    out.append(f"severidad = {q(c['severidad_base'])}")
    out.append(f"detectable_en_F1 = {'true' if det else 'false'}")
    out.append(f"razon_detectable = {q(razon)}")
    out.append(f"deteccion_verificada = {q(verif)}")
    out.append(f"reservado = {'true' if reservado(n) else 'false'}")
    out.append("")

for n, (control, archivo, patron, razon, extra) in enumerate(L, 1):
    out.append("[[limpio]]")
    out.append(f"id = \"L{n:02d}\"")
    out.append(f"control = {q(control)}")
    out.append(f"archivo = {q(archivo)}")
    if patron is not None:
        out.append(f"linea = {ubicar(archivo, patron)}")
        out.append(f"patron = {q(patron)}")
    if extra.get("paquete"):
        out.append(f"paquete = {q(extra['paquete'])}")
    del_catalogo(control)
    out.append(f"razon = {q(razon)}")
    out.append(f"reservado = {'true' if reservado(n) else 'false'}")
    out.append("")

(RAIZ / "verdad-terreno.toml").write_text("\n".join(out), encoding="utf-8")
print(len(D), "defectos;", len(L), "limpios")
