#!/usr/bin/env python3
"""Detecta el stack técnico de un proyecto solo por sus archivos → perfil_tecnico.json.

Uso:
    detectar_stack.py RUTA [--salida ARCHIVO]

Solo lee; nunca escribe en el proyecto auditado. No entra a node_modules, .git, entornos
virtuales ni carpetas de build (estas últimas se registran en `carpetas_build`). No sigue
enlaces simbólicos. La evidencia que sale SOLO de carpetas de test o fixtures (comun.es_test_o_fixture: test/, tests/,
spec/, e2e/, fixtures/, __mocks__/…, *.test.*, test_*.py) queda en `evidencia_secundaria` y no enciende banderas: un
manifiesto o Dockerfile de prueba no es superficie del proyecto y no debe volver obligatorios sus controles. Los
escaneos de hallazgos no usan este criterio (no cambian). Las banderas que solo se conocen por entrevista (salud, menores, etc.)
no se infieren aquí (PLAN_MAESTRO §3.6).
"""
import argparse
import json
import os
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "checks"))
import comun  # noqa: E402  (criterio único de código de test / fixtures)

GENERADOR = "detectar_stack.py 0.1.0"
MAX_ARCHIVOS = 50_000
MAX_BYTES_LECTURA = 512 * 1024
MAX_EVIDENCIA = 10

# Carpetas que no se recorren.
EXCLUIDAS = {
    "node_modules", ".git", ".hg", ".svn", ".auditoria", "bower_components", ".venv", "venv",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox", ".idea",
    ".gradle", ".dart_tool", ".pnpm-store", ".yarn", ".cache", ".turbo", ".parcel-cache",
    "site-packages", "Pods", "DerivedData",
}
# Carpetas de build: se registran como presentes, pero tampoco se recorren.
BUILD = {"dist", "build", ".next", "out", ".output", ".nuxt", ".svelte-kit", ".vercel",
         ".netlify", "storybook-static", ".expo", "web-build"}

EXTENSIONES = {
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".py": "python", ".go": "go", ".rb": "ruby", ".java": "java", ".kt": "kotlin",
    ".swift": "swift", ".dart": "dart", ".rs": "rust", ".php": "php", ".cs": "csharp",
    ".html": "html", ".htm": "html", ".css": "css", ".scss": "css", ".sass": "css", ".less": "css",
    ".sql": "sql", ".tf": "hcl", ".sh": "shell",
}

# --- Mapas dependencia → valor (nombres de npm tal cual; nombres de Python normalizados) ---
FRAMEWORKS_NODE = {
    "vite": "vite", "next": "next", "react": "react", "vue": "vue", "svelte": "svelte",
    "@sveltejs/kit": "sveltekit", "nuxt": "nuxt", "astro": "astro", "@remix-run/react": "remix",
    "express": "express", "@nestjs/core": "nest", "fastify": "fastify", "hono": "hono",
    "@angular/core": "angular", "koa": "koa",
}
FRAMEWORKS_PY = {"fastapi": "fastapi", "django": "django", "flask": "flask", "starlette": "starlette",
                 "litestar": "litestar", "streamlit": "streamlit"}
# starlette suele venir con fastapi; se elimina si fastapi está presente.

ORM_NODE = {"@prisma/client": "prisma", "prisma": "prisma", "drizzle-orm": "drizzle", "typeorm": "typeorm",
            "sequelize": "sequelize", "mongoose": "mongoose", "kysely": "kysely", "@mikro-orm/core": "mikro-orm",
            "knex": "knex", "objection": "objection"}
ORM_PY = {"sqlalchemy": "sqlalchemy", "flask-sqlalchemy": "sqlalchemy", "sqlmodel": "sqlmodel",
          "django": "django-orm", "tortoise-orm": "tortoise", "peewee": "peewee", "pony": "pony",
          "prisma": "prisma", "mongoengine": "mongoengine"}

BAAS_NODE = {"@supabase/supabase-js": "supabase", "@supabase/ssr": "supabase",
             "@supabase/auth-helpers-nextjs": "supabase", "firebase": "firebase",
             "firebase-admin": "firebase", "@react-native-firebase/app": "firebase"}
BAAS_PY = {"supabase": "supabase", "firebase-admin": "firebase"}

SSR_NODE = {"next": "next", "nuxt": "nuxt", "@sveltejs/kit": "sveltekit", "@remix-run/node": "remix",
            "@remix-run/react": "remix", "@astrojs/node": "astro-ssr", "@astrojs/vercel": "astro-ssr",
            "@astrojs/netlify": "astro-ssr", "@astrojs/cloudflare": "astro-ssr",
            "@netlify/functions": "netlify-functions", "@vercel/node": "vercel-functions",
            "serverless": "serverless-framework", "wrangler": "cloudflare-workers",
            "firebase-functions": "firebase-functions"}

LLM_NODE = {"openai": "openai", "@anthropic-ai/sdk": "anthropic", "@google/generative-ai": "google",
            "@google/genai": "google", "ai": "vercel-ai-sdk", "langchain": "langchain",
            "groq-sdk": "groq", "cohere-ai": "cohere", "@mistralai/mistralai": "mistral", "ollama": "ollama",
            "replicate": "replicate", "llamaindex": "llamaindex"}
LLM_NODE_PREFIJOS = {"@ai-sdk/": "vercel-ai-sdk", "@langchain/": "langchain"}
LLM_PY = {"openai": "openai", "anthropic": "anthropic", "google-generativeai": "google", "google-genai": "google",
          "langchain": "langchain", "groq": "groq", "cohere": "cohere", "mistralai": "mistral",
          "ollama": "ollama", "replicate": "replicate", "llama-index": "llamaindex", "litellm": "litellm"}
LLM_PY_PREFIJOS = {"langchain-": "langchain", "llama-index-": "llamaindex"}

PAGOS_NODE = {"stripe": "stripe", "@stripe/stripe-js": "stripe", "@stripe/react-stripe-js": "stripe",
              "mercadopago": "mercadopago", "@mercadopago/sdk-react": "mercadopago", "braintree": "braintree",
              "square": "square", "@lemonsqueezy/lemonsqueezy.js": "lemonsqueezy", "transbank-sdk": "transbank",
              "razorpay": "razorpay", "paypal-rest-sdk": "paypal"}
PAGOS_NODE_PREFIJOS = {"@paypal/": "paypal", "@paddle/": "paddle"}
PAGOS_PY = {"stripe": "stripe", "mercadopago": "mercadopago", "transbank-sdk": "transbank",
            "paypalrestsdk": "paypal", "braintree": "braintree", "razorpay": "razorpay"}

EMAILS_NODE = {"resend": "resend", "@sendgrid/mail": "sendgrid", "nodemailer": "nodemailer", "postmark": "postmark",
               "mailgun.js": "mailgun", "@getbrevo/brevo": "brevo", "sib-api-v3-sdk": "brevo",
               "@aws-sdk/client-ses": "aws-ses", "@aws-sdk/client-sesv2": "aws-ses", "react-email": "react-email"}
EMAILS_NODE_PREFIJOS = {"@react-email/": "react-email"}
EMAILS_PY = {"resend": "resend", "sendgrid": "sendgrid", "postmarker": "postmark", "flask-mail": "flask-mail",
             "django-anymail": "anymail", "fastapi-mail": "fastapi-mail"}

MOVIL_NODE = {"expo": "expo", "react-native": "react-native", "@capacitor/core": "capacitor",
              "cordova": "cordova", "nativescript": "nativescript"}
MOVIL_NODE_PREFIJOS = {"@ionic/": "ionic"}

PWA_NODE = {"vite-plugin-pwa": "vite-plugin-pwa", "next-pwa": "next-pwa", "@ducanh2912/next-pwa": "next-pwa",
            "@angular/service-worker": "angular-sw", "serwist": "serwist"}
PWA_NODE_PREFIJOS = {"workbox-": "workbox", "@vite-pwa/": "vite-plugin-pwa", "@serwist/": "serwist"}

I18N_NODE = {"i18next": "i18next", "react-i18next": "i18next", "next-i18next": "i18next", "next-intl": "next-intl",
             "vue-i18n": "vue-i18n", "@nuxtjs/i18n": "nuxt-i18n", "svelte-i18n": "svelte-i18n",
             "react-intl": "formatjs", "@formatjs/intl": "formatjs", "typesafe-i18n": "typesafe-i18n",
             "i18n-js": "i18n-js", "expo-localization": "expo-localization"}
I18N_NODE_PREFIJOS = {"@lingui/": "lingui"}
I18N_PY = {"flask-babel": "babel", "babel": "babel", "django-modeltranslation": "django-i18n",
           "django-rosetta": "django-i18n", "fastapi-babel": "babel"}
I18N_CARPETAS = {"locales", "locale", "i18n", "translations"}

AGENTE_ARCHIVOS = {".mcp.json": "mcp", "CLAUDE.md": "claude", "AGENTS.md": "agents-md", ".cursorrules": "cursor",
                   ".windsurfrules": "windsurf", ".clinerules": "cline", "GEMINI.md": "gemini",
                   ".aider.conf.yml": "aider", "copilot-instructions.md": "copilot"}
AGENTE_CARPETAS = {".claude": "claude", ".cursor": "cursor", ".continue": "continue", ".windsurf": "windsurf"}

CI_ARCHIVOS = {".gitlab-ci.yml": "gitlab", "azure-pipelines.yml": "azure", "bitbucket-pipelines.yml": "bitbucket",
               "Jenkinsfile": "jenkins", ".travis.yml": "travis"}

LOCK_NODE = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "pnpm-lock.yaml": "pnpm",
             "yarn.lock": "yarn", "bun.lockb": "bun", "bun.lock": "bun"}
# Ronda 6 (stack): requirements.lock (pip-tools/rye/uv pip compile) también es lockfile; archivos_clave ya lo aceptaba
# y el perfil decía «sin lockfile» (contradicción en harness).
LOCK_PY = {"uv.lock": "uv", "poetry.lock": "poetry", "Pipfile.lock": "pipenv", "pdm.lock": "pdm",
           "requirements.lock": "pip"}
OTROS_ECOSISTEMAS = {  # ecosistema: (manifiestos, lockfiles, gestor)
    "go": ({"go.mod"}, {"go.sum"}, "go"),
    "ruby": ({"Gemfile"}, {"Gemfile.lock"}, "bundler"),
    "rust": ({"Cargo.toml"}, {"Cargo.lock"}, "cargo"),
    "php": ({"composer.json"}, {"composer.lock"}, "composer"),
    "dart": ({"pubspec.yaml"}, {"pubspec.lock"}, "pub"),
}

# Servidor propio (backend o SSR) y base de datos: condicionan los controles de servidor/BD/IaC
# (Anexo C del brazo C, AUD-INF). Una PWA estática sin estas dependencias queda servidor = bd = false.
SERVIDOR_NODE = {"express": "express", "fastify": "fastify", "koa": "koa", "hono": "hono",
                 "@nestjs/core": "nest", "@hapi/hapi": "hapi", "next": "next", "nuxt": "nuxt",
                 "@sveltejs/kit": "sveltekit", "@remix-run/node": "remix", "@remix-run/react": "remix",
                 "@astrojs/node": "astro-ssr", "socket.io": "socket.io", "ws": "ws"}
SERVIDOR_PY = {"fastapi": "fastapi", "django": "django", "flask": "flask", "starlette": "starlette",
               "litestar": "litestar", "aiohttp": "aiohttp", "sanic": "sanic", "tornado": "tornado",
               "streamlit": "streamlit", "uvicorn": "uvicorn", "gunicorn": "gunicorn"}
BD_NODE = {"pg": "pg", "postgres": "postgres", "mysql": "mysql", "mysql2": "mysql2", "mongodb": "mongodb",
           "mongoose": "mongoose", "better-sqlite3": "sqlite", "sqlite3": "sqlite", "@libsql/client": "libsql",
           "@neondatabase/serverless": "neon", "@planetscale/database": "planetscale", "@vercel/postgres": "vercel-postgres",
           "redis": "redis", "ioredis": "redis"}
BD_PY = {"psycopg": "psycopg", "psycopg2": "psycopg", "psycopg2-binary": "psycopg", "asyncpg": "asyncpg",
         "pymongo": "pymongo", "motor": "pymongo", "mysqlclient": "mysql", "pymysql": "mysql", "redis": "redis"}
CARPETAS_MIGRACIONES = ("supabase/migrations", "prisma/migrations", "alembic/versions", "db/migrate",
                        "database/migrations", "migrations")

# Ronda 6 (stack): pagos también por uso en el código (import/require del SDK) y por rutas webhook que nombran a un
# proveedor de pagos (un webhook de Stripe sin el SDK instalado dejaba pagos=false y SEG-PAGOS-FIRMA en no_aplica).
EXT_CODIGO_PAGOS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".rb", ".php", ".go"}
MAX_ARCHIVOS_CODIGO = 5000
RE_PAGOS_IMPORT = (
    (re.compile(r"^\s*(?:import\s+stripe\b|from\s+stripe\b)|require\(\s*['\"]stripe['\"]\s*\)|"
                r"from\s+['\"](?:stripe|@stripe/[\w-]+)['\"]|import\s+['\"]stripe['\"]", re.M), "stripe"),
    (re.compile(r"^\s*(?:import\s+mercadopago\b|from\s+mercadopago\b)|require\(\s*['\"]mercadopago['\"]\s*\)|"
                r"from\s+['\"](?:mercadopago|@mercadopago/[\w-]+)['\"]", re.M), "mercadopago"),
    (re.compile(r"^\s*(?:import\s+paypalrestsdk\b|from\s+paypal\w*\b)|require\(\s*['\"](?:@paypal/[\w-]+|paypal-[\w-]+)"
                r"['\"]\s*\)|from\s+['\"](?:@paypal/[\w-]+|paypal-[\w-]+)['\"]", re.M), "paypal"),
    (re.compile(r"^\s*(?:import\s+transbank\b|from\s+transbank\b)|require\(\s*['\"]transbank-sdk['\"]\s*\)|"
                r"from\s+['\"]transbank-sdk['\"]|\bWebpayPlus\b|webpay\.cl\b", re.M), "transbank"),
    (re.compile(r"\bflow\.cl/api\b|\bsandbox\.flow\.cl\b|\bFLOW_(?:API_KEY|SECRET_KEY)\b"), "flow"),
)
RE_RUTA_WEBHOOK = re.compile(r"""['"`][^'"`\n]*webhook[^'"`\n]*['"`]|(?:^|/)webhooks?(?:/|\.|$)""", re.I | re.M)
RE_PROVEEDOR_PAGO = (
    (re.compile(r"\bstripe\b|Stripe-Signature|checkout\.session\.|payment_intent\.", re.I), "stripe"),
    (re.compile(r"mercado\s*pago|x-signature.*mercadopago", re.I), "mercadopago"),
    (re.compile(r"\bpaypal\b|PAYPAL-TRANSMISSION", re.I), "paypal"),
    (re.compile(r"\bwebpay\b|\btransbank\b", re.I), "transbank"),
    (re.compile(r"\bflow\.cl\b", re.I), "flow"),
)
# Tipo de proyecto (detalle.tipo_proyecto) para que otros controles distingan web/servidor, SPA, móvil y CLI/librería.
RE_SCRIPTS_PY = re.compile(r"^\s*\[(?:project\.scripts|project\.gui-scripts|tool\.poetry\.scripts)\]", re.M)

RE_K8S_KIND = re.compile(r"^kind:\s*(Deployment|StatefulSet|DaemonSet|Service|Ingress|CronJob|Job|ConfigMap|"
                         r"Pod|HorizontalPodAutoscaler|Namespace|Secret)\b", re.MULTILINE)
RE_K8S_API = re.compile(r"^apiVersion:\s*\S+", re.MULTILINE)
RE_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalizar_py(nombre):
    return re.sub(r"[-_.]+", "-", nombre.strip().lower())


def leer_texto(ruta):
    try:
        with open(ruta, "rb") as f:
            return f.read(MAX_BYTES_LECTURA).decode("utf-8", errors="replace")
    except OSError:
        return ""


def nombre_req(linea):
    linea = linea.split("#", 1)[0].strip()
    if not linea or linea.startswith("-"):
        return None
    m = RE_REQ.match(linea)
    return normalizar_py(m.group(1)) if m else None


# Archivos de configuración de plataformas de despliegue (en la raíz o un nivel abajo). Ronda 3 (PV-R2-08):
# INF-INVENTARIO «Stack y plataforma de despliegue detectados» exige ≥ 1.
PLATAFORMAS_ARCHIVO = {
    "vercel.json": "vercel", "netlify.toml": "netlify", "fly.toml": "fly", "render.yaml": "render",
    "render.yml": "render", "railway.json": "railway", "railway.toml": "railway", "procfile": "heroku",
    "app.json": None, "app.yaml": "gcp-app-engine", "app.yml": "gcp-app-engine", "wrangler.toml": "cloudflare",
    "wrangler.json": "cloudflare", "wrangler.jsonc": "cloudflare", "amplify.yml": "aws-amplify",
    "serverless.yml": "serverless-framework", "serverless.yaml": "serverless-framework", "firebase.json": "firebase",
    "apprunner.yaml": "aws-app-runner", "appspec.yml": "aws-codedeploy", "zeabur.json": "zeabur",
    "nixpacks.toml": "nixpacks", "dokku.json": "dokku", "Procfile": "heroku", "staticwebapp.config.json": "azure-swa",
    "azure.yaml": "azure", "deno.json": None, ".platform.app.yaml": "platform.sh", "kamal.yml": None,
}


# Pasos de despliegue en workflows (`uses:`) y comandos de despliegue (en `run:` o en scripts de package.json): también
# son evidencia de la plataforma. Los comandos se leen con el análisis de shell de checks/workflows.py (un
# `echo "vercel deploy"` no cuenta).
PLATAFORMAS_ACCION = (
    (re.compile(r"^(amondnet/vercel-action|vercel/)", re.I), "vercel"),
    (re.compile(r"^(nwtgck/actions-netlify|netlify/actions)", re.I), "netlify"),
    (re.compile(r"^superfly/flyctl-actions", re.I), "fly"),
    (re.compile(r"^firebaseextended/action-hosting-deploy", re.I), "firebase"),
    (re.compile(r"^cloudflare/(wrangler-action|pages-action)", re.I), "cloudflare"),
    (re.compile(r"^(actions/deploy-pages|peaceiris/actions-gh-pages|jamesives/github-pages-deploy-action)", re.I),
     "github-pages"),
    (re.compile(r"^google-github-actions/deploy-", re.I), "gcp"),
    (re.compile(r"^aws-actions/(amazon-ecs-deploy|aws-cloudformation-github-deploy)", re.I), "aws"),
    (re.compile(r"^azure/(webapps-deploy|static-web-apps-deploy|functions-action)", re.I), "azure"),
    (re.compile(r"^akhileshns/heroku-deploy", re.I), "heroku"),
    (re.compile(r"^railwayapp/", re.I), "railway"),
)
PLATAFORMAS_CLI = {  # cli: (subcomandos o banderas que despliegan, plataforma)
    "vercel": ({"deploy", "--prod", "--prebuilt"}, "vercel"), "netlify": ({"deploy"}, "netlify"),
    "flyctl": ({"deploy"}, "fly"), "fly": ({"deploy"}, "fly"), "firebase": ({"deploy"}, "firebase"),
    "wrangler": ({"deploy", "publish", "pages"}, "cloudflare"), "railway": ({"up", "deploy"}, "railway"),
    "gcloud": ({"deploy"}, "gcp"), "amplify": ({"publish"}, "aws-amplify"),
    "serverless": ({"deploy"}, "serverless-framework"), "sls": ({"deploy"}, "serverless-framework"),
    "gh-pages": (None, "github-pages"), "surge": (None, "surge"), "sst": ({"deploy"}, "sst"),
}


def plataformas_en_comando(linea):
    """Plataformas que un comando de shell despliega de verdad (no dentro de un echo)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent / "checks"))
    import workflows  # noqa: E402
    res = set()
    for toks in workflows._comandos_simples(linea) or []:
        toks = workflows._sin_prefijos(toks)
        while toks and toks[0] in ("npx", "pnpx", "bunx", "pnpm", "yarn", "dlx", "exec", "--yes", "-y"):
            toks = toks[1:]
        if not toks:
            continue
        cli = toks[0].rsplit("/", 1)[-1]
        if cli in PLATAFORMAS_CLI:
            subs, plataforma = PLATAFORMAS_CLI[cli]
            if subs is None or any(t in subs for t in toks[1:]):
                res.add(plataforma)
    return res


class Detector:
    def __init__(self, raiz):
        self.raiz = Path(raiz).resolve()
        self.archivos = []          # rutas relativas (str, separador /)
        self.carpetas = set()       # rutas relativas de carpetas recorridas
        self.build = set()
        self.excluidos = set()
        self.truncado = False
        self.deps_node = {}         # dependencia -> [manifiestos]
        self.deps_py = {}
        self.evidencia = {}
        self.detalle = {}
        self.lenguajes = {}
        self.conteo = {}            # (clave, valor) -> nº de evidencias
        self.aportes = {}           # (clave, valor) -> archivos que lo aportan (valor None: bandera sin valor)
        self.evidencia_secundaria = {}

    # -- utilidades ---------------------------------------------------------
    def marcar(self, clave, archivo, valor=None):
        self.evidencia.setdefault(clave, set()).add(archivo)
        self.aportes.setdefault((clave, valor), set()).add(archivo)
        if valor:
            self.detalle.setdefault(clave, set()).add(valor)
            self.conteo[(clave, valor)] = self.conteo.get((clave, valor), 0) + 1

    def recorrer(self):
        for actual, dirs, files in os.walk(self.raiz, followlinks=False):
            rel_dir = os.path.relpath(actual, self.raiz)
            rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
            conservar = []
            for d in sorted(dirs):
                rel = f"{rel_dir}/{d}" if rel_dir else d
                if os.path.islink(os.path.join(actual, d)):
                    continue
                if d in EXCLUIDAS:
                    self.excluidos.add(rel)
                elif d in BUILD:
                    self.build.add(rel)
                else:
                    conservar.append(d)
                    self.carpetas.add(rel)
            dirs[:] = conservar
            for f in sorted(files):
                if os.path.islink(os.path.join(actual, f)):
                    continue
                if len(self.archivos) >= MAX_ARCHIVOS:
                    self.truncado = True
                    return
                self.archivos.append(f"{rel_dir}/{f}" if rel_dir else f)

    def ruta(self, rel):
        return self.raiz / rel

    # -- manifiestos --------------------------------------------------------
    def leer_manifiestos(self):
        for rel in self.archivos:
            nombre = rel.rsplit("/", 1)[-1]
            if nombre == "package.json":
                self._leer_package_json(rel)
            elif re.fullmatch(r"requirements.*\.(txt|in)", nombre):
                for linea in leer_texto(self.ruta(rel)).splitlines():
                    n = nombre_req(linea)
                    if n:
                        self.deps_py.setdefault(n, set()).add(rel)
            elif nombre in ("pyproject.toml", "Pipfile"):
                self._leer_toml_py(rel, nombre)

    def _leer_package_json(self, rel):
        try:
            datos = json.loads(leer_texto(self.ruta(rel)))
        except ValueError:
            return
        if not isinstance(datos, dict):
            return
        for campo in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps = datos.get(campo)
            if isinstance(deps, dict):
                for n in deps:
                    self.deps_node.setdefault(n, set()).add(rel)
        if rel == "package.json" and isinstance(datos.get("packageManager"), str):
            self.package_manager = datos["packageManager"].split("@", 1)[0]

    def _leer_toml_py(self, rel, nombre):
        try:
            datos = tomllib.loads(leer_texto(self.ruta(rel)))
        except (tomllib.TOMLDecodeError, ValueError):
            return
        nombres = []
        if nombre == "Pipfile":
            for sec in ("packages", "dev-packages"):
                nombres += list((datos.get(sec) or {}).keys())
        else:
            proyecto = datos.get("project") or {}
            nombres += [x for x in proyecto.get("dependencies") or [] if isinstance(x, str)]
            for lista in (proyecto.get("optional-dependencies") or {}).values():
                nombres += [x for x in lista if isinstance(x, str)]
            for lista in (datos.get("dependency-groups") or {}).values():
                nombres += [x for x in lista if isinstance(x, str)]
            poetry = (datos.get("tool") or {}).get("poetry") or {}
            if poetry:
                self.poetry = True
            nombres += list((poetry.get("dependencies") or {}).keys())
            for grupo in (poetry.get("group") or {}).values():
                nombres += list((grupo.get("dependencies") or {}).keys())
        for n in nombres:
            n = nombre_req(n)
            if n and n != "python":
                self.deps_py.setdefault(n, set()).add(rel)

    # -- mapeo de dependencias -----------------------------------------------
    def mapear(self, clave, mapa_node=None, mapa_py=None, prefijos_node=None, prefijos_py=None):
        encontrados = set()
        for dep, origenes in self.deps_node.items():
            valor = (mapa_node or {}).get(dep)
            if valor is None:
                for pref, v in (prefijos_node or {}).items():
                    if dep.startswith(pref):
                        valor = v
                        break
            if valor:
                encontrados.add(valor)
                for o in origenes:
                    self.marcar(clave, o, valor)
        for dep, origenes in self.deps_py.items():
            valor = (mapa_py or {}).get(dep)
            if valor is None:
                for pref, v in (prefijos_py or {}).items():
                    if dep.startswith(pref):
                        valor = v
                        break
            if valor:
                encontrados.add(valor)
                for o in origenes:
                    self.marcar(clave, o, valor)
        return encontrados

    # -- detección -----------------------------------------------------------
    def detectar(self):
        self.package_manager = None
        self.poetry = False
        self.recorrer()
        self.leer_manifiestos()

        for rel in self.archivos:
            ext = os.path.splitext(rel)[1].lower()
            if ext in EXTENSIONES:
                lang = EXTENSIONES[ext]
                self.lenguajes[lang] = self.lenguajes.get(lang, 0) + 1

        frameworks = self.mapear("frameworks", FRAMEWORKS_NODE, FRAMEWORKS_PY)
        orm = self.mapear("orm", ORM_NODE, ORM_PY)
        baas = self.mapear("baas", BAAS_NODE, BAAS_PY)
        ssr = self.mapear("ssr_serverless", SSR_NODE)
        llm = self.mapear("llm", LLM_NODE, LLM_PY, LLM_NODE_PREFIJOS, LLM_PY_PREFIJOS)
        pagos = self.mapear("pagos", PAGOS_NODE, PAGOS_PY, PAGOS_NODE_PREFIJOS)
        emails = self.mapear("emails", EMAILS_NODE, EMAILS_PY, EMAILS_NODE_PREFIJOS)
        movil = self.mapear("movil", MOVIL_NODE, None, MOVIL_NODE_PREFIJOS)
        pwa = self.mapear("pwa", PWA_NODE, None, PWA_NODE_PREFIJOS)
        i18n = self.mapear("multi_idioma", I18N_NODE, I18N_PY, I18N_NODE_PREFIJOS)
        servidor = self.mapear("servidor", SERVIDOR_NODE, SERVIDOR_PY)
        bd = self.mapear("bd", BD_NODE, BD_PY)
        docker, iac, k8s, agente, ci = set(), set(), set(), set(), set()
        plataformas = set()

        for rel in self.archivos:
            nombre = rel.rsplit("/", 1)[-1]
            partes = rel.split("/")
            bajo = nombre.lower()
            # frameworks por archivo de configuración
            if re.fullmatch(r"vite\.config\.(js|ts|mjs|mts|cjs)", nombre):
                frameworks.add("vite"); self.marcar("frameworks", rel, "vite")
            elif re.fullmatch(r"next\.config\.(js|ts|mjs|cjs)", nombre):
                frameworks.add("next"); ssr.add("next"); self.marcar("frameworks", rel, "next")
                self.marcar("ssr_serverless", rel, "next")
            elif nombre == "manage.py" and "django" in leer_texto(self.ruta(rel)).lower():
                frameworks.add("django"); self.marcar("frameworks", rel, "django")
            # ORM / BaaS por archivo
            if nombre == "schema.prisma":
                orm.add("prisma"); self.marcar("orm", rel, "prisma")
            elif re.fullmatch(r"drizzle\.config\.(js|ts|mjs)", nombre):
                orm.add("drizzle"); self.marcar("orm", rel, "drizzle")
            if rel == "supabase/config.toml" or (len(partes) >= 2 and partes[-2] == "supabase" and nombre == "config.toml"):
                baas.add("supabase"); self.marcar("baas", rel, "supabase")
            if nombre in ("firebase.json", ".firebaserc"):
                baas.add("firebase"); self.marcar("baas", rel, "firebase")
            # SSR / serverless por archivo
            for patron, valor in (("vercel.json", "vercel"), ("netlify.toml", "netlify"),
                                  ("serverless.yml", "serverless-framework"), ("wrangler.toml", "cloudflare-workers")):
                if nombre == patron:
                    ssr.add(valor); self.marcar("ssr_serverless", rel, valor)
            if re.search(r"(^|/)supabase/functions/", rel):
                ssr.add("supabase-edge-functions"); self.marcar("ssr_serverless", rel, "supabase-edge-functions")
            if "netlify" in partes[:-1] and "functions" in partes[:-1]:
                ssr.add("netlify-functions"); self.marcar("ssr_serverless", rel, "netlify-functions")
            # Plataforma de despliegue por archivo (ronda 3, INF-INVENTARIO)
            if len(partes) <= 2:
                plataforma = PLATAFORMAS_ARCHIVO.get(nombre) or PLATAFORMAS_ARCHIVO.get(bajo)
                if plataforma:
                    plataformas.add(plataforma); self.marcar("plataformas_despliegue", rel, plataforma)
            # Docker
            if nombre in ("Dockerfile", "Containerfile") or nombre.startswith("Dockerfile.") or bajo.endswith(".dockerfile") \
                    or re.fullmatch(r"(docker-)?compose([.-][\w.-]+)?\.ya?ml", bajo):
                docker.add("docker"); self.marcar("docker", rel)
            # IaC
            if bajo.endswith(".tf"):
                iac.add("terraform"); self.marcar("iac", rel, "terraform")
            elif nombre in ("Pulumi.yaml", "Pulumi.yml"):
                iac.add("pulumi"); self.marcar("iac", rel, "pulumi")
            elif nombre == "cdk.json":
                iac.add("cdk"); self.marcar("iac", rel, "cdk")
            elif bajo.endswith(".bicep"):
                iac.add("bicep"); self.marcar("iac", rel, "bicep")
            # YAML: k8s / cloudformation (excluye workflows y compose)
            if bajo.endswith((".yaml", ".yml")) and not rel.startswith(".github/") and "compose" not in bajo:
                if nombre == "Chart.yaml":
                    k8s.add("helm"); self.marcar("k8s", rel, "helm")
                elif nombre in ("kustomization.yaml", "kustomization.yml"):
                    k8s.add("kustomize"); self.marcar("k8s", rel, "kustomize")
                else:
                    texto = leer_texto(self.ruta(rel))
                    if RE_K8S_API.search(texto) and RE_K8S_KIND.search(texto):
                        k8s.add("manifiestos"); self.marcar("k8s", rel, "manifiestos")
                    elif "AWSTemplateFormatVersion" in texto or "AWS::Serverless" in texto:
                        iac.add("cloudformation"); self.marcar("iac", rel, "cloudformation")
            # BD por migraciones versionadas (.sql dentro de una carpeta de migraciones)
            if bajo.endswith(".sql") and any(rel.startswith(c + "/") or f"/{c}/" in rel for c in CARPETAS_MIGRACIONES):
                bd.add("migraciones-sql"); self.marcar("bd", rel, "migraciones-sql")
            # Móvil por archivo
            if re.fullmatch(r"capacitor\.config\.(ts|js|json)", nombre):
                movil.add("capacitor"); self.marcar("movil", rel, "capacitor")
            elif nombre == "app.json" and '"expo"' in leer_texto(self.ruta(rel)):
                movil.add("expo"); self.marcar("movil", rel, "expo")
            elif nombre == "pubspec.yaml" and "flutter:" in leer_texto(self.ruta(rel)):
                movil.add("flutter"); self.marcar("movil", rel, "flutter")
            # PWA por archivo
            if bajo.endswith(".webmanifest"):
                pwa.add("manifest"); self.marcar("pwa", rel, "manifest")
            elif nombre == "manifest.json":
                texto = leer_texto(self.ruta(rel))
                if '"start_url"' in texto or '"display"' in texto:
                    pwa.add("manifest"); self.marcar("pwa", rel, "manifest")
            elif nombre in ("sw.js", "service-worker.js", "sw.ts", "service-worker.ts"):
                pwa.add("service-worker"); self.marcar("pwa", rel, "service-worker")
            # Agentes IA
            if nombre in AGENTE_ARCHIVOS and (nombre != "copilot-instructions.md" or rel.startswith(".github/")):
                agente.add(AGENTE_ARCHIVOS[nombre]); self.marcar("agente_ia", rel, AGENTE_ARCHIVOS[nombre])
            for carpeta, valor in AGENTE_CARPETAS.items():
                if carpeta in partes[:-1]:
                    agente.add(valor); self.marcar("agente_ia", rel, valor)
            # CI
            if len(partes) >= 3 and partes[0] == ".github" and partes[1] == "workflows" and bajo.endswith((".yml", ".yaml")):
                ci.add("github_actions"); self.marcar("ci", rel, "github_actions")
            elif nombre in CI_ARCHIVOS and len(partes) == 1:
                ci.add(CI_ARCHIVOS[nombre]); self.marcar("ci", rel, CI_ARCHIVOS[nombre])
            elif rel == ".circleci/config.yml":
                ci.add("circleci"); self.marcar("ci", rel, "circleci")

        # Pagos por uso en el código (ronda 6): import del SDK o ruta webhook que nombra a un proveedor de pagos
        vistos_codigo = 0
        for rel in self.archivos:
            if os.path.splitext(rel)[1].lower() not in EXT_CODIGO_PAGOS:
                continue
            vistos_codigo += 1
            if vistos_codigo > MAX_ARCHIVOS_CODIGO:
                break
            texto = leer_texto(self.ruta(rel))
            for rx, valor in RE_PAGOS_IMPORT:
                if rx.search(texto):
                    pagos.add(valor); self.marcar("pagos", rel, valor)
            if RE_RUTA_WEBHOOK.search(texto) or RE_RUTA_WEBHOOK.search(rel):
                for rx, valor in RE_PROVEEDOR_PAGO:
                    if rx.search(texto):
                        pagos.add(valor); self.marcar("pagos", rel, valor)

        # Carpetas de agente vacías y de idiomas
        for rel in sorted(self.carpetas):
            nombre = rel.rsplit("/", 1)[-1]
            if nombre in AGENTE_CARPETAS:
                agente.add(AGENTE_CARPETAS[nombre]); self.marcar("agente_ia", rel, AGENTE_CARPETAS[nombre])
            if nombre in I18N_CARPETAS:
                i18n.add("carpeta-" + nombre); self.marcar("multi_idioma", rel, "carpeta-" + nombre)

        self._depurar_secundaria({
            "frameworks": frameworks, "orm": orm, "baas": baas, "ssr_serverless": ssr, "llm": llm, "pagos": pagos,
            "emails": emails, "movil": movil, "pwa": pwa, "multi_idioma": i18n, "servidor": servidor, "bd": bd,
            "docker": docker, "iac": iac, "k8s": k8s, "agente_ia": agente, "ci": ci, "plataformas_despliegue": plataformas})

        if "fastapi" in frameworks:
            frameworks.discard("starlette")
            self.detalle.get("frameworks", set()).discard("starlette")

        # BaaS: uno solo (el de más evidencia; empate → supabase)
        if baas:
            cuenta = {b: self.conteo.get(("baas", b), 0) for b in baas}
            baas_final = max(sorted(baas, key=lambda b: b != "supabase"), key=lambda b: cuenta[b])
        else:
            baas_final = "ninguno"

        # Servidor: backend propio, SSR/serverless, contenedor u orquestador. BD: driver/ORM, BaaS o migraciones.
        for valor, origen in (("ssr-serverless", ssr), ("docker", docker), ("k8s", k8s)):
            if origen:
                servidor.add(valor)
                self.detalle.setdefault("servidor", set()).add(valor)
        if orm:
            bd.add("orm"); self.detalle.setdefault("bd", set()).add("orm")
        if baas:
            bd.add("baas"); self.detalle.setdefault("bd", set()).add("baas")

        # Plataformas por pasos de despliegue en workflows y scripts de package.json
        for rel in self.archivos:
            partes = rel.split("/")
            if len(partes) == 3 and partes[0] == ".github" and partes[1] == "workflows" \
                    and rel.lower().endswith((".yml", ".yaml")):
                texto = leer_texto(self.ruta(rel))
                for m in re.finditer(r"^\s*(?:-\s+)?uses\s*:\s*['\"]?([^\s'\"#]+)", texto, re.M):
                    for rx, plataforma in PLATAFORMAS_ACCION:
                        if rx.search(m.group(1)):
                            plataformas.add(plataforma); self.marcar("plataformas_despliegue", rel, plataforma)
                sys.path.insert(0, str(Path(__file__).resolve().parent / "checks"))
                import workflows  # noqa: E402
                for _, comando in workflows.lineas_run(texto.splitlines()):
                    for plataforma in plataformas_en_comando(comando):
                        plataformas.add(plataforma); self.marcar("plataformas_despliegue", rel, plataforma)
            elif partes[-1] == "package.json" and len(partes) <= 2 and not comun.es_test_o_fixture(rel):
                try:
                    scripts = json.loads(leer_texto(self.ruta(rel)) or "{}").get("scripts") or {}
                except (json.JSONDecodeError, AttributeError):
                    scripts = {}
                for cuerpo in scripts.values() if isinstance(scripts, dict) else []:
                    for plataforma in plataformas_en_comando(str(cuerpo)):
                        plataformas.add(plataforma); self.marcar("plataformas_despliegue", rel, plataforma)

        # Plataformas también por dependencias serverless, contenedores, orquestadores e IaC
        for valor, plataforma in (("vercel", "vercel"), ("vercel-functions", "vercel"), ("netlify", "netlify"),
                                  ("netlify-functions", "netlify"), ("cloudflare-workers", "cloudflare"),
                                  ("serverless-framework", "serverless-framework"),
                                  ("supabase-edge-functions", "supabase-edge-functions")):
            if valor in ssr:
                plataformas.add(plataforma)
        if docker:
            plataformas.add("contenedor")
        if k8s:
            plataformas.add("kubernetes")
        for valor in iac:
            plataformas.add("iac-" + valor)

        tipo = self.tipo_proyecto(frameworks, servidor, movil)
        self.detalle_final = {
            "ssr_serverless": ssr, "llm": llm, "pagos": pagos, "emails": emails, "docker": docker,
            "iac": iac, "k8s": k8s, "movil": movil, "pwa": pwa, "multi_idioma": i18n, "agente_ia": agente,
            "ci": ci, "baas": baas, "servidor": servidor, "bd": bd, "tipo_proyecto": {tipo},
        }

        return {
            "version_esquema": "1",
            "generador": GENERADOR,
            "lenguajes": [l for l, _ in sorted(self.lenguajes.items(), key=lambda x: (-x[1], x[0]))],
            "frameworks": sorted(frameworks),
            "ecosistemas": self.ecosistemas(),
            "baas": baas_final,
            "orm": sorted(orm),
            "ssr_serverless": bool(ssr),
            "llm": bool(llm),
            "pagos": bool(pagos),
            "emails": bool(emails),
            "docker": bool(docker),
            "iac": bool(iac),
            "k8s": bool(k8s),
            "movil": bool(movil),
            "pwa": bool(pwa),
            "multi_idioma": bool(i18n),
            "agente_ia": bool(agente),
            "ci": bool(ci),
            "servidor": bool(servidor),
            "bd": bool(bd),
            "carpetas_build": sorted(self.build),
            "plataformas_despliegue": sorted(plataformas),
            "detalle": {k: sorted(v) for k, v in sorted(self.detalle_final.items())
                        if v and k not in ("docker",)},
            "evidencia": {k: sorted(v)[:MAX_EVIDENCIA] for k, v in sorted(self.evidencia.items()) if v},
            "evidencia_secundaria": {k: sorted(v)[:MAX_EVIDENCIA]
                                     for k, v in sorted(self.evidencia_secundaria.items()) if v},
            "limites": {
                "archivos_vistos": len(self.archivos),
                "truncado": self.truncado,
                "excluidos": sorted(self.excluidos)[:50],
            },
        }

    def tipo_proyecto(self, frameworks, servidor, movil):
        """Ronda 6 (stack): un valor de detalle.tipo_proyecto (el esquema de perfil_tecnico no admite claves nuevas en
        la raíz; detalle sí). movil (Expo/React Native/Capacitor/Flutter) > servidor-web (backend propio, SSR,
        contenedor) > spa (framework de front sin backend) > cli-python (pyproject con [project.scripts]) >
        libreria-python (paquete Python sin servidor ni scripts) > desconocido. Es una ESTIMACIÓN por archivos."""
        if movil:
            self.marcar("tipo_proyecto", sorted(self.evidencia.get("movil") or ["package.json"])[0], "movil")
            return "movil"
        if servidor:
            return "servidor-web"
        front = {"react", "vue", "svelte", "angular", "vite", "astro"}
        if frameworks & front:
            return "spa"
        if "python" in self.lenguajes and "pyproject.toml" in self.archivos:
            texto = leer_texto(self.ruta("pyproject.toml"))
            if RE_SCRIPTS_PY.search(texto):
                self.marcar("tipo_proyecto", "pyproject.toml", "cli-python")
                return "cli-python"
            if re.search(r"^\s*\[(?:project|tool\.poetry)\]", texto, re.M):
                self.marcar("tipo_proyecto", "pyproject.toml", "libreria-python")
                return "libreria-python"
        if "python" in self.lenguajes and ("setup.py" in self.archivos or "setup.cfg" in self.archivos):
            texto = leer_texto(self.ruta("setup.py")) + leer_texto(self.ruta("setup.cfg"))
            valor = "cli-python" if re.search(r"console_scripts|entry_points", texto) else "libreria-python"
            self.marcar("tipo_proyecto", "setup.py" if "setup.py" in self.archivos else "setup.cfg", valor)
            return valor
        return "desconocido"

    def _depurar_secundaria(self, conjuntos):
        """Quita de cada conjunto los valores que solo aportan archivos de test o fixtures y mueve esa evidencia a
        `evidencia_secundaria`. Un valor con al menos un archivo propio se conserva (con la evidencia propia)."""
        for clave, conjunto in conjuntos.items():
            for valor in sorted(conjunto):
                archivos = self.aportes.get((clave, valor)) or self.aportes.get((clave, None))
                if archivos and all(comun.es_test_o_fixture(a) for a in archivos):
                    conjunto.discard(valor)
                    self.detalle.get(clave, set()).discard(valor)
            secundarios = {a for a in self.evidencia.get(clave, set()) if comun.es_test_o_fixture(a)}
            if secundarios:
                self.evidencia[clave] -= secundarios
                self.evidencia_secundaria.setdefault(clave, set()).update(secundarios)

    def ecosistemas(self):
        eco = {}
        nombres = {}
        for rel in self.archivos:
            nombres.setdefault(rel.rsplit("/", 1)[-1], []).append(rel)

        manif_node = nombres.get("package.json", [])
        if manif_node:
            locks = sorted(r for n in LOCK_NODE for r in nombres.get(n, []))
            gestor = self.package_manager
            if not gestor:
                raiz_locks = [r for r in locks if "/" not in r] or locks
                gestor = LOCK_NODE[raiz_locks[0].rsplit("/", 1)[-1]] if raiz_locks else None
            eco["node"] = {"gestor": gestor, "manifiestos": sorted(manif_node), "lockfiles": locks}

        manif_py = sorted(r for n, rs in nombres.items() for r in rs
                          if n in ("pyproject.toml", "Pipfile", "setup.py", "setup.cfg")
                          or re.fullmatch(r"requirements.*\.(txt|in)", n))
        if manif_py:
            locks = sorted(r for n in LOCK_PY for r in nombres.get(n, []))
            gestor = None
            if locks:
                raiz_locks = [r for r in locks if "/" not in r] or locks
                gestor = LOCK_PY[raiz_locks[0].rsplit("/", 1)[-1]]
            elif self.poetry:
                gestor = "poetry"
            elif "Pipfile" in nombres:
                gestor = "pipenv"
            else:
                gestor = "pip"
            eco["python"] = {"gestor": gestor, "manifiestos": manif_py, "lockfiles": locks}

        for nombre_eco, (manifs, lks, gestor) in OTROS_ECOSISTEMAS.items():
            m = sorted(r for n in manifs for r in nombres.get(n, []))
            if m:
                eco[nombre_eco] = {"gestor": gestor, "manifiestos": m,
                                   "lockfiles": sorted(r for n in lks for r in nombres.get(n, []))}
        return eco


def detectar(ruta):
    """Devuelve el perfil técnico (dict) del proyecto en `ruta`."""
    return Detector(ruta).detectar()


def main(argv=None):
    p = argparse.ArgumentParser(description="Detecta el stack de un proyecto → perfil_tecnico.json")
    p.add_argument("ruta", help="carpeta del proyecto a auditar")
    p.add_argument("--salida", help="archivo de salida (por defecto, stdout)")
    args = p.parse_args(argv)

    raiz = Path(args.ruta)
    if not raiz.is_dir():
        print(f"detectar_stack: no es una carpeta: {raiz}", file=sys.stderr)
        return 2
    perfil = detectar(raiz)
    texto = json.dumps(perfil, ensure_ascii=False, indent=2) + "\n"
    if args.salida:
        destino = Path(args.salida)
        destino.parent.mkdir(parents=True, exist_ok=True)
        destino.write_text(texto, encoding="utf-8")
    else:
        sys.stdout.write(texto)
    return 0


if __name__ == "__main__":
    sys.exit(main())
