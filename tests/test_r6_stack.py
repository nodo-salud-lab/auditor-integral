"""Ronda 6 — grupo «stack»: sesgo web/JS y falsos positivos de checks (verificación real 2026-11-20).

Cada corrección tiene casos positivos (el defecto ya no aparece) y negativos (lo que sí es defecto sigue saliendo,
fail-closed: lo que deja de ser hallazgo queda visible con motivo y sin pase):
  1  SEG-ENV-EJEMPLO   constantes de Vite / NODE_ENV / variables del sistema y CLI Python sin entorno propio
  2  COD-REPRO         README con arranque de Python, make/just, cargo, go, docker compose; todos los README*
  3  SEG-LOCKFILE      librería/CLI Python sin dependencias de runtime; requirements.lock en detectar_stack
  4  OPS-HEALTH        rutas de salud en español y comunes
  5  migraciones_sql   dialecto SQLite: sin reglas propias de PostgreSQL; reconstrucción de tabla
  6  rls_estatico      RLS activado en bloque DO dinámico; RLS sin políticas = deny-all (informativo)
  7  rutas_inventario  ruta_admin_sin_auth (alta) y entorno_expuesto (media); auth global evita el hallazgo
  8  detectar_stack    pagos por import/webhook en código; tipo_proyecto (móvil, CLI, librería, SPA, servidor)
  9  tipos             tsconfig.json en subpaquetes de un monorepo
  10 ux_estatico       input en componente reutilizable envuelto por <label> donde se usa; <Select> no es campo
  +  workflows         `npm test` cuyo script corre archivos *.test.mjs cuenta como tests (COD-CI-BASICO)
"""
import json
import secrets
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402
TMP_BASE.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "scripts"))

import archivos_clave  # noqa: E402
import detectar_stack  # noqa: E402
import migraciones_sql  # noqa: E402
import rls_estatico  # noqa: E402
import rutas_inventario  # noqa: E402
import tipos  # noqa: E402
import ux_estatico  # noqa: E402
import workflows  # noqa: E402
import validar_schema as vs  # noqa: E402

SCHEMA_TEC = vs.subschema(json.loads((RAIZ / "schemas" / "perfil.schema.json").read_text()), "perfil_tecnico")


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = TMP_BASE / f"r6s_{self.id().split('.')[-1]}_{secrets.token_hex(3)}"
        self.dir.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def escribir(self, rel, texto):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(texto, encoding="utf-8")
        return p

    @staticmethod
    def subs(res):
        return [h["regla"].split(".", 1)[1] for h in res["hallazgos"]]

    @staticmethod
    def pases(res):
        return [p["regla"].split(".", 1)[1] for p in res["checks_pass"]]


# ------------------------------------------------------------------------------------------- 1 SEG-ENV-EJEMPLO
class TestEnvEjemplo(Base):
    def test_constantes_vite_no_exigen_ejemplo(self):
        self.escribir("src/main.js", "if (import.meta.env.PROD) registrar();\nconst m = import.meta.env.MODE;\n"
                                     "const b = import.meta.env.BASE_URL; if (process.env.NODE_ENV === 'x') {}\n")
        res = archivos_clave.analizar(self.dir)
        self.assertNotIn("env_ejemplo_ausente", self.subs(res))
        self.assertNotIn("env_ejemplo", self.pases(res))  # sin pase: queda visible en no_requerido
        self.assertIn("env_ejemplo_no_requerido", res["no_requerido"])

    def test_cli_python_con_variables_del_sistema(self):
        self.escribir("src/cli.py", "import os\nxdg = os.environ.get('XDG_CONFIG_HOME')\ned = os.environ.get('EDITOR')\n"
                                    "for v in ('LC_ALL', 'LANG'):\n    os.environ.get(v)\n")
        res = archivos_clave.analizar(self.dir)
        self.assertNotIn("env_ejemplo_ausente", self.subs(res))
        self.assertIn("src/cli.py", res["no_requerido"]["env_ejemplo_no_requerido"])  # lectura dinámica visible

    def test_variables_de_tests_no_cuentan(self):
        self.escribir("app/test/e2e/medir.mjs", "const t = process.env.TASAS;\n")
        self.assertNotIn("env_ejemplo_ausente", self.subs(archivos_clave.analizar(self.dir)))

    def test_variable_propia_si_exige_ejemplo(self):
        self.escribir("src/api.js", "const url = import.meta.env.VITE_API_URL;\n")
        res = archivos_clave.analizar(self.dir)
        self.assertIn("env_ejemplo_ausente", self.subs(res))
        self.assertNotIn("env_ejemplo_no_requerido", res.get("no_requerido", {}))

    def test_desestructuracion_y_dotenv_exigen_ejemplo(self):
        self.escribir("a.js", "const { STRIPE_KEY } = process.env;\n")
        self.assertIn("env_ejemplo_ausente", self.subs(archivos_clave.analizar(self.dir)))
        (self.dir / "a.js").unlink()
        self.escribir("cfg.py", "from dotenv import load_dotenv\nload_dotenv()\n")
        self.assertIn("env_ejemplo_ausente", self.subs(archivos_clave.analizar(self.dir)))

    def test_env_real_exige_ejemplo(self):
        self.escribir(".env", "FOO=bar\n")
        self.assertIn("env_ejemplo_ausente", self.subs(archivos_clave.analizar(self.dir)))


# ------------------------------------------------------------------------------------------------ 2 COD-REPRO
class TestReadme(Base):
    def test_comandos_python_y_otros(self):
        for texto in ("pipx install git+https://x/y", "uv sync", "poetry install", "python -m mi_paquete",
                      "```\nmake dev\n```", "    pytest -q", "cargo run", "go run .", "docker compose up",
                      "`just test`"):
            with self.subTest(texto=texto):
                self.assertTrue(archivos_clave.hay_arranque(texto))

    def test_prosa_no_es_arranque(self):
        for texto in ("Make sure it works.", "Just a moment.", "We use pytest heavily.", "Instalar y usar."):
            with self.subTest(texto=texto):
                self.assertFalse(archivos_clave.hay_arranque(texto))

    def test_cualquier_readme_de_la_raiz(self):
        self.escribir("README.es.md", "# Proyecto\nDescripción sin comandos.\n")
        self.escribir("README.md", "# Project\n\n```\npipx install git+https://x/y\n```\n")
        res = archivos_clave.analizar(self.dir)
        self.assertNotIn("readme_sin_arranque", self.subs(res))
        self.assertIn("readme", self.pases(res))

    def test_readme_sin_comandos_sigue_fallando(self):
        self.escribir("README.md", "# Proyecto\nSolo una descripción.\n")
        self.assertIn("readme_sin_arranque", self.subs(archivos_clave.analizar(self.dir)))


# --------------------------------------------------------------------------------------------- 3 SEG-LOCKFILE
class TestLockfile(Base):
    def test_cli_python_sin_dependencias(self):
        self.escribir("pyproject.toml", "[project]\nname='x'\ndependencies = []\n[project.optional-dependencies]\n"
                                        "dev = ['pytest']\n[project.scripts]\nx = 'x:main'\n")
        res = archivos_clave.analizar(self.dir)
        self.assertNotIn("lockfile_ausente", self.subs(res))
        self.assertNotIn("lockfile", self.pases(res))
        self.assertIn("lockfile_no_requerido", res["no_requerido"])

    def test_con_dependencias_exige_lockfile(self):
        self.escribir("pyproject.toml", "[project]\nname='x'\ndependencies = ['requests>=2']\n")
        self.assertIn("lockfile_ausente", self.subs(archivos_clave.analizar(self.dir)))

    def test_dependencias_dinamicas_o_requirements_exigen_lockfile(self):
        self.escribir("pyproject.toml", "[project]\nname='x'\ndynamic = ['dependencies']\n")
        self.assertIn("lockfile_ausente", self.subs(archivos_clave.analizar(self.dir)))
        self.escribir("pyproject.toml", "[project]\nname='x'\ndependencies = []\n")
        self.escribir("requirements.txt", "flask\n")
        self.assertIn("lockfile_ausente", self.subs(archivos_clave.analizar(self.dir)))

    def test_package_json_sigue_exigiendo(self):
        self.escribir("package.json", '{"name": "x"}')
        self.assertIn("lockfile_ausente", self.subs(archivos_clave.analizar(self.dir)))

    def test_detectar_stack_reconoce_requirements_lock(self):
        self.escribir("pyproject.toml", "[project]\nname='x'\ndependencies=['a']\n")
        self.escribir("requirements.lock", "a==1.0\n")
        perfil = detectar_stack.detectar(self.dir)
        self.assertEqual(perfil["ecosistemas"]["python"]["lockfiles"], ["requirements.lock"])


# ---------------------------------------------------------------------------------------------- 4 OPS-HEALTH
class TestHealth(Base):
    def test_rutas_en_espanol_y_comunes(self):
        for ruta in ("/salud", "/estado", "/status", "/healthz", "/livez", "/readyz", "/ping"):
            with self.subTest(ruta=ruta):
                self.escribir("server/app.js", f"import Fastify from 'fastify';\nconst app = fastify();\n"
                                               f"app.get('{ruta}', async () => ({{ ok: true }}));\n")
                self.escribir("package.json", '{"dependencies": {"fastify": "5"}}')
                res = archivos_clave.analizar(self.dir)
                self.assertIn("health", self.pases(res))
                self.assertNotIn("health_ausente", self.subs(res))

    def test_servidor_sin_ruta_de_salud(self):
        self.escribir("package.json", '{"dependencies": {"express": "4"}}')
        self.escribir("server.js", "const express = require('express');\nconst app = express();\n"
                                   "app.get('/usuarios', h);\n")
        self.assertIn("health_ausente", self.subs(archivos_clave.analizar(self.dir)))

    def test_cli_o_spa_sin_servidor_no_exige(self):
        self.escribir("src/main.jsx", "export default function App() { return null }\n")
        self.escribir("package.json", '{"dependencies": {"react": "18", "vite": "5"}}')
        res = archivos_clave.analizar(self.dir)
        self.assertNotIn("health_ausente", self.subs(res))
        self.assertFalse(detectar_stack.detectar(self.dir)["servidor"])


# ------------------------------------------------------------------------------------------ 5 migraciones_sql
SQL_SQLITE = ("CREATE TABLE alertas_nueva (id INTEGER PRIMARY KEY, nivel TEXT);\n"
              "INSERT INTO alertas_nueva (id, nivel) SELECT id, nivel FROM alertas;\n"
              "DROP TABLE alertas;\nALTER TABLE alertas_nueva RENAME TO alertas;\n"
              "CREATE INDEX alertas_nivel ON alertas (nivel);\nALTER TABLE lecturas ADD COLUMN fase TEXT;\n")


class TestMigracionesDialecto(Base):
    def test_sqlite_por_manifiesto(self):
        self.escribir("server/package.json", '{"description": "API y SQLite", "dependencies": {"better-sqlite3": "12"}}')
        self.escribir("server/migrations/006.sql", SQL_SQLITE)
        res = migraciones_sql.analizar(self.dir)
        # DECISIONES #12 (adenda 2): la reconstrucción omitida queda visible como info (reconstruccion_sqlite).
        self.assertEqual(self.subs(res), ["reconstruccion_sqlite"])
        self.assertEqual(res["dialectos"]["server/migrations/006.sql"]["dialecto"], "sqlite")
        self.assertEqual(sorted(o["regla"].split(".")[-1] for o in res["omitidos"]), ["drop_table", "rename"])
        self.assertEqual(self.pases(res), [])  # hubo omisiones: sin pase

    def test_sqlite_por_sintaxis(self):
        self.escribir("migrations/1.sql", "CREATE TABLE u (id INTEGER PRIMARY KEY AUTOINCREMENT);\n"
                                          "CREATE INDEX u_i ON v (x);\n")
        res = migraciones_sql.analizar(self.dir)
        self.assertNotIn("index_sin_concurrently", self.subs(res))
        self.assertNotIn("tipo_serial_int", self.subs(res))

    def test_sqlite_destruccion_real_sigue(self):
        self.escribir("package.json", '{"dependencies": {"better-sqlite3": "12"}}')
        self.escribir("migrations/1.sql", "DROP TABLE pacientes;\nALTER TABLE x DROP COLUMN y;\n")
        self.assertEqual(sorted(self.subs(migraciones_sql.analizar(self.dir))), ["drop_column", "drop_table"])

    def test_postgres_mantiene_reglas(self):
        self.escribir("package.json", '{"dependencies": {"pg": "8"}}')
        self.escribir("migrations/1.sql", SQL_SQLITE)
        subs = self.subs(migraciones_sql.analizar(self.dir))
        self.assertIn("index_sin_concurrently", subs)
        self.assertIn("drop_table", subs)

    def test_sin_senales_aplica_postgres(self):
        self.escribir("migrations/1.sql", "CREATE INDEX i ON t (x);\n")
        res = migraciones_sql.analizar(self.dir)
        self.assertIn("index_sin_concurrently", self.subs(res))
        self.assertEqual(res["dialectos"]["migrations/1.sql"]["dialecto"], "desconocido")

    def test_ambos_motores_aplica_postgres(self):
        self.escribir("package.json", '{"dependencies": {"pg": "8", "better-sqlite3": "12"}}')
        self.escribir("migrations/1.sql", "CREATE INDEX i ON t (x);\n")
        self.assertIn("index_sin_concurrently", self.subs(migraciones_sql.analizar(self.dir)))

    def test_supabase_siempre_postgres(self):
        self.escribir("package.json", '{"dependencies": {"better-sqlite3": "12"}}')
        self.escribir("supabase/migrations/1.sql", "CREATE INDEX i ON t (x);\n")
        self.assertIn("index_sin_concurrently", self.subs(migraciones_sql.analizar(self.dir)))


# --------------------------------------------------------------------------------------------- 6 rls_estatico
DO_ESQUEMA = """do $$
declare t text;
begin
  for t in select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
           where n.nspname = 'public' and c.relkind = 'r'
  loop
    execute format('alter table public.%I enable row level security', t);
  end loop;
end $$;
"""


class TestRlsDinamico(Base):
    def test_do_por_esquema_activa_rls(self):
        self.escribir("supabase/migrations/1.sql", "create table public.a (id int primary key);\n"
                                                   "create table public.b (id int primary key);\n" + DO_ESQUEMA +
                      "create policy p on public.a for select using (auth.uid() = id);\n"
                      "create policy q on public.b for select using (auth.uid() = id);\n")
        res = rls_estatico.analizar(self.dir)
        self.assertNotIn("rls_deshabilitado", self.subs(res))
        self.assertEqual(res["rls_dinamico"][0]["tablas"], 2)

    def test_tabla_creada_despues_del_do_sigue_sin_rls(self):
        self.escribir("supabase/migrations/1.sql", "create table public.a (id int primary key);\n" + DO_ESQUEMA +
                      "create table public.tarde (id int primary key);\n")
        res = rls_estatico.analizar(self.dir)
        self.assertEqual([h["evidencia"] for h in res["hallazgos"] if "rls_deshabilitado" in h["regla"]],
                         ["public.tarde"])

    def test_do_con_array_y_politicas_dinamicas(self):
        self.escribir("supabase/migrations/1.sql", "create table public.a (id int primary key);\n"
                      "do $$ declare t text; begin foreach t in array array['a'] loop\n"
                      "execute format('alter table public.%I enable row level security', t);\n"
                      "execute format('create policy %1$s_sel on public.%1$I for select using (true)', t);\n"
                      "end loop; end $$;\n")
        res = rls_estatico.analizar(self.dir)
        self.assertEqual(self.subs(res), [])
        self.assertNotIn("informativos", res)

    def test_do_no_resuelto_no_evaluado_nunca_fail(self):
        self.escribir("supabase/migrations/1.sql", "create table public.a (id int primary key);\n"
                      "do $$ declare t text; begin for t in select tablename from pg_tables where schemaname = 'public'"
                      " and tablename like 'x%' loop\n"
                      "execute format('alter table public.%I enable row level security', t);\n"
                      "end loop; end $$;\n")
        res = rls_estatico.analizar(self.dir)
        self.assertNotIn("rls_deshabilitado", self.subs(res))
        self.assertEqual(res["rls_dinamico_no_resuelto"][0]["tabla"], "public.a")
        self.assertIn("no evaluado", res["motivo"])
        self.assertEqual(self.pases(res), [])

    def test_sin_do_sigue_fallando(self):
        self.escribir("supabase/migrations/1.sql", "create table public.a (id int primary key);\n")
        self.assertIn("rls_deshabilitado", self.subs(rls_estatico.analizar(self.dir)))

    def test_rls_sin_politicas_es_deny_all(self):
        self.escribir("supabase/migrations/1.sql", "create table public.a (id int primary key);\n"
                                                   "alter table public.a enable row level security;\n")
        res = rls_estatico.analizar(self.dir)
        # DECISIONES #12 (adenda 2): además es hallazgo info rls_sin_politicas (→ DAT-RLS-DENY-ALL, no PERMISIVA).
        self.assertEqual(self.subs(res), ["rls_sin_politicas"])
        self.assertEqual(res["informativos"][0]["severidad"], "info")
        self.assertEqual(self.pases(res), [])

    def test_politica_true_sigue_siendo_critica(self):
        self.escribir("supabase/migrations/1.sql", "create table public.a (id int primary key);\n"
                      "alter table public.a enable row level security;\n"
                      "create policy p on public.a for insert with check (true);\n")
        self.assertIn("politica_siempre_true", self.subs(rls_estatico.analizar(self.dir)))


# ----------------------------------------------------------------------------------------- 7 rutas_inventario
class TestRutasHallazgos(Base):
    def test_admin_sin_auth_alta(self):
        self.escribir("server/routes/admin.js", "const router = require('express').Router();\n"
                      "router.get('/users', async (req, res) => { res.json([]) });\n")
        res = rutas_inventario.analizar(self.dir)
        hs = [h for h in res["hallazgos"] if h["regla"].endswith("ruta_admin_sin_auth")]
        self.assertEqual(len(hs), 1)
        self.assertEqual(hs[0]["severidad_sugerida"], "alta")
        self.assertEqual(res["checks_pass"], [])

    def test_debug_y_entorno_expuesto(self):
        self.escribir("pages/api/debug.js", "export default function handler(req, res) {\n"
                      "  res.status(200).json({ env: process.env });\n}\n")
        subs = sorted(self.subs(rutas_inventario.analizar(self.dir)))
        self.assertEqual(subs, ["entorno_expuesto", "ruta_admin_sin_auth"])
        sev = {h["regla"].split(".")[-1]: h["severidad_sugerida"] for h in rutas_inventario.analizar(self.dir)["hallazgos"]}
        self.assertEqual(sev["entorno_expuesto"], "media")

    def test_variable_concreta_no_es_entorno_expuesto(self):
        self.escribir("pages/api/info.js", "export default function handler(req, res) {\n"
                      "  res.json({ v: process.env.APP_VERSION });\n}\n")
        self.escribir("tools/run.py", "import os, subprocess\nsubprocess.run(['x'], env={**os.environ})\n")
        self.assertNotIn("entorno_expuesto", self.subs(rutas_inventario.analizar(self.dir)))

    def test_auth_global_evita_hallazgo(self):
        self.escribir("server/app.js", "const app = require('express')();\napp.use('/api/admin', requireAdmin, adminRoutes);\n")
        self.escribir("server/routes/admin.js", "const router = require('express').Router();\n"
                      "router.get('/users', async (req, res) => { res.json([]) });\n")
        res = rutas_inventario.analizar(self.dir)
        self.assertNotIn("ruta_admin_sin_auth", self.subs(res))
        self.assertTrue(res["resumen"]["auth_global"])

    def test_auth_en_otro_router_no_protege_admin(self):
        self.escribir("server/routes/billing.js", "const router = require('express').Router();\nrouter.use(requireUser);\n")
        self.escribir("server/routes/admin.js", "const router = require('express').Router();\n"
                      "router.get('/users', async (req, res) => { res.json([]) });\n")
        self.assertIn("ruta_admin_sin_auth", self.subs(rutas_inventario.analizar(self.dir)))

    def test_flask_before_request_y_handler_con_auth(self):
        self.escribir("app/admin.py", "from flask import Blueprint, abort\nbp = Blueprint('admin', __name__)\n"
                      "@bp.before_request\ndef chequeo():\n    if not current_user.is_admin:\n        abort(403)\n\n"
                      "@bp.route('/admin/users')\ndef users():\n    return []\n")
        self.escribir("pages/api/admin/users.js", "export default async function handler(req, res) {\n"
                      "  const admin = await requireAdmin(req, res);\n  if (!admin) return;\n  res.json([]);\n}\n")
        self.assertEqual(self.subs(rutas_inventario.analizar(self.dir)), [])


# ------------------------------------------------------------------------------------------ 8 detectar_stack
class TestDetectarStack(Base):
    def test_pagos_por_webhook_sin_sdk(self):
        self.escribir("requirements.txt", "flask\n")
        self.escribir("app/routes/payments.py", "@bp.route('/webhook', methods=['POST'])\ndef stripe_webhook():\n"
                      "    if event.get('type') == 'checkout.session.completed':\n        pass\n")
        perfil = detectar_stack.detectar(self.dir)
        self.assertTrue(perfil["pagos"])
        self.assertIn("app/routes/payments.py", perfil["evidencia"]["pagos"])
        self.assertEqual(vs.validar(perfil, SCHEMA_TEC), [])

    def test_pagos_por_import(self):
        self.escribir("src/pago.js", "import { WebpayPlus } from 'transbank-sdk';\n")
        self.assertEqual(detectar_stack.detectar(self.dir)["detalle"]["pagos"], ["transbank"])

    def test_sin_pagos_y_webhook_ajeno(self):
        self.escribir("src/hook.js", "app.post('/webhook/github', h); // stripes de colores\n")
        self.escribir("tests/test_pago.py", "import stripe\n")  # solo en tests: no enciende la bandera
        perfil = detectar_stack.detectar(self.dir)
        self.assertFalse(perfil["pagos"])

    def test_tipo_proyecto(self):
        casos = {
            "cli-python": {"pyproject.toml": "[project]\nname='x'\n[project.scripts]\nx='x:main'\n", "x.py": ""},
            "libreria-python": {"pyproject.toml": "[project]\nname='x'\n", "x.py": ""},
            "movil": {"app.json": '{"expo": {"name": "x"}}', "package.json": '{"dependencies": {"react-native": "1"}}'},
            "spa": {"package.json": '{"dependencies": {"react": "18", "vite": "5"}}'},
            "servidor-web": {"package.json": '{"dependencies": {"express": "4"}}'},
        }
        for esperado, archivos in casos.items():
            with self.subTest(tipo=esperado):
                d = self.dir / esperado
                for rel, texto in archivos.items():
                    (d / rel).parent.mkdir(parents=True, exist_ok=True)
                    (d / rel).write_text(texto, encoding="utf-8")
                perfil = detectar_stack.detectar(d)
                self.assertEqual(perfil["detalle"]["tipo_proyecto"], [esperado])
                self.assertEqual(vs.validar(perfil, SCHEMA_TEC), [])


# -------------------------------------------------------------------------------------------------- 9 tipos
class TestTiposMonorepo(Base):
    def test_tsconfig_en_subpaquetes(self):
        self.escribir("packages/core/tsconfig.json", "{}")
        self.escribir("apps/web/tsconfig.json", "{}")
        self.escribir("node_modules/x/tsconfig.json", "{}")
        self.assertEqual(tipos._configs(self.dir), ["apps/web/tsconfig.json", "packages/core/tsconfig.json"])
        res = tipos.analizar(self.dir, tsc="")
        self.assertEqual(res["estado"], "no_evaluado")
        self.assertNotIn("sin tsconfig", res["motivo"])  # el motivo ahora es la falta de un tsc confiable

    def test_sin_ningun_tsconfig(self):
        self.escribir("src/a.ts", "export const a = 1\n")
        res = tipos.analizar(self.dir, tsc="")
        self.assertEqual(res["estado"], "no_evaluado")
        self.assertIn("sin tsconfig.json", res["motivo"])

    @unittest.skipUnless(shutil.which("sh"), "requiere sh")
    def test_subpaquetes_se_pasan_a_tsc(self):
        self.escribir("packages/core/tsconfig.json", "{}")
        self.escribir("packages/core/a.ts", "export const a = 1\n")
        falso = TMP_BASE / f"tsc_falso_{secrets.token_hex(3)}"
        falso.write_text("#!/bin/sh\necho \"$PWD/packages/core/a.ts\"\nexit 0\n", encoding="utf-8")
        falso.chmod(0o755)
        self.addCleanup(falso.unlink)
        res = tipos.analizar(self.dir, tsc=str(falso))
        self.assertEqual(self.pases(res), ["sin_errores"])
        self.assertIn("packages/core/tsconfig.json", res["checks_pass"][0]["mensaje"])


# --------------------------------------------------------------------------------------------- 10 ux_estatico
NUMERO = ("function Numero({ valor }) {\n  return (\n    <input type=\"text\" value={valor} />\n  );\n}\n"
          "export function Panel() {\n  return (<div>\n")


class TestUxFormularios(Base):
    def test_componente_envuelto_en_label_donde_se_usa(self):
        self.escribir("src/Medir.jsx", NUMERO + "<label>Masa<Numero valor={1} /></label>\n"
                      "<label>Brazo<Numero valor={2} /></label>\n</div>);\n}\n")
        res = ux_estatico.analizar(self.dir)
        self.assertNotIn("input_sin_label", self.subs(res))
        self.assertEqual(res["no_juzgados"][0]["componente"], "Numero")
        self.assertNotIn("input_label", self.pases(res))

    def test_uso_mixto_baja_a_media(self):
        self.escribir("src/Medir.jsx", NUMERO + "<label>Masa<Numero valor={1} /></label>\n<Numero valor={2} />\n"
                      "</div>);\n}\n")
        hs = [h for h in ux_estatico.analizar(self.dir)["hallazgos"] if h["regla"].endswith("input_sin_label")]
        self.assertEqual([h["severidad_sugerida"] for h in hs], ["media"])

    def test_sin_label_en_ningun_uso_sigue_alta(self):
        self.escribir("src/Login.jsx", "export function Login() {\n  return (<form>\n"
                      "<input type=\"email\" value={e} />\n</form>);\n}\n")
        self.escribir("src/App.jsx", "export function App() { return <Login /> }\n")
        hs = [h for h in ux_estatico.analizar(self.dir)["hallazgos"] if h["regla"].endswith("input_sin_label")]
        self.assertEqual([h["severidad_sugerida"] for h in hs], ["alta"])

    def test_componente_select_y_id_dinamico(self):
        self.escribir("src/Form.tsx", "function Campo({ label }) {\n  const id = useId()\n  return (<div>\n"
                      "<label htmlFor={id}>{label}</label>\n<select id={id}><option /></select>\n</div>)\n}\n"
                      "export function Form() { return <Select label=\"Tipo\" value={v} /> }\n")
        self.assertNotIn("input_sin_label", self.subs(ux_estatico.analizar(self.dir)))

    def test_html_sigue_igual(self):
        self.escribir("index.html", "<html lang=\"es\"><head><meta name=\"viewport\" content=\"width=device-width\">"
                      "</head><body><INPUT type=\"text\"></body></html>\n")
        self.assertIn("input_sin_label", self.subs(ux_estatico.analizar(self.dir)))


# ------------------------------------------------------------------------------------ workflows (COD-CI-BASICO)
class TestWorkflowsArchivoTest(Base):
    def test_script_que_corre_archivos_de_test(self):
        self.escribir("app/package.json", json.dumps({"scripts": {
            "test": "node test/dsp.test.mjs && node test/emg.test.mjs"}}))
        self.escribir(".github/workflows/ci.yml", "on: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
                      "    defaults:\n      run:\n        working-directory: app\n    steps:\n"
                      "      - run: npm ci\n      - run: npm test\n")
        self.assertTrue(workflows.calidad_ci(self.dir)[0])

    def test_nombres_que_solo_contienen_test_no_cuentan(self):
        for archivo in ("generate-test-fixtures.js", "scripts/deploy-test.js", "test-data.json"):
            with self.subTest(archivo=archivo):
                self.assertFalse(workflows.es_calidad(["node", archivo]))
        self.assertTrue(workflows.es_calidad(["python", "tests/test_api.py"]))


# --------------------------------------------------------------------------------- CLI de los checks (contrato)
class TestContratoCli(Base):
    def test_checks_escriben_json_valido(self):
        self.escribir("pages/api/debug.js", "export default function h(req, res) { res.json({ env: process.env }) }\n")
        crudo = self.dir.parent / f"crudo_{secrets.token_hex(3)}"
        crudo.mkdir()
        self.addCleanup(shutil.rmtree, crudo, ignore_errors=True)
        for script in ("archivos_clave.py", "rutas_inventario.py", "migraciones_sql.py", "rls_estatico.py",
                       "ux_estatico.py"):
            with self.subTest(script=script):
                r = subprocess.run([sys.executable, "-I", str(RAIZ / "scripts" / "checks" / script), str(self.dir),
                                    str(crudo)], capture_output=True, text=True, timeout=120)
                self.assertEqual(r.returncode, 0, r.stderr)
        datos = json.loads((crudo / "check_rutas_inventario.json").read_text(encoding="utf-8"))
        self.assertIn("check:rutas_inventario.entorno_expuesto", [h["regla"] for h in datos["hallazgos"]])


if __name__ == "__main__":
    unittest.main()
