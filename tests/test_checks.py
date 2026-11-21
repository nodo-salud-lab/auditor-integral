"""Tests de los chequeos propios de scripts/checks/ (env_publicas, registro_deps, archivos_clave,
config_agentes). Fixtures pequeñas creadas al vuelo; los secretos son canarios generados al azar."""
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
CHECKS = RAIZ / "scripts" / "checks"
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
TMP_BASE.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(CHECKS))

import archivos_clave  # noqa: E402
import config_agentes  # noqa: E402
import env_publicas  # noqa: E402
import registro_deps  # noqa: E402


def azar(n, alfabeto=string.ascii_letters + string.digits):
    return "".join(secrets.choice(alfabeto) for _ in range(n))


def jwt_canario(rol):
    """JWT falso (firma al azar) con el rol indicado: solo sirve para probar la detección."""
    import base64

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'iss': 'supabase', 'role': rol})}.{azar(43)}"


class BaseFixture(unittest.TestCase):
    def setUp(self):
        self.dir = TMP_BASE / f"checks_{self.id().split('.')[-1]}_{azar(6)}"
        self.dir.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def escribir(self, rel, texto):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(texto, encoding="utf-8")
        return p

    def reglas(self, resultado):
        return [h["regla"] for h in resultado["hallazgos"]]

    def validar_forma(self, resultado, nombre):
        self.assertIn(resultado["estado"], ("ok", "no_evaluado", "error"))
        for h in resultado["hallazgos"]:
            self.assertEqual(set(h), {"regla", "archivo", "linea", "mensaje", "evidencia", "severidad_sugerida"}, h)
            self.assertTrue(h["regla"].startswith(f"check:{nombre}."), h["regla"])
            self.assertIn(h["severidad_sugerida"], ("critica", "alta", "media", "baja", "info"))
            self.assertLessEqual(len(h["evidencia"]), 300)
        for p in resultado["checks_pass"]:
            self.assertTrue(p["regla"].startswith(f"check:{nombre}."), p)


# ----------------------------------------------------------------------------- env_publicas

class TestEnvPublicas(BaseFixture):
    def test_nombres_sensibles_y_publicos(self):
        clave = "sk-" + azar(40)
        self.escribir(".env", "\n".join([
            "VITE_APP_NOMBRE=Demo",                       # 1 no sensible
            "VITE_SUPABASE_URL=https://x.supabase.co",    # 2 URL pública
            "VITE_SUPABASE_ANON_KEY=sb_publishable_" + azar(20),  # 3 pública por diseño
            "VITE_STRIPE_PUBLISHABLE_KEY=pk_live_" + azar(24),    # 4 pública por diseño
            f"VITE_OPENAI_API_KEY={clave}",               # 5 sensible
            "NEXT_PUBLIC_STRIPE_SECRET_KEY=",             # 6 sensible sin valor
            "STRIPE_SECRET_KEY=sk_live_" + azar(24),      # 7 sin prefijo público: no es de este check
            "",
        ]))
        r = env_publicas.analizar(self.dir)
        self.validar_forma(r, "env_publicas")
        por_linea = {h["linea"]: h for h in r["hallazgos"]}
        self.assertEqual(sorted(por_linea), [5, 6])
        self.assertEqual(por_linea[5]["regla"], "check:env_publicas.nombre_sensible")
        self.assertEqual(por_linea[5]["severidad_sugerida"], "critica")
        self.assertEqual(por_linea[6]["severidad_sugerida"], "alta")  # sin valor: diseño defectuoso
        # Nunca se copia el valor del secreto a la evidencia.
        self.assertNotIn(clave, json.dumps(r))
        self.assertNotIn(clave[3:15], json.dumps(r))
        self.assertIn("VITE_OPENAI_API_KEY", por_linea[5]["evidencia"])

    def test_valor_secreto_en_variable_de_nombre_publico(self):
        self.escribir(".env.local", f"VITE_SUPABASE_ANON_KEY={jwt_canario('service_role')}\n"
                                    f"VITE_SUPABASE_OTRA_ANON_KEY={jwt_canario('anon')}\n")
        r = env_publicas.analizar(self.dir)
        self.assertEqual(self.reglas(r), ["check:env_publicas.valor_secreto"])
        self.assertEqual(r["hallazgos"][0]["archivo"], ".env.local")
        self.assertEqual(r["hallazgos"][0]["severidad_sugerida"], "critica")

    def test_referencia_en_codigo_solo_si_no_esta_en_env(self):
        self.escribir(".env", "VITE_OPENAI_API_KEY=sk-" + azar(30) + "\n")
        self.escribir("src/ia.js", "const k = import.meta.env.VITE_OPENAI_API_KEY\n")
        self.escribir("src/admin.ts", "\n\nconst s = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY\n")
        self.escribir("src/ok.ts", "const u = import.meta.env.VITE_SUPABASE_URL\n")
        self.escribir("node_modules/x/index.js", "process.env.NEXT_PUBLIC_DB_PASSWORD\n")
        self.escribir("dist/a.js", "process.env.NEXT_PUBLIC_DB_PASSWORD\n")
        r = env_publicas.analizar(self.dir)
        refs = [h for h in r["hallazgos"] if h["regla"] == "check:env_publicas.referencia_codigo"]
        self.assertEqual([(h["archivo"], h["linea"]) for h in refs], [("src/admin.ts", 3)])
        self.assertEqual(len(r["hallazgos"]), 2)  # + la del .env

    def test_pass_sin_hallazgos(self):
        self.escribir(".env", "VITE_SUPABASE_URL=https://x.supabase.co\n")
        r = env_publicas.analizar(self.dir)
        self.assertEqual(r["hallazgos"], [])
        self.assertEqual(r["estado"], "ok")
        self.assertEqual([p["regla"] for p in r["checks_pass"]], ["check:env_publicas.nombre_sensible"])

    def test_cli_escribe_crudo_y_meta(self):
        self.escribir(".env", "VITE_DB_PASSWORD=" + azar(20) + "\n")
        crudo = self.dir / "corrida" / "crudo"
        p = subprocess.run([sys.executable, str(CHECKS / "env_publicas.py"), str(self.dir), str(crudo)],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        datos = json.loads((crudo / "check_env_publicas.json").read_text())
        self.assertEqual(datos["check"], "env_publicas")
        self.assertEqual(len(datos["hallazgos"]), 1)
        meta = json.loads((crudo / "check_env_publicas.meta.json").read_text())
        self.assertEqual(meta["herramienta"], "check:env_publicas")
        self.assertEqual(meta["estado"], "ok")
        for k in ("version", "exit_code", "duracion_s", "comando", "error"):
            self.assertIn(k, meta)


# ----------------------------------------------------------------------------- registro_deps

class ConsultaFalsa:
    """Registro simulado: dict (ecosistema, nombre) → respuesta; ausente → no existe."""

    def __init__(self, conocidos, sin_red=False):
        self.conocidos = conocidos
        self.sin_red = sin_red
        self.llamadas = []

    def __call__(self, ecosistema, nombre, timeout):
        self.llamadas.append((ecosistema, nombre))
        if self.sin_red:
            raise registro_deps.ErrorRed("sin conexión (simulado)")
        if (ecosistema, nombre) in self.conocidos:
            return dict({"existe": True}, **self.conocidos[(ecosistema, nombre)])
        return {"existe": False}


class TestRegistroDeps(BaseFixture):
    PKG = """{
  "name": "demo",
  "dependencies": {
    "react": "18.3.1",
    "paquete-inventado-xyz": "^1.0.0",
    "@scope/real": "2.0.0",
    "local": "file:../local",
    "desde-git": "github:user/repo"
  },
  "devDependencies": {
    "vite-plugin-nuevo": "0.0.1"
  }
}
"""

    def test_inexistente_y_reciente(self):
        self.escribir("package.json", self.PKG)
        consulta = ConsultaFalsa({
            ("npm", "react"): {"creado": "2013-05-24T16:15:54Z"},
            ("npm", "@scope/real"): {"creado": "2020-01-01T00:00:00Z"},
            ("npm", "vite-plugin-nuevo"): {"creado": "2026-11-10T00:00:00Z"},
        })
        r = registro_deps.analizar(self.dir, consulta=consulta, cache=None, hoy="2026-11-18")
        self.validar_forma(r, "registro_deps")
        por_regla = {(h["regla"], h["linea"]) for h in r["hallazgos"]}
        self.assertEqual(por_regla, {("check:registro_deps.inexistente", 5), ("check:registro_deps.reciente", 11)})
        inex = [h for h in r["hallazgos"] if h["regla"].endswith("inexistente")][0]
        self.assertIn("paquete-inventado-xyz", inex["evidencia"])
        self.assertEqual(inex["severidad_sugerida"], "critica")
        # No se consultan dependencias locales ni de git.
        self.assertNotIn(("npm", "local"), consulta.llamadas)
        self.assertNotIn(("npm", "desde-git"), consulta.llamadas)
        self.assertEqual(r["estado"], "ok")

    def test_python_requirements_y_pyproject(self):
        self.escribir("requirements.txt", "# comentario\nrequests==2.32.0\nhuggingface-cli-pro>=1\n-r otro.txt\n")
        self.escribir("pyproject.toml", '[project]\nname = "x"\ndependencies = [\n  "fastapi>=0.110",\n  "Pydantic_Settings",\n]\n')
        consulta = ConsultaFalsa({
            ("pypi", "requests"): {"creado": "2011-02-14T00:00:00Z"},
            ("pypi", "fastapi"): {"creado": "2018-12-05T00:00:00Z"},
            ("pypi", "pydantic-settings"): {"creado": "2021-01-01T00:00:00Z"},
        })
        r = registro_deps.analizar(self.dir, consulta=consulta, cache=None, hoy="2026-11-18")
        self.assertEqual([(h["archivo"], h["linea"], h["regla"]) for h in r["hallazgos"]],
                         [("requirements.txt", 3, "check:registro_deps.inexistente")])

    def test_sin_red_no_evaluado(self):
        self.escribir("package.json", self.PKG)
        consulta = ConsultaFalsa({}, sin_red=True)
        r = registro_deps.analizar(self.dir, consulta=consulta, cache=None, hoy="2026-11-18")
        self.assertEqual(r["estado"], "no_evaluado")
        self.assertIn("red", r["motivo"])
        self.assertEqual(r["hallazgos"], [])
        self.assertEqual(r["checks_pass"], [])
        self.assertEqual(len(consulta.llamadas), 1)  # deja de insistir tras el primer fallo de red

    def test_cache_evita_consultas_repetidas(self):
        self.escribir("package.json", '{"dependencies": {"react": "18.3.1", "nada-existe-abc": "1.0.0"}}')
        cache = self.dir / "cache" / "registro_deps.json"
        c1 = ConsultaFalsa({("npm", "react"): {"creado": "2013-05-24T16:15:54Z"}})
        r1 = registro_deps.analizar(self.dir, consulta=c1, cache=cache, hoy="2026-11-18")
        self.assertEqual(len(c1.llamadas), 2)
        self.assertTrue(cache.exists())
        c2 = ConsultaFalsa({}, sin_red=True)
        r2 = registro_deps.analizar(self.dir, consulta=c2, cache=cache, hoy="2026-11-18")
        self.assertEqual(c2.llamadas, [])
        self.assertEqual(r1["hallazgos"], r2["hallazgos"])
        self.assertEqual(r2["estado"], "ok")

    def test_pass_si_todo_existe(self):
        self.escribir("package.json", '{"dependencies": {"react": "18.3.1"}}')
        r = registro_deps.analizar(self.dir, consulta=ConsultaFalsa({("npm", "react"): {"creado": "2013-05-24T00:00:00Z"}}),
                                   cache=None, hoy="2026-11-18")
        self.assertEqual(sorted(p["regla"] for p in r["checks_pass"]),
                         ["check:registro_deps.inexistente", "check:registro_deps.reciente"])

    def test_sin_manifiestos_no_aplica(self):
        r = registro_deps.analizar(self.dir, consulta=ConsultaFalsa({}), cache=None, hoy="2026-11-18")
        self.assertEqual(r["estado"], "ok")
        self.assertEqual(r["hallazgos"], [])
        self.assertEqual(r["checks_pass"], [])
        self.assertIn("sin manifiestos", r["motivo"])

    def test_cli_sin_red_meta_no_evaluado(self):
        self.escribir("package.json", '{"dependencies": {"react": "18.3.1"}}')
        crudo = self.dir / "corrida" / "crudo"
        env = {"AUDITOR_REGISTRO_SIN_RED": "1", "PATH": "/usr/bin:/bin"}
        p = subprocess.run([sys.executable, str(CHECKS / "registro_deps.py"), str(self.dir), str(crudo)],
                           capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        meta = json.loads((crudo / "check_registro_deps.meta.json").read_text())
        self.assertEqual(meta["estado"], "no_evaluado")
        self.assertTrue((crudo / "check_registro_deps.json").exists())


# ----------------------------------------------------------------------------- archivos_clave

class TestArchivosClave(BaseFixture):
    def setUp(self):
        super().setUp()
        # Las fixtures viven dentro del repo del auditor: se impide que git suba más allá de tests/.tmp
        # para que cada fixture se vea como un proyecto independiente.
        parche = mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": str(TMP_BASE)})
        parche.start()
        self.addCleanup(parche.stop)

    def proyecto_minimo_vacio(self):
        self.escribir("package.json", '{"name": "x", "scripts": {"dev": "vite"}, "dependencies": {"express": "4.21.2", "pg": "8.0.0"}}')
        self.escribir("server/index.js", "import express from 'express'\nconst app = express()\napp.get('/api/x', h)\nconst k = process.env.CLAVE\n")
        self.escribir("README.md", "# Mi app\n\nHecha con IA. ¡Funciona!\n")
        self.escribir(".env", "CLAVE=1\n")

    def test_ausencias(self):
        self.proyecto_minimo_vacio()
        r = archivos_clave.analizar(self.dir)
        self.validar_forma(r, "archivos_clave")
        reglas = set(self.reglas(r))
        for esperada in ("readme_sin_arranque", "env_ejemplo_ausente", "lockfile_ausente", "ci_ausente",
                         "tests_ausentes", "health_ausente", "env_no_ignorado", "doc_agente_ausente",
                         "error_tracking_ausente", "migraciones_ausentes", "git_sin_repo"):
            self.assertIn(f"check:archivos_clave.{esperada}", reglas)

    def test_presencias_como_pass(self):
        self.escribir("package.json", json.dumps({
            "name": "x", "scripts": {"dev": "vite", "test": "vitest run"},
            "dependencies": {"express": "4.21.2", "@sentry/node": "8.0.0", "@supabase/supabase-js": "2.0.0"}}))
        self.escribir("package-lock.json", "{}")
        self.escribir("server/index.js", "app.get('/health', (req, res) => res.json({ ok: true }))\n")
        self.escribir("README.md", "# App\n\n## Instalación\n\n```bash\nnpm install\nnpm run dev\n```\n")
        self.escribir(".env.example", "CLAVE=\n")
        self.escribir(".gitignore", "node_modules\n.env\n")
        # Ronda 1: el pase `ci` exige que el CI ejecute lint/typecheck/tests (no basta que exista el archivo).
        self.escribir(".github/workflows/ci.yml", "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
                                                  "    steps:\n      - run: npm test\n")
        self.escribir("tests/humo.test.js", "test('x', () => {})\n")
        self.escribir("CLAUDE.md", "# Arquitectura\n")
        self.escribir("supabase/migrations/001_inicial.sql", "create table x (id int);\n")
        r = archivos_clave.analizar(self.dir)
        reglas = set(self.reglas(r))
        self.assertFalse(reglas - {"check:archivos_clave.git_sin_repo"}, reglas)
        pases = {p["regla"] for p in r["checks_pass"]}
        for esperada in ("readme", "env_ejemplo", "lockfile", "ci", "tests", "health", "doc_agente",
                         "error_tracking", "migraciones"):
            self.assertIn(f"check:archivos_clave.{esperada}", pases)

    def test_readme_ausente(self):
        self.escribir("index.html", "<html></html>")
        r = archivos_clave.analizar(self.dir)
        self.assertIn("check:archivos_clave.readme_ausente", self.reglas(r))

    def test_sitio_estatico_sin_servidor_no_exige_health_ni_migraciones(self):
        self.escribir("index.html", "<html></html>")
        r = archivos_clave.analizar(self.dir)
        todas = set(self.reglas(r)) | {p["regla"] for p in r["checks_pass"]}
        self.assertFalse(any("health" in x for x in todas), todas)
        self.assertFalse(any("migraciones" in x for x in todas), todas)

    def test_env_comiteado_en_git(self):
        self.proyecto_minimo_vacio()
        subprocess.run(["git", "init", "-q", str(self.dir)], check=True)
        subprocess.run(["git", "-C", str(self.dir), "add", ".env"], check=True)
        r = archivos_clave.analizar(self.dir)
        reglas = self.reglas(r)
        self.assertIn("check:archivos_clave.env_comiteado", reglas)
        self.assertNotIn("check:archivos_clave.git_sin_repo", reglas)
        h = [x for x in r["hallazgos"] if x["regla"].endswith("env_comiteado")][0]
        self.assertEqual(h["archivo"], ".env")
        self.assertEqual(h["severidad_sugerida"], "critica")

    def test_script_test_por_defecto_de_npm_no_cuenta(self):
        self.escribir("package.json", '{"scripts": {"test": "echo \\"Error: no test specified\\" && exit 1"}}')
        r = archivos_clave.analizar(self.dir)
        self.assertIn("check:archivos_clave.tests_ausentes", self.reglas(r))


# ----------------------------------------------------------------------------- config_agentes

class TestConfigAgentes(BaseFixture):
    def test_settings_peligrosos(self):
        self.escribir(".claude/settings.json", json.dumps({
            "permissions": {
                "defaultMode": "bypassPermissions",
                "allow": ["Read(./src/**)", "Bash(npm run build)", "Bash(*)", "mcp__supabase__execute_sql"],
                "deny": ["Read(./.env)"],
            }}, indent=2))
        r = config_agentes.analizar(self.dir)
        self.validar_forma(r, "config_agentes")
        por_regla = {h["regla"]: h for h in r["hallazgos"]}
        self.assertEqual(set(por_regla), {"check:config_agentes.bypass_permisos", "check:config_agentes.bash_comodin",
                                          "check:config_agentes.mcp_sql_arbitrario"})
        self.assertEqual(por_regla["check:config_agentes.bypass_permisos"]["linea"], 3)
        self.assertEqual(por_regla["check:config_agentes.bash_comodin"]["linea"], 7)
        self.assertEqual(por_regla["check:config_agentes.mcp_sql_arbitrario"]["linea"], 8)

    def test_mcp_con_secreto_literal_y_version_flotante(self):
        jwt = jwt_canario("service_role")
        self.escribir(".mcp.json", json.dumps({"mcpServers": {
            "supabase": {"command": "npx", "args": ["-y", "@supabase/mcp-server-supabase@latest"],
                         "env": {"SUPABASE_SERVICE_ROLE_KEY": jwt}},
            "docs": {"command": "npx", "args": ["-y", "@upstash/context7-mcp@1.0.14"],
                     "env": {"CONTEXT7_API_KEY": "${CONTEXT7_API_KEY}"}},
        }}, indent=2))
        r = config_agentes.analizar(self.dir)
        reglas = sorted(self.reglas(r))
        self.assertEqual(reglas, ["check:config_agentes.mcp_secreto_literal", "check:config_agentes.mcp_version_flotante"])
        sec = [h for h in r["hallazgos"] if h["regla"].endswith("mcp_secreto_literal")][0]
        texto = (self.dir / ".mcp.json").read_text()
        self.assertEqual(sec["linea"], texto[:texto.index(jwt)].count("\n") + 1)
        self.assertEqual(sec["severidad_sugerida"], "critica")
        self.assertNotIn(jwt, json.dumps(r))

    def test_cursor_mcp_y_sin_config(self):
        r = config_agentes.analizar(self.dir)
        self.assertEqual(r["hallazgos"], [])
        self.assertEqual(r["checks_pass"], [])  # sin archivos de agentes: no aplica
        self.escribir(".cursor/mcp.json", json.dumps({"mcpServers": {"x": {"command": "node", "args": ["s.js"]}}}))
        r = config_agentes.analizar(self.dir)
        self.assertEqual(r["hallazgos"], [])
        self.assertTrue(r["checks_pass"])

    def test_json_invalido_no_revienta(self):
        self.escribir(".claude/settings.local.json", "{ esto no es json")
        r = config_agentes.analizar(self.dir)
        self.assertEqual(self.reglas(r), ["check:config_agentes.json_invalido"])


if __name__ == "__main__":
    unittest.main()


class TestMapeoCatalogo(unittest.TestCase):
    """Cada subregla que emiten los chequeos mapea a un control del catálogo (contrato con normalizar/)."""
    SUBREGLAS = {
        "env_publicas": ["nombre_sensible", "valor_secreto", "referencia_codigo"],
        "registro_deps": ["inexistente", "reciente"],
        "archivos_clave": ["readme_ausente", "readme_sin_arranque", "readme", "git_sin_repo", "git",
                           "env_ejemplo_ausente", "env_ejemplo", "env_comiteado", "env_no_ignorado", "env_ignorado",
                           "lockfile_ausente", "lockfile", "ci_ausente", "ci", "tests_ausentes",
                           "health_ausente", "health", "migraciones_ausentes", "migraciones",
                           "doc_agente_ausente", "doc_agente", "error_tracking_ausente", "error_tracking"],
        "config_agentes": ["bypass_permisos", "bash_comodin", "mcp_sql_arbitrario", "mcp_secreto_literal",
                           "mcp_version_flotante", "json_invalido", "configuracion"],
    }

    def test_todas_mapean(self):
        sys.path.insert(0, str(RAIZ / "scripts"))
        import catalogo
        cat = catalogo.cargar_catalogo()
        for nombre, subs in self.SUBREGLAS.items():
            for sub in subs:
                self.assertIsNotNone(catalogo.control_por_regla("check", f"{nombre}.{sub}", cat), f"{nombre}.{sub}")

    def test_pase_de_tests_no_da_pass_a_tests_de_humo(self):
        # Que existan archivos de test no prueba que pasen: solo la ausencia decide COD-TESTS-HUMO.
        sys.path.insert(0, str(RAIZ / "scripts"))
        import catalogo
        self.assertIsNone(catalogo.control_por_regla("check", "archivos_clave.tests"))
        self.assertEqual(catalogo.control_por_regla("check", "archivos_clave.tests_ausentes"), "COD-TESTS-HUMO")
