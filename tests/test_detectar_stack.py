"""Tests de scripts/detectar_stack.py sobre 5 fixtures (criterio F0-4)."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))

import detectar_stack as ds  # noqa: E402
import validar_schema as vs  # noqa: E402

FIX = RAIZ / "tests" / "fixtures" / "stacks"
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
TMP_BASE.mkdir(parents=True, exist_ok=True)
SCHEMA_TEC = vs.subschema(json.loads((RAIZ / "schemas" / "perfil.schema.json").read_text()), "perfil_tecnico")

BANDERAS = ("ssr_serverless", "llm", "pagos", "emails", "docker", "iac", "k8s", "movil", "pwa",
            "multi_idioma", "agente_ia", "ci")


class Base(unittest.TestCase):
    fixture = None
    esperado_true = set()

    @classmethod
    def setUpClass(cls):
        if cls.fixture:
            cls.p = ds.detectar(FIX / cls.fixture)

    def comprobar_banderas(self):
        for b in BANDERAS:
            with self.subTest(bandera=b):
                self.assertIs(self.p[b], b in self.esperado_true, f"{self.fixture}: {b}")

    def test_valida_contra_schema(self):
        if self.fixture:
            self.assertEqual(vs.validar(self.p, SCHEMA_TEC), [])


class TestViteSupabase(Base):
    fixture = "vite_supabase"
    esperado_true = {"llm", "ci"}

    def test_clasificacion(self):
        p = self.p
        self.assertIn("vite", p["frameworks"])
        self.assertIn("react", p["frameworks"])
        self.assertNotIn("next", p["frameworks"], "no debe leer node_modules")
        self.assertEqual(p["baas"], "supabase")
        self.assertEqual(p["ecosistemas"]["node"]["gestor"], "npm")
        self.assertEqual(p["ecosistemas"]["node"]["lockfiles"], ["package-lock.json"])
        self.assertIn("typescript", p["lenguajes"])
        self.assertEqual(p["detalle"]["llm"], ["openai"])
        self.assertEqual(p["detalle"]["ci"], ["github_actions"])
        self.assertIn("dist", p["carpetas_build"])
        self.assertIn("node_modules", p["limites"]["excluidos"])
        self.comprobar_banderas()

    def test_no_entra_a_node_modules_ni_dist(self):
        for archivos in self.p["evidencia"].values():
            for a in archivos:
                self.assertFalse(a.startswith("node_modules") or "/node_modules/" in a, a)
                self.assertFalse(a.startswith("dist/"), a)


class TestNextPrisma(Base):
    fixture = "next_prisma"
    esperado_true = {"ssr_serverless", "pagos", "emails", "multi_idioma", "agente_ia", "llm"}

    def test_clasificacion(self):
        p = self.p
        self.assertIn("next", p["frameworks"])
        self.assertIn("react", p["frameworks"])
        self.assertIn("prisma", p["orm"])
        self.assertEqual(p["baas"], "ninguno")
        self.assertEqual(p["ecosistemas"]["node"]["gestor"], "pnpm")
        self.assertEqual(p["detalle"]["pagos"], ["stripe"])
        self.assertEqual(p["detalle"]["emails"], ["resend"])
        self.assertEqual(p["detalle"]["llm"], ["anthropic"])
        self.assertIn(".mcp.json", p["evidencia"]["agente_ia"])
        self.assertIn(".next", p["carpetas_build"])
        self.comprobar_banderas()


class TestFastAPI(Base):
    fixture = "fastapi"
    esperado_true = {"llm"}

    def test_clasificacion(self):
        p = self.p
        self.assertEqual(p["frameworks"], ["fastapi"])
        self.assertIn("sqlalchemy", p["orm"])
        self.assertEqual(p["lenguajes"], ["python"])
        self.assertEqual(p["ecosistemas"]["python"]["gestor"], "uv")
        self.assertEqual(p["ecosistemas"]["python"]["lockfiles"], ["uv.lock"])
        self.assertNotIn("node", p["ecosistemas"])
        self.assertEqual(p["detalle"]["llm"], ["anthropic"])
        self.comprobar_banderas()


class TestEstatico(Base):
    fixture = "estatico"
    esperado_true = set()

    def test_clasificacion(self):
        p = self.p
        self.assertEqual(p["frameworks"], [])
        self.assertEqual(p["orm"], [])
        self.assertEqual(p["baas"], "ninguno")
        self.assertEqual(p["ecosistemas"], {})
        self.assertEqual(set(p["lenguajes"]), {"html", "css", "javascript"})
        self.assertEqual(p["carpetas_build"], [])
        self.comprobar_banderas()


class TestDocker(Base):
    fixture = "docker"
    esperado_true = {"docker", "k8s", "iac", "emails"}

    def test_clasificacion(self):
        p = self.p
        self.assertEqual(p["frameworks"], ["flask"])
        self.assertIn("sqlalchemy", p["orm"])
        self.assertEqual(p["ecosistemas"]["python"]["gestor"], "pip")
        self.assertEqual(p["ecosistemas"]["python"]["lockfiles"], [])
        self.assertEqual(p["detalle"]["emails"], ["sendgrid"])
        self.assertEqual(p["detalle"]["iac"], ["terraform"])
        self.assertIn("Dockerfile", p["evidencia"]["docker"])
        self.comprobar_banderas()


class TestCasosBorde(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=TMP_BASE))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_package_json_invalido_no_rompe(self):
        (self.tmp / "package.json").write_text("{ esto no es json")
        p = ds.detectar(self.tmp)
        self.assertEqual(p["frameworks"], [])
        self.assertEqual(vs.validar(p, SCHEMA_TEC), [])

    def test_movil_pwa_firebase(self):
        (self.tmp / "package.json").write_text(json.dumps({"dependencies": {
            "expo": "51", "react-native": "0.74", "firebase": "10", "mercadopago": "2",
            "vite-plugin-pwa": "0.20", "i18next": "23"}}))
        (self.tmp / "yarn.lock").write_text("")
        p = ds.detectar(self.tmp)
        self.assertTrue(p["movil"])
        self.assertEqual(p["detalle"]["movil"], ["expo", "react-native"])
        self.assertEqual(p["baas"], "firebase")
        self.assertTrue(p["pagos"])
        self.assertEqual(p["detalle"]["pagos"], ["mercadopago"])
        self.assertTrue(p["pwa"])
        self.assertTrue(p["multi_idioma"])
        self.assertEqual(p["ecosistemas"]["node"]["gestor"], "yarn")

    def test_symlink_fuera_no_se_sigue(self):
        afuera = Path(tempfile.mkdtemp(dir=TMP_BASE))
        try:
            (afuera / "package.json").write_text(json.dumps({"dependencies": {"stripe": "1"}}))
            (self.tmp / "enlace").symlink_to(afuera, target_is_directory=True)
            p = ds.detectar(self.tmp)
            self.assertFalse(p["pagos"])
        finally:
            shutil.rmtree(afuera)

    def test_no_escribe_en_el_proyecto(self):
        shutil.copytree(FIX / "vite_supabase", self.tmp / "p")
        antes = sorted(str(x) for x in (self.tmp / "p").rglob("*"))
        ds.detectar(self.tmp / "p")
        self.assertEqual(antes, sorted(str(x) for x in (self.tmp / "p").rglob("*")))


class TestCLI(unittest.TestCase):
    def test_cli_salida_archivo_y_stdout(self):
        script = RAIZ / "scripts" / "detectar_stack.py"
        with tempfile.TemporaryDirectory(dir=TMP_BASE) as d:
            destino = Path(d) / "perfil_tecnico.json"
            r = subprocess.run([sys.executable, str(script), str(FIX / "fastapi"), "--salida", str(destino)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(destino.read_text())["frameworks"], ["fastapi"])
        r = subprocess.run([sys.executable, str(script), str(FIX / "estatico")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["baas"], "ninguno")
        r = subprocess.run([sys.executable, str(script), "/ruta/que/no/existe"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_determinista(self):
        a = ds.detectar(FIX / "next_prisma")
        b = ds.detectar(FIX / "next_prisma")
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
