"""Regresiones de la autoauditoría del auditor (2026-11-20): defectos del propio auditor y de su arnés de tests.

- Temporales de tests fuera del árbol del proyecto y con limpieza registrada aunque falle setUp/setUpClass.
- OPS-HEALTH: una ruta /health escrita en un test o fixture no da pase.
- dockerfile.py no trata `dockerfile.py` (código) como Dockerfile; un Dockerfile de fixture no da pase.
- gitleaks (árbol) no escanea __pycache__ ni .pyc.
- detectar_stack: la evidencia de tests/fixtures queda en evidencia_secundaria y no enciende banderas.
- Informe: las entradas sintéticas del tope de triage no se cuentan como juicios de la IA; texto de tokens; el
  número del bloqueo muestra aparte los FP de IA pendientes de verificación humana.
- corrida.py: «sin-commits» (repo sin commits) distinto de «sin-git» (fuera de todo repo).
"""
import io
import json
import os
import re
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import archivos_clave  # noqa: E402
import comun  # noqa: E402
import corrida  # noqa: E402
import detectar_stack  # noqa: E402
import dockerfile  # noqa: E402
import render_informe  # noqa: E402
import tmp_tests  # noqa: E402

SERVIDOR = "import express from 'express'\nconst app = express()\napp.listen(3000)\n"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tmp_tests.tmp_dir(self)

    def escribir(self, rel, texto):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(texto, encoding="utf-8")
        return p


class TestTemporales(unittest.TestCase):
    def test_tmp_base_fuera_del_proyecto(self):
        self.assertFalse(tmp_tests.TMP_BASE.is_relative_to(RAIZ), tmp_tests.TMP_BASE)

    def test_limpieza_registrada_en_setup(self):
        rutas = []

        class Caso(unittest.TestCase):
            def setUp(self):
                rutas.append(tmp_tests.tmp_dir(self))
                raise RuntimeError("setUp falla después de crear la carpeta")

            def test_x(self):
                pass
        unittest.TextTestRunner(stream=io.StringIO()).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(Caso))
        self.assertEqual(len(rutas), 1)
        self.assertFalse(rutas[0].exists())

    def test_limpieza_registrada_en_setupclass(self):
        rutas = []

        class Caso(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                rutas.append(tmp_tests.tmp_dir(cls))
                raise RuntimeError("setUpClass falla: tearDownClass no se ejecuta")

            def test_x(self):
                pass
        unittest.TextTestRunner(stream=io.StringIO()).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(Caso))
        self.assertEqual(len(rutas), 1)
        self.assertFalse(rutas[0].exists())


class TestHealthSoloEnTests(Base):
    def test_health_solo_en_tests_no_da_pase(self):
        self.escribir("server/index.js", SERVIDOR)
        self.escribir("tests/test_servidor.py", "app.get('/health', (req, res) => res.json({ ok: true }))\n")
        self.escribir("tests/fixtures/app/server.js", "app.get('/healthz', (req, res) => res.send('ok'))\n")
        r = archivos_clave.analizar(self.dir)
        reglas = {h["regla"] for h in r["hallazgos"]}
        pases = {p["regla"] for p in r["checks_pass"]}
        self.assertIn("check:archivos_clave.health_ausente", reglas)
        self.assertNotIn("check:archivos_clave.health", pases)

    def test_health_en_codigo_del_proyecto_si_da_pase(self):
        self.escribir("server/index.js", SERVIDOR + "app.get('/health', (req, res) => res.json({ ok: true }))\n")
        r = archivos_clave.analizar(self.dir)
        self.assertIn("check:archivos_clave.health", {p["regla"] for p in r["checks_pass"]})

    def test_servidor_solo_en_tests_sigue_activando_la_obligacion(self):
        self.escribir("tests/servidor_falso.js", SERVIDOR)
        r = archivos_clave.analizar(self.dir)
        self.assertIn("check:archivos_clave.health_ausente", {h["regla"] for h in r["hallazgos"]})


class TestDockerfile(Base):
    def test_nombres(self):
        for nombre, esperado in (("dockerfile.py", False), ("Dockerfile.md", False), ("dockerfile.json", False),
                                 ("Dockerfile", True), ("Dockerfile.dev", True), ("Dockerfile.prod", True),
                                 ("api.dockerfile", True), ("Containerfile", True)):
            with self.subTest(nombre):
                self.assertEqual(dockerfile.es_dockerfile(Path(nombre)), esperado)

    def test_el_propio_check_no_se_analiza(self):
        self.escribir("scripts/checks/dockerfile.py", "from pathlib import Path\nimport re\n")
        r = dockerfile.analizar(self.dir)
        self.assertEqual(r["hallazgos"], [])

    def test_dockerfile_de_fixture_hallazgos_si_pase_no(self):
        self.escribir("tests/fixtures/stacks/docker/Dockerfile", "FROM node:latest\nCMD node app.js\n")
        r = dockerfile.analizar(self.dir)
        self.assertTrue(any(h["regla"].endswith("tag_latest") for h in r["hallazgos"]))
        self.assertEqual(r["checks_pass"], [])

    def test_dockerfile_propio_da_pase(self):
        self.escribir("Dockerfile", "FROM node:20.11-alpine AS b\nRUN npm ci\nFROM node:20.11-alpine\n"
                                    "COPY --from=b /app /app\nUSER node\nCMD [\"node\", \"app.js\"]\n")
        r = dockerfile.analizar(self.dir)
        self.assertTrue(r["checks_pass"])


class TestGitleaksArbol(unittest.TestCase):
    def test_excluye_bytecode(self):
        conf = tomllib.loads((RAIZ / "reglas" / "gitleaks" / "arbol.toml").read_text(encoding="utf-8"))
        rx = [re.compile(p) for p in conf["allowlists"][0]["paths"]]
        for ruta in ("tests/__pycache__/test_x.cpython-312.pyc", "a/b.pyc", "c.pyo"):
            self.assertTrue(any(r.search(ruta) for r in rx), ruta)
        for ruta in ("tests/test_x.py", "src/app.js", "pycache.txt"):
            self.assertFalse(any(r.search(ruta) for r in rx), ruta)

    def test_base_no_cambia(self):
        texto = (RAIZ / "reglas" / "gitleaks" / "base.toml").read_text(encoding="utf-8")
        self.assertNotIn("__pycache__", texto)


class TestPerfilSinFixtures(Base):
    def test_fixtures_no_encienden_banderas(self):
        self.escribir("package.json", json.dumps({"dependencies": {"react": "18.3.1"}}))
        self.escribir("tests/fixtures/stacks/pagos/package.json", json.dumps({"dependencies": {"stripe": "1.0.0"}}))
        self.escribir("tests/fixtures/stacks/docker/Dockerfile", "FROM node:20\n")
        self.escribir("e2e/k8s/deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n")
        p = detectar_stack.detectar(self.dir)
        self.assertFalse(p["pagos"])
        self.assertFalse(p["docker"])
        self.assertFalse(p["k8s"])
        self.assertFalse(p["servidor"])
        sec = p["evidencia_secundaria"]
        self.assertIn("tests/fixtures/stacks/pagos/package.json", sec["pagos"])
        self.assertIn("tests/fixtures/stacks/docker/Dockerfile", sec["docker"])
        self.assertNotIn("pagos", p["evidencia"])

    def test_evidencia_propia_se_conserva(self):
        self.escribir("package.json", json.dumps({"dependencies": {"stripe": "1.0.0"}}))
        self.escribir("tests/fixtures/x/package.json", json.dumps({"dependencies": {"stripe": "1.0.0"}}))
        p = detectar_stack.detectar(self.dir)
        self.assertTrue(p["pagos"])
        self.assertEqual(p["evidencia"]["pagos"], ["package.json"])
        self.assertEqual(p["evidencia_secundaria"]["pagos"], ["tests/fixtures/x/package.json"])

    def test_criterio(self):
        for rel, esperado in (("tests/a.py", True), ("src/__mocks__/x.js", True), ("fixtures/p/package.json", True),
                              ("src/app.test.ts", True), ("src/app.ts", False), ("package.json", False)):
            with self.subTest(rel):
                self.assertEqual(comun.es_test_o_fixture(rel), esperado)


class TestInforme(unittest.TestCase):
    def test_sinteticos_no_cuentan_como_juicios(self):
        veredictos = [{"agente": "triage-fp", "control": "SEG-X", "veredicto": "verdadero", "modelo": "m"}] + [
            {"agente": "auditor", "control": "SEG-X", "veredicto": "incierto", "modelo": None} for _ in range(5)]
        s = render_informe.seccion_que_hizo({}, [], {}, veredictos, None, "estandar")
        self.assertIn("Qué revisó la IA (1 juicios)", s)
        self.assertIn("5 hallazgo(s) crítico(s)/alto(s) **no juzgados**", s)
        self.assertNotIn("`auditor`", s)

    def test_solo_sinteticos(self):
        veredictos = [{"agente": "auditor", "control": "SEG-X", "veredicto": "incierto", "modelo": None}]
        s = render_informe.seccion_que_hizo({}, [], {}, veredictos, None, "estandar")
        self.assertIn("La IA no emitió juicios", s)
        self.assertIn("1 hallazgo(s) crítico(s)/alto(s) **no juzgados**", s)

    def test_aviso_no_revisado(self):
        a = render_informe._aviso_triage({"veredicto": "incierto", "razon": "no juzgado: tope", "modelo": "auditor"},
                                         "src/a.js:3")
        self.assertIn("No revisado por la IA", a)
        self.assertNotIn("no pudo confirmarlo", a)
        self.assertIn("Cuenta como verdadero", a)
        b = render_informe._aviso_triage({"veredicto": "incierto", "razon": "dudoso", "modelo": "m"}, "src/a.js:3")
        self.assertIn("no pudo confirmarlo", b)

    def test_texto_tokens(self):
        s = render_informe.seccion_que_hizo({}, [], {}, [], None, "estandar")
        self.assertIn("no encontró transcripts con usage", s)

    def test_bloqueo_muestra_fp_ia_pendientes(self):
        g = {"global": {"bloqueos": [{"control": "SEG-SECRETO-REPO", "tipo": "secreto_vivo",
                                      "hallazgos": ["H-1", "H-2"]}]}}
        hallazgos = [{"id": f"H-{i}", "control": "SEG-SECRETO-REPO", "severidad": "critica",
                      "estado_hallazgo": "abierto"} for i in range(1, 6)]
        hallazgos[4]["verificacion_humana"] = {"quien": "x"}
        triage = {"H-3": {"veredicto": "falso_positivo"}, "H-4": {"veredicto": "falso_positivo"},
                  "H-5": {"veredicto": "falso_positivo"}}
        s = render_informe._seccion_bloqueos(g, {}, hallazgos, triage)
        self.assertIn("2 hallazgo(s) más 2 con posible falso positivo de la IA pendiente de verificación humana", s)
        self.assertIn("4 en total", s)
        self.assertIn("2 hallazgo(s).", render_informe._seccion_bloqueos(g, {}, hallazgos, {}))


class TestIdCorrida(Base):
    def _git(self, *args):
        subprocess.run(["git", *args], cwd=self.dir, check=True, capture_output=True,
                       env=dict(os.environ, GIT_CEILING_DIRECTORIES=str(self.dir.parent)))

    def test_repo_sin_commits(self):
        self._git("init", "-q")
        c = corrida.crear(self.dir, "rapido")
        self.assertTrue(c.name.endswith("-sin-commits"), c.name)
        self.assertTrue(corrida.RE_ID.match(c.name))

    def test_fuera_de_git(self):
        c = corrida.crear(self.dir, "rapido")
        self.assertTrue(c.name.endswith("-sin-git"), c.name)
        self.assertTrue(corrida.RE_ID.match(c.name))


if __name__ == "__main__":
    unittest.main()
