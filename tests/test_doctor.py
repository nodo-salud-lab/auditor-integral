"""Tests de scripts/doctor.sh: detecta versiones, nunca instala, timeout por herramienta."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
DOCTOR = RAIZ / "scripts" / "doctor.sh"
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
TMP_BASE.mkdir(parents=True, exist_ok=True)

HERRAMIENTAS = ["gitleaks", "semgrep", "osv-scanner", "zizmor", "trivy", "jscpd", "knip", "squawk", "k6",
                "hadolint", "actionlint", "checkov", "lizard", "node", "npx", "python3", "jq", "git",
                "playwright", "lhci", "nuclei", "syft", "zap.sh", "psql"]


def correr(args=(), env=None, timeout=180):
    if env is None:
        env = dict(os.environ, TMPDIR=str(TMP_BASE))
    return subprocess.run(["bash", str(DOCTOR), *args], capture_output=True, text=True, env=env, timeout=timeout)


def escribir_falso(directorio, nombre, cuerpo):
    ruta = Path(directorio) / nombre
    ruta.write_text("#!/bin/bash\n" + cuerpo + "\n")
    ruta.chmod(ruta.stat().st_mode | stat.S_IXUSR)
    return ruta


class TestDoctorReal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        r = correr()
        assert r.returncode == 0, r.stderr
        cls.datos = json.loads(r.stdout)

    def test_lista_completa(self):
        self.assertEqual(sorted(self.datos["herramientas"]), sorted(HERRAMIENTAS))
        self.assertEqual(self.datos["version_esquema"], "1")
        self.assertIn("generado", self.datos)

    def test_instaladas_con_version(self):
        h = self.datos["herramientas"]
        self.assertEqual(h["gitleaks"]["version"], "8.30.1")
        self.assertEqual(h["semgrep"]["version"], "1.181.0")
        self.assertEqual(h["osv-scanner"]["version"], "2.7.0")
        self.assertEqual(h["zizmor"]["version"], "1.32.0")
        for n in ("git", "python3", "jq", "node"):
            self.assertTrue(h[n]["disponible"], n)
            self.assertEqual(h[n]["estado"], "ok")

    def test_campos_y_sugerencia_de_instalacion(self):
        for nombre, d in self.datos["herramientas"].items():
            with self.subTest(herramienta=nombre):
                for campo in ("disponible", "estado", "version", "ruta", "instalacion_sugerida"):
                    self.assertIn(campo, d)
                self.assertIn(d["estado"], ("ok", "ausente", "timeout", "error"))
                if not d["disponible"]:
                    self.assertTrue(d["instalacion_sugerida"], "las faltantes llevan comando sugerido")
                    self.assertRegex(d["instalacion_sugerida"], r"^(brew|npm|pipx|pip|go|curl) ")


class TestDoctorAislado(unittest.TestCase):
    """PATH controlado con binarios falsos."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir=TMP_BASE)
        self.env = dict(os.environ, PATH=f"{self.tmp}:/usr/bin:/bin", TMPDIR=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_ausente_no_instala(self):
        # npm/brew falsos que dejan rastro si alguien los invoca
        rastro = Path(self.tmp) / "rastro"
        for n in ("brew", "npm", "pipx", "pip3", "curl"):
            escribir_falso(self.tmp, n, f'echo "{n} $*" >> "{rastro}"')
        r = correr(env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)["herramientas"]
        self.assertFalse(d["gitleaks"]["disponible"])
        self.assertEqual(d["gitleaks"]["estado"], "ausente")
        self.assertFalse(rastro.exists(), "doctor nunca debe invocar instaladores")

    def test_timeout_por_herramienta(self):
        escribir_falso(self.tmp, "gitleaks", "sleep 30")
        env = dict(self.env, AUDITOR_DOCTOR_TIMEOUT="1")
        t0 = time.monotonic()
        r = correr(env=env, timeout=120)
        self.assertLess(time.monotonic() - t0, 25)
        d = json.loads(r.stdout)["herramientas"]["gitleaks"]
        self.assertEqual(d["estado"], "timeout")
        self.assertFalse(d["disponible"])

    def test_version_extraida_y_escapado_json(self):
        escribir_falso(self.tmp, "zizmor", 'echo "zizmor 9.8.7 \\"beta\\"	tab"')
        d = json.loads(correr(env=self.env).stdout)["herramientas"]["zizmor"]
        self.assertTrue(d["disponible"])
        self.assertEqual(d["version"], "9.8.7")

    def test_salida_a_archivo(self):
        destino = Path(self.tmp) / "sub" / "herramientas.json"
        r = correr(["--salida", str(destino)], env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "")
        self.assertIn("herramientas", json.loads(destino.read_text()))


TABLA = RAIZ / "scripts" / "doctor_tabla.py"
DOCTOR_FALSO = {"herramientas": {
    "gitleaks": {"disponible": True, "estado": "ok", "version": "8.30.1", "via": "path", "instalacion_sugerida": None},
    "jscpd": {"disponible": True, "estado": "ok", "version": "4.0.5", "via": "npx", "instalacion_sugerida": None},
    "lhci": {"disponible": False, "estado": "ausente", "version": None, "instalacion_sugerida": "npm install -g @lhci/cli"},
    "trivy": {"disponible": False, "estado": "timeout", "detalle": "sin respuesta en 10 s", "version": None,
              "instalacion_sugerida": "brew install trivy"}}}


class TestDoctorTabla(unittest.TestCase):
    """scripts/doctor_tabla.py y doctor.sh --tabla: vista legible, solo lectura; el JSON por defecto no cambia."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(dir=TMP_BASE))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def tabla(self, *args, entrada=None):
        return subprocess.run([sys.executable, "-I", str(TABLA), *map(str, args)], input=entrada,
                              capture_output=True, text=True, timeout=60)

    def test_disponibles_primero_y_comando_sugerido_sin_ejecutar(self):
        r = self.tabla(entrada=json.dumps(DOCTOR_FALSO))
        self.assertEqual(r.returncode, 0, r.stderr)
        t = r.stdout
        self.assertIn("2 disponibles, 2 faltan (de 4)", t)
        self.assertLess(t.index("Disponibles (2)"), t.index("Faltan (2)"))
        self.assertIn("comando sugerido, sin ejecutar", t)
        self.assertRegex(t, r"gitleaks\s+8\.30\.1")
        self.assertIn("(vía npx)", t)
        self.assertRegex(t, r"lhci\s+npm install -g @lhci/cli")
        self.assertIn("[timeout: sin respuesta en 10 s]", t)
        self.assertNotIn("control(es) no_evaluado", t)       # sin --corrida no hay conteo

    def test_conteo_por_corrida(self):
        (self.tmp / "h.json").write_text(json.dumps(DOCTOR_FALSO), encoding="utf-8")
        controles = [
            {"control": "UX-A", "estado": "no_evaluado", "motivo": "lighthouse: sin datos de la herramienta"},
            {"control": "UX-B", "estado": "no_evaluado", "motivo": "axe: x; lhci: sin datos"},
            {"control": "UX-C", "estado": "fail", "motivo": "lighthouse: x"},             # no es no_evaluado
            {"control": "INF-A", "estado": "no_evaluado", "motivo": "trivy: timeout de la herramienta"},
            {"control": "INF-B", "estado": "no_evaluado", "motivo": "sin trivy instalado"}]  # no es «trivy:»
        (self.tmp / "estado.json").write_text(json.dumps({"controles": controles}), encoding="utf-8")
        r = self.tabla("--archivo", self.tmp / "h.json", "--corrida", self.tmp)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout, r"lhci .*· 2 control\(es\) no_evaluado")
        self.assertRegex(r.stdout, r"trivy .*· 1 control\(es\) no_evaluado")
        self.assertIn("coincidencia de texto", r.stdout)

    def test_json_invalido_rc2(self):
        r = self.tabla(entrada="no es json")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_doctor_sh_tabla_y_json_por_defecto_intacto(self):
        env = dict(os.environ, PATH=f"{self.tmp}:/usr/bin:/bin", TMPDIR=str(self.tmp), AUDITOR_PYTHON=sys.executable)
        r = correr(["--tabla"], env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("comando sugerido, sin ejecutar", r.stdout)
        self.assertRaises(ValueError, json.loads, r.stdout)
        destino = self.tmp / "herramientas.json"
        r = correr(["--tabla", "--salida", str(destino)], env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Faltan", r.stdout)
        self.assertEqual(sorted(json.loads(destino.read_text())["herramientas"]), sorted(HERRAMIENTAS))
        r = correr(env=env)                                    # sin --tabla: JSON como siempre
        self.assertEqual(sorted(json.loads(r.stdout)["herramientas"]), sorted(HERRAMIENTAS))


if __name__ == "__main__":
    unittest.main()
