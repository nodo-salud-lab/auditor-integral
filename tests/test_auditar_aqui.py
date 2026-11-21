"""Tests de bin/auditar-aqui y scripts/resumen_corrida.py (mejora «auditar el proyecto actual», H-13).

- auditar-aqui exige elegir la red (--con-red / --sin-red, o AUDITOR_SIN_RED en el entorno) y se niega con rc 2
  en /, $HOME, la raíz del auditor, .auditoria/, una corrida o una carpeta sin archivos de proyecto.
- Con un proyecto real llama a 'auditar all', deja la carpeta de corrida como última línea de stdout y escribe
  el resumen en stderr con las 3 rutas en orden de lectura.
- resumen_corrida.py solo cuenta lo que trae gates.json: bloqueos por control (no por entrada), la frase de N0
  sin bloqueos y rc 1 sin gates.json (no inventa un nivel).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
AQUI = RAIZ / "bin" / "auditar-aqui"
RESUMEN = RAIZ / "scripts" / "resumen_corrida.py"
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)


def correr(cwd, *args, env_extra=None, quitar=("AUDITOR_SIN_RED",)):
    env = {k: v for k, v in os.environ.items() if k not in quitar}
    env.update(env_extra or {})
    return subprocess.run([str(AQUI), *args], cwd=cwd, capture_output=True, text=True, env=env, timeout=300)


class Base(unittest.TestCase):
    def setUp(self):
        TMP_BASE.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(dir=TMP_BASE))
        self.proy = self.tmp / "mi proyecto"          # con espacio, como PROYECTOS /
        (self.proy / "src").mkdir(parents=True)
        (self.proy / "package.json").write_text('{"name":"x","version":"1.0.0"}\n', encoding="utf-8")
        (self.proy / "src" / "index.js").write_text("console.log(1)\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestRechazos(Base):
    def assert_rechazo(self, r, texto):
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn(texto, r.stderr)
        self.assertEqual(r.stdout, "")

    def test_exige_elegir_la_red(self):
        r = correr(self.proy)
        self.assert_rechazo(r, "falta elegir la red")
        self.assertFalse((self.proy / ".auditoria").exists())

    def test_red_excluyente_y_contradiccion_con_entorno(self):
        self.assert_rechazo(correr(self.proy, "--sin-red", "--con-red"), "excluyentes")
        self.assert_rechazo(correr(self.proy, "--con-red", env_extra={"AUDITOR_SIN_RED": "1"}), "contradice")

    def test_raiz_home_auditor(self):
        self.assert_rechazo(correr("/", "--sin-red"), "es /")
        self.assert_rechazo(correr(self.proy, "--sin-red", env_extra={"HOME": str(self.proy)}), "carpeta personal")
        self.assert_rechazo(correr(RAIZ, "--sin-red"), "propio auditor")

    def test_auditoria_y_corrida(self):
        c = self.proy / ".auditoria" / "2026-01-01_0000-sin-git"
        c.mkdir(parents=True)
        self.assert_rechazo(correr(c, "--sin-red"), ".auditoria/")
        otra = self.tmp / "corrida-suelta"
        otra.mkdir()
        (otra / "run.json").write_text("{}", encoding="utf-8")
        self.assert_rechazo(correr(otra, "--sin-red"), "carpeta de corrida")

    def test_carpeta_sin_proyecto(self):
        vacia = self.tmp / "vacia"
        (vacia / "docs").mkdir(parents=True)
        (vacia / "docs" / "notas.md").write_text("# notas\n", encoding="utf-8")
        self.assert_rechazo(correr(vacia, "--sin-red"), "no hay archivos de proyecto")
        self.assertFalse((vacia / ".auditoria").exists())

    def test_no_recibe_ruta_ni_modo_invalido(self):
        self.assert_rechazo(correr(self.proy, "--sin-red", str(self.proy)), "no recibe RUTA")
        self.assert_rechazo(correr(self.proy, "--sin-red", "--modo", "turbo"), "modo inválido")
        self.assert_rechazo(correr(self.proy, "--sin-red", "--mode", "rapido"), "¿quiso decir --modo?")


class TestCorridaReal(Base):
    def test_audita_el_cwd_y_resume(self):
        r = correr(self.proy, "--sin-red", "--modo", "rapido")
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        corrida = Path(r.stdout.strip().splitlines()[-1])
        self.assertEqual(corrida.parent, self.proy.resolve() / ".auditoria")
        self.assertTrue((corrida / "gates.json").is_file())
        err = r.stderr
        self.assertIn(f"Auditando: {self.proy.resolve()}", err)
        self.assertIn("sin red (--sin-red)", err)
        self.assertIn("Nivel demostrado:", err)
        self.assertIn("¿Listo para datos reales?:", err)
        resumen = err[err.index("── Resumen ──"):]
        rutas = [resumen.index(str(corrida / n)) for n in ("resumen-dueno.md", "informe.md", "hoja-de-ruta.md")]
        self.assertEqual(rutas, sorted(rutas))
        # --sin-red llegó a la corrida: los motivos lo registran
        estado = json.loads((corrida / "estado.json").read_text(encoding="utf-8"))
        self.assertTrue(any("sin red (AUDITOR_SIN_RED)" in (c.get("motivo") or "") for c in estado["controles"]))


def gates(nd="N0", bloqueos=(), dominios=None):
    return {"global": {"nivel_demostrado": nd, "nivel_potencial": nd, "hito": "h", "listo_datos_reales": "NO",
                       "bloqueos": list(bloqueos)},
            "cobertura_por_nivel": {"N1": {"aplicables": 4, "evaluados": 2}, "N2": {"aplicables": 0, "evaluados": 0}},
            "dominios": dominios or {}}


class TestResumen(unittest.TestCase):
    def setUp(self):
        TMP_BASE.mkdir(parents=True, exist_ok=True)
        self.c = Path(tempfile.mkdtemp(dir=TMP_BASE))
        (self.c / "run.json").write_text(json.dumps({"id": "X", "modo": "rapido", "fases": {}}), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.c, ignore_errors=True)

    def resumir(self, g):
        if g is not None:
            (self.c / "gates.json").write_text(json.dumps(g), encoding="utf-8")
        return subprocess.run([sys.executable, "-I", str(RESUMEN), "--corrida", str(self.c)],
                              capture_output=True, text=True, timeout=60)

    def test_bloqueos_por_control_no_por_entrada(self):
        b = [{"control": "SEG-A", "tope": "N0"}, {"control": "SEG-A", "tope": "N1"}, {"control": "DAT-B", "tope": "N1"}]
        r = self.resumir(gates(bloqueos=b))
        self.assertEqual(r.returncode, 0)
        self.assertIn("Bloqueos: 2 control(es)", r.stderr)
        self.assertIn("3 entrada(s)", r.stderr)
        self.assertNotIn("N0 porque", r.stderr)
        self.assertEqual(r.stdout, "")

    def test_n0_sin_bloqueos_explica(self):
        dom = {"SEG": {"activo": True, "nivel_demostrado": "N0",
                       "niveles": {"N1": {"fallidos": ["SEG-X"], "pendientes": ["SEG-Y", "SEG-Z"]}}},
               "ESC": {"activo": True, "nivel_demostrado": "N1", "niveles": {"N1": {"fallidos": [], "pendientes": []}}}}
        r = self.resumir(gates(dominios=dom))
        self.assertIn("N0 porque N1 no quedó demostrado en 1 dominio(s) (SEG): 1 control(es) de N1 fallan y 2 "
                      "quedan sin evaluar", r.stderr)
        self.assertIn("N1 2/4", r.stderr)
        self.assertNotIn("N2 0/0", r.stderr)
        self.assertIn("(no generado)", r.stderr)

    def test_sin_gates_no_inventa_nivel(self):
        r = self.resumir(None)
        self.assertEqual(r.returncode, 1)
        self.assertIn("Sin gates.json legible", r.stderr)
        self.assertNotIn("Nivel demostrado", r.stderr)


if __name__ == "__main__":
    unittest.main()
