"""U-1 / H-3 (investigacion/18): `--salida` mal tipeado no debe crear una corrida vacía en silencio.

Antes, `bin/auditar digest RUTA --salida corrida-typo` hacía `mkdir -p` y `crear_corrida`: rc 0 y un digest «completo»
sobre datos vacíos. Ahora los subcomandos que exigen una corrida previa (scan, normalize, gates, report, perfil,
digest, veredictos) fallan con rc 4 y un mensaje claro si --salida no existe o no tiene run.json, sin crear nada.
stack, all y doctor siguen creando la corrida. La validación previa (--salida dentro del proyecto fuera de
.auditoria → rc 2) se mantiene y va primero.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
AUDITAR = RAIZ / "bin" / "auditar"
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
EXIGEN_CORRIDA = ("scan", "normalize", "gates", "report", "perfil", "digest", "veredictos")


def entorno():
    env = {k: v for k, v in os.environ.items() if not k.startswith("AUDITOR_")}
    env.update(TMPDIR=str(TMP_BASE), GIT_CEILING_DIRECTORIES=str(TMP_BASE), AUDITOR_SIN_RED="1",
               AUDITOR_PYTHON=sys.executable)
    return env


class TestSalidaExigeCorrida(unittest.TestCase):
    def setUp(self):
        TMP_BASE.mkdir(parents=True, exist_ok=True)
        self.dir = Path(tempfile.mkdtemp(dir=TMP_BASE))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.proy = self.dir / "proy"
        self.proy.mkdir()
        (self.proy / "package.json").write_text('{"dependencies": {}}', encoding="utf-8")

    def auditar(self, *args, cwd=None):
        return subprocess.run(["bash", str(AUDITAR), *map(str, args)], capture_output=True, text=True,
                              env=entorno(), timeout=120, cwd=cwd)

    def test_salida_inexistente_rc4_sin_crear_nada(self):
        for sub in EXIGEN_CORRIDA:
            with self.subTest(sub=sub):
                typo = self.dir / f"corrida-typo-{sub}"
                r = self.auditar(sub, self.proy, "--salida", typo)
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertIn("--salida no existe", r.stderr)
                self.assertIn("no se crea una vacía", r.stderr)
                self.assertFalse(typo.exists(), "no debe crear la carpeta")
                self.assertEqual(r.stdout.strip(), "", "stdout no debe anunciar una corrida")

    def test_typo_dentro_de_auditoria_tambien_rc4(self):
        typo = self.proy / ".auditoria" / "corrida-typo"
        r = self.auditar("digest", self.proy, "--salida", typo)
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertFalse(typo.exists())

    def test_carpeta_existente_sin_run_json_rc4(self):
        vacia = self.dir / "vacia"
        vacia.mkdir()
        r = self.auditar("gates", self.proy, "--salida", vacia)
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertIn("falta run.json", r.stderr)
        self.assertEqual(list(vacia.iterdir()), [], "no debe escribir nada en la carpeta")

    def test_pista_si_ruta_es_una_corrida(self):
        corrida = self.dir / "c1"
        self.assertEqual(self.auditar("stack", self.proy, "--salida", corrida).returncode, 0)
        r = self.auditar("gates", corrida, "--salida", self.proy)
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertIn("invirtió RUTA y --salida", r.stderr)

    def test_corrida_valida_sigue_funcionando(self):
        corrida = self.dir / "c1"
        r = self.auditar("stack", self.proy, "--salida", corrida)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((corrida / "run.json").is_file())
        r = self.auditar("normalize", self.proy, "--salida", corrida)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip().splitlines()[-1], str(corrida.resolve()))

    def test_stack_all_y_doctor_crean_la_corrida(self):
        for sub in ("stack", "doctor"):
            with self.subTest(sub=sub):
                nueva = self.dir / f"nueva-{sub}"
                r = self.auditar(sub, self.proy, "--salida", nueva)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertTrue((nueva / "run.json").is_file())
        sin_ruta = self.dir / "doctor-sin-ruta"
        r = self.auditar("doctor", "--salida", sin_ruta)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((sin_ruta / "herramientas.json").is_file())

    def test_validacion_dentro_del_proyecto_sigue_en_rc2(self):
        r = self.auditar("digest", self.proy, "--salida", self.proy / "salidas" / "x")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn(".auditoria", r.stderr)
        self.assertFalse((self.proy / "salidas").exists())

    def test_sin_salida_y_sin_corrida_previa_sigue_rc4(self):
        r = self.auditar("digest", self.proy)
        self.assertEqual(r.returncode, 4, r.stderr)
        self.assertFalse((self.proy / ".auditoria").exists())

    def test_ayuda_documenta_el_rc4(self):
        r = self.auditar("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--salida no es una corrida", r.stdout)


if __name__ == "__main__":
    unittest.main()
