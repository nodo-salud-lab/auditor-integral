"""F3-A: subcomandos de bin/auditar — perfil, digest y veredictos (aplicar + recalcular gates e informe)."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402

AUDITAR = RAIZ / "bin" / "auditar"


def auditar(*args):
    return subprocess.run([str(AUDITAR), *map(str, args)], capture_output=True, text=True, timeout=300)


class TestSubcomandosF3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = ap.tmp_dir(cls)
        cls.proyecto = cls.tmp / "proyecto"
        (cls.proyecto / "src").mkdir(parents=True)
        (cls.proyecto / "src" / "server.js").write_text(
            "const app = require('express')();\n"
            "app.get('/api/citas/:id', async (req, res) => {\n"
            "  res.json(await db.query('SELECT * FROM citas WHERE id = $1', [req.params.id]));\n"
            "});\n", encoding="utf-8")
        cls.corrida = cls.tmp / "corrida"
        for sub in ("stack", "normalize"):
            p = auditar(sub, cls.proyecto, "--salida", cls.corrida)
            assert p.returncode == 0, (sub, p.stderr)

    @classmethod
    def tearDownClass(cls):
        ap.limpiar(cls.tmp)

    def test_1_perfil(self):
        r = self.tmp / "respuestas.json"
        r.write_text(json.dumps({"respuestas": {"9": "no"}, "declaraciones": {"datos_reales_cargados": False}}),
                     encoding="utf-8")
        p = auditar("perfil", self.proyecto, "--salida", self.corrida, "--respuestas", r)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), str(self.corrida))
        perfil = json.loads((self.corrida / "perfil.json").read_text(encoding="utf-8"))
        self.assertIs(perfil["banderas"]["datos_reales_cargados"], False)

    def test_2_digest(self):
        p = auditar("digest", self.proyecto, "--salida", self.corrida)
        self.assertEqual(p.returncode, 0, p.stderr)
        ind = json.loads((self.corrida / "digest" / "indice.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(ind["digests"]), ["arquitectura", "autorizacion", "triage", "ux"])

    def test_3_veredictos_sin_archivo_falla(self):
        p = auditar("veredictos", self.proyecto, "--salida", self.corrida)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("veredictos.jsonl", p.stderr)

    def test_4_veredictos_aplica_y_recalcula(self):
        v = {"agente": "revisor-arquitectura", "control": "SEG-STRIDE", "veredicto": "fail",
             "razon": "No hay modelo de amenazas para el flujo de citas.", "modelo": "m",
             "ubicaciones": ["src/server.js:2"]}
        (self.corrida / "veredictos.jsonl").write_text(json.dumps(v) + "\nbasura\n", encoding="utf-8")
        p = auditar("veredictos", self.proyecto, "--salida", self.corrida)
        self.assertEqual(p.returncode, 0, p.stderr)
        estado = {c["control"]: c for c in json.loads((self.corrida / "estado.json").read_text())["controles"]}
        self.assertEqual(estado["SEG-STRIDE"]["estado"], "fail")
        self.assertTrue((self.corrida / "gates.json").is_file())
        informe = (self.corrida / "informe.md").read_text(encoding="utf-8")
        self.assertIn("Decisiones de la IA", informe)
        self.assertIn("SEG-STRIDE", informe.split("Decisiones de la IA", 1)[1])

    def test_5_respuestas_solo_con_perfil(self):
        p = auditar("digest", self.proyecto, "--salida", self.corrida, "--respuestas", "x.json")
        self.assertEqual(p.returncode, 2)

    def test_ayuda_lista_subcomandos(self):
        p = auditar("--help")
        for sub in ("perfil", "digest", "veredictos"):
            self.assertIn(sub, p.stdout)


if __name__ == "__main__":
    unittest.main()
