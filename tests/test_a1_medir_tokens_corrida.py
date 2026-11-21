"""A1 (investigacion/18-evaluacion-herramienta.md): el paso 10 de /auditar llama «medir_tokens.py --corrida "$C"»
(skills/auditar/SKILL.md), pero el script solo aceptaba el directorio posicional: rc 2 «unrecognized arguments».

Regla: se aceptan las dos formas.
- posicional DIR: igual que antes (stdout o --salida).
- --corrida C: busca transcripts en C (o en el DIR posicional si se da) y escribe C/tokens.json salvo --salida.
- Fail-closed: si no hay ningún mensaje con message.usage, NO se escribe tokens.json (un total 0 se leería como
  medido y dentro de presupuesto); el informe sigue diciendo «no medido». rc 0: no es un error de la corrida.
"""
import json
import re
import shlex
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import medir_tokens  # noqa: E402
from test_f3a_medir_tokens import asistente  # noqa: E402


class TestCorrida(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)
        self.corrida = self.tmp / "corrida"
        self.corrida.mkdir()
        (self.corrida / "hallazgos.jsonl").write_text(json.dumps({"id": "H-1", "control": "X"}) + "\n",
                                                      encoding="utf-8")
        self.trans = self.tmp / "transcripts"
        self.trans.mkdir()
        (self.trans / "agent-1.jsonl").write_text(
            asistente("m1", 10, 5, agentType="triage-fp") + "\n", encoding="utf-8")

    def tearDown(self):
        ap.limpiar(self.tmp)

    def leer(self):
        return json.loads((self.corrida / "tokens.json").read_text(encoding="utf-8"))

    def test_solo_corrida_con_transcripts_escribe_tokens_json(self):
        (self.corrida / "transcripts").mkdir()
        (self.corrida / "transcripts" / "agent-1.jsonl").write_text(asistente("m1", 7, 3) + "\n", encoding="utf-8")
        self.assertEqual(medir_tokens.main(["--corrida", str(self.corrida)]), 0)
        self.assertEqual(self.leer()["total"]["total"], 10)

    def test_posicional_mas_corrida_escribe_en_la_corrida(self):
        self.assertEqual(medir_tokens.main([str(self.trans), "--corrida", str(self.corrida), "--modo", "rapido"]), 0)
        d = self.leer()
        self.assertEqual(d["total"]["total"], 15)
        self.assertEqual(d["por_fase"], {"f4d_triage": 15})
        self.assertIn("presupuesto", d)

    def test_salida_explicita_manda(self):
        salida = self.tmp / "otro.json"
        self.assertEqual(medir_tokens.main([str(self.trans), "--corrida", str(self.corrida),
                                            "--salida", str(salida)]), 0)
        self.assertTrue(salida.is_file())
        self.assertFalse((self.corrida / "tokens.json").exists())

    def test_sin_mensajes_no_escribe_cero(self):
        self.assertEqual(medir_tokens.main(["--corrida", str(self.corrida)]), 0)
        self.assertFalse((self.corrida / "tokens.json").exists(), "un total 0 no es una medición")

    def test_sin_mensajes_con_salida_tampoco(self):
        vacio = self.tmp / "vacio"
        vacio.mkdir()
        salida = self.tmp / "t.json"
        self.assertEqual(medir_tokens.main([str(vacio), "--salida", str(salida)]), 0)
        self.assertFalse(salida.exists())

    def test_errores_de_uso(self):
        self.assertEqual(medir_tokens.main([]), 2)
        self.assertEqual(medir_tokens.main(["--corrida", str(self.tmp / "no-existe")]), 2)
        self.assertEqual(medir_tokens.main([str(self.tmp / "no-existe"), "--corrida", str(self.corrida)]), 2)

    def test_la_linea_del_skill_es_aceptada(self):
        texto = (RAIZ / "skills" / "auditar" / "SKILL.md").read_text(encoding="utf-8")
        lineas = [l for l in texto.splitlines() if "medir_tokens.py" in l and l.strip().startswith("python3")]
        self.assertEqual(len(lineas), 1, lineas)
        comando = re.sub(r"\s+#.*$", "", lineas[0].strip())
        args = shlex.split(comando)[2:]   # sin «python3» ni la ruta del script
        args = [str(self.corrida) if a == "$C" else a for a in args]
        (self.corrida / "transcripts").mkdir()
        (self.corrida / "transcripts" / "agent-x.jsonl").write_text(asistente("m9", 1, 1) + "\n", encoding="utf-8")
        self.assertEqual(medir_tokens.main(args), 0)
        self.assertEqual(self.leer()["total"]["total"], 2)


class TestCorridaNoEsFuenteDeTranscripts(unittest.TestCase):
    """Verificador (A1): con --corrida sin DIR, el script recorría todos los *.jsonl de la corrida, incluido
    veredictos.jsonl (lo escribe la IA): una línea con message.usage bastaba para un tokens.json «medido». Y si no
    había medición, un tokens.json anterior quedaba y el informe lo mostraba como actual."""

    def setUp(self):
        self.tmp = ap.tmp_dir(self)
        self.corrida = self.tmp / "corrida"
        self.corrida.mkdir()

    def tearDown(self):
        ap.limpiar(self.tmp)

    def sembrar_artefactos(self, base):
        linea = asistente("m-ia", 5, 5) + "\n"
        for n in ("veredictos.jsonl", "hallazgos.jsonl", "hallazgos_todos.jsonl", "hallazgos_ia.jsonl",
                  "ejecuciones.jsonl"):
            (base / n).write_text(linea, encoding="utf-8")

    def test_veredictos_con_usage_en_la_corrida_no_es_medicion(self):
        self.sembrar_artefactos(self.corrida)
        self.assertEqual(medir_tokens.main(["--corrida", str(self.corrida), "--modo", "profundo"]), 0)
        self.assertFalse((self.corrida / "tokens.json").exists(), "veredictos.jsonl no es un transcript")

    def test_jsonl_suelto_en_la_corrida_no_se_lee(self):
        (self.corrida / "otro").mkdir()
        (self.corrida / "otro" / "agent-1.jsonl").write_text(asistente("m1", 7, 3) + "\n", encoding="utf-8")
        self.assertEqual(medir_tokens.main(["--corrida", str(self.corrida)]), 0)
        self.assertFalse((self.corrida / "tokens.json").exists(), "solo cuenta <corrida>/transcripts/")

    def test_subcarpeta_transcripts_si_se_mide_y_excluye_artefactos(self):
        t = self.corrida / "transcripts"
        t.mkdir()
        (t / "agent-1.jsonl").write_text(asistente("m1", 7, 3) + "\n", encoding="utf-8")
        self.sembrar_artefactos(t)
        self.assertEqual(medir_tokens.main(["--corrida", str(self.corrida)]), 0)
        d = json.loads((self.corrida / "tokens.json").read_text(encoding="utf-8"))
        self.assertEqual(d["total"]["total"], 10)
        self.assertEqual(d["archivos"], 1)

    def test_dir_posicional_excluye_artefactos_de_corrida(self):
        self.sembrar_artefactos(self.corrida)
        salida = self.tmp / "t.json"
        self.assertEqual(medir_tokens.main([str(self.corrida), "--salida", str(salida)]), 0)
        self.assertFalse(salida.exists())

    def test_tokens_json_previo_se_retira_si_no_hay_medicion(self):
        previo = self.corrida / "tokens.json"
        previo.write_text(json.dumps({"total": {"total": 123, "mensajes": 1}}), encoding="utf-8")
        self.assertEqual(medir_tokens.main(["--corrida", str(self.corrida)]), 0)
        self.assertFalse(previo.exists(), "un tokens.json viejo se leería como medición actual")
        obsoleto = self.corrida / "tokens.json.obsoleto"
        self.assertTrue(obsoleto.is_file(), "se conserva renombrado, no se borra")
        import render_informe
        self.assertIsNone(render_informe._tokens(None))


if __name__ == "__main__":
    unittest.main()
