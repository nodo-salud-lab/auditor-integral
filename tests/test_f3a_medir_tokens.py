"""F3-A: scripts/medir_tokens.py — tokens reales desde transcripts de subagentes de Claude Code (PLAN_MAESTRO §9).

*.jsonl con message.usage (input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens);
se deduplica por message.id (Claude Code repite la misma respuesta en varias líneas) y se suma por agente y total.
"""
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import medir_tokens  # noqa: E402


def asistente(mid, inp, out, cr=0, cc=0, **extra):
    d = {"type": "assistant", "message": {"id": mid, "role": "assistant", "model": "m",
                                          "usage": {"input_tokens": inp, "output_tokens": out,
                                                    "cache_read_input_tokens": cr,
                                                    "cache_creation_input_tokens": cc}}}
    d.update(extra)
    return json.dumps(d)


class TestMedir(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)
        self.dir = self.tmp / "transcripts"
        (self.dir / "sub").mkdir(parents=True)
        # agente A: msg_1 aparece 3 veces (streaming), msg_2 una vez; una línea de usuario y una inválida
        (self.dir / "agent-a1.jsonl").write_text("\n".join([
            json.dumps({"type": "user", "message": {"role": "user", "content": "hola"}}),
            asistente("msg_1", 10, 1, 100, 5),
            asistente("msg_1", 10, 1, 100, 5),
            asistente("msg_1", 10, 7, 100, 5),
            "{esto no es json",
            asistente("msg_2", 3, 20, 0, 0),
        ]) + "\n", encoding="utf-8")
        (self.dir / "agent-a1.meta.json").write_text(json.dumps({"agentType": "revisor-autorizacion"}),
                                                     encoding="utf-8")
        # agente B: nombre desde el campo de la línea; un mensaje repetido entre archivos no se cuenta dos veces
        (self.dir / "sub" / "agent-b2.jsonl").write_text("\n".join([
            asistente("msg_3", 1000, 50, agentType="triage-fp"),
            asistente("msg_2", 3, 20, 0, 0),
        ]) + "\n", encoding="utf-8")
        (self.dir / "otro.txt").write_text("ignorar", encoding="utf-8")

    def tearDown(self):
        ap.limpiar(self.tmp)

    def test_suma_por_agente_deduplicando(self):
        r = medir_tokens.medir(self.dir)
        a = r["por_agente"]["revisor-autorizacion"]
        self.assertEqual((a["input_tokens"], a["output_tokens"], a["cache_read_input_tokens"],
                          a["cache_creation_input_tokens"], a["mensajes"]), (13, 27, 100, 5, 2))
        b = r["por_agente"]["triage-fp"]
        self.assertEqual((b["input_tokens"], b["output_tokens"], b["mensajes"]), (1000, 50, 1))
        t = r["total"]
        self.assertEqual((t["input_tokens"], t["output_tokens"], t["mensajes"]), (1013, 77, 3))
        self.assertEqual(t["total"], 1013 + 77 + 100 + 5)
        self.assertEqual(r["archivos"], 2)
        self.assertEqual(r["lineas_invalidas"], 1)
        self.assertEqual(r["mensajes_duplicados"], 3)

    def test_por_fase_y_presupuesto(self):
        r = medir_tokens.medir(self.dir, modo="estandar")
        self.assertEqual(r["por_fase"]["f4a_autorizacion"], r["por_agente"]["revisor-autorizacion"]["total"])
        self.assertEqual(r["por_fase"]["f4d_triage"], r["por_agente"]["triage-fp"]["total"])
        self.assertEqual(r["presupuesto"]["techo_duro"], 100000)
        self.assertFalse(r["presupuesto"]["excede_techo_duro"])

    def test_nombre_por_archivo_si_no_hay_tipo(self):
        d = self.tmp / "t2"
        d.mkdir()
        (d / "agent-zz9.jsonl").write_text(asistente("m1", 1, 1) + "\n", encoding="utf-8")
        r = medir_tokens.medir(d)
        self.assertEqual(list(r["por_agente"]), ["agent-zz9"])
        self.assertEqual(r["por_fase"], {"orquestacion": 2})

    def test_cli_escribe_tokens_json(self):
        salida = self.tmp / "tokens.json"
        self.assertEqual(medir_tokens.main([str(self.dir), "--salida", str(salida), "--modo", "rapido"]), 0)
        datos = json.loads(salida.read_text(encoding="utf-8"))
        self.assertEqual(datos["total"]["total"], 1013 + 77 + 100 + 5)
        self.assertNotIn(str(self.dir), json.dumps(datos), "no se escriben rutas absolutas")
        self.assertEqual(medir_tokens.main([str(self.tmp / "no-existe"), "--salida", str(salida)]), 2)

    def test_compatible_con_el_informe(self):
        import render_informe
        r = medir_tokens.medir(self.dir)
        total, fases = render_informe._tokens(r)
        self.assertEqual(total, r["total"]["total"])
        self.assertEqual(fases["f4d_triage"], 1050)


if __name__ == "__main__":
    unittest.main()
