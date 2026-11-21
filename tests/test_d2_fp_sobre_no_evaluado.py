"""D2 (investigacion/18-evaluacion-herramienta.md): un falso positivo de la IA sobre un crítico/alto debe seguir
mostrando su bloqueo (DECISIONES.md #10) aunque el control quede no_evaluado por OTRA causa.

Caso real (app sembrada): triage-fp marcó falso_positivo H-d06d0e597385 de DAT-RLS-PERMISIVA. Sin ese hallazgo el
control quedó no_evaluado con «splinter: sin datos…» (herramienta que no corrió). veredictos.ajustar solo escribía
el motivo FP si el estado era pass/no_aplica, así que gates.py (roadmap.es_motivo_fp_ia exige que el motivo EMPIECE
por la frase FP) no lo reconoció como pendiente_ia: los bloqueos bajaron de 14 a 13.

Regla: si el control queda no_evaluado (por la vía que sea) y tiene ids en fp_graves/fp_criticos, el motivo empieza
por la frase FP y conserva el motivo previo detrás («…; <previo>»), recortado a 300 sin perder la frase. Un fail
nunca se toca.
"""
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import gates  # noqa: E402
import roadmap  # noqa: E402
import veredictos  # noqa: E402
from test_f3a_veredictos import Base, hallazgo, ver  # noqa: E402

PREVIO = ("splinter: sin datos de la herramienta (no se ejecutó); rls_estatico: cobertura parcial del control "
          "(sin hallazgos, no basta para pass)")


def control(cid, estado, motivo=None):
    return {"control": cid, "estado": estado, "motivo": motivo, "metodo": "determinista", "duracion_s": None,
            "herramienta": None, "hallazgos": []}


def res(criticos=None, graves=None, forzar=None):
    criticos = criticos or {}
    graves = graves if graves is not None else dict(criticos)
    return {"pases": {}, "forzar": forzar or {}, "fp_criticos": criticos, "fp_graves": graves, "aplicadas": [],
            "descartadas": []}


class TestAjustarNoEvaluadoPrevio(unittest.TestCase):
    def test_critico_sobre_no_evaluado_por_otra_causa(self):
        cs = [control("DAT-RLS-PERMISIVA", "no_evaluado", PREVIO)]
        veredictos.ajustar(cs, res(criticos={"DAT-RLS-PERMISIVA": ["H-d06d0e597385"]}))
        m = cs[0]["motivo"]
        self.assertEqual(cs[0]["estado"], "no_evaluado")
        self.assertTrue(m.startswith(roadmap.MOTIVO_FP_CRITICO), m)
        self.assertTrue(roadmap.es_motivo_fp_ia(m))
        self.assertIn("H-d06d0e597385", m)
        self.assertIn("; splinter: sin datos", m, "el motivo previo se conserva detrás")

    def test_alto_sobre_no_evaluado_por_otra_causa(self):
        cs = [control("SEG-Y", "no_evaluado", "semgrep: herramienta ausente")]
        veredictos.ajustar(cs, res(graves={"SEG-Y": ["H-9"]}))
        self.assertTrue(cs[0]["motivo"].startswith(roadmap.MOTIVO_FP_ALTO), cs[0]["motivo"])
        self.assertTrue(cs[0]["motivo"].endswith("; semgrep: herramienta ausente"))

    def test_no_evaluado_sin_motivo_previo(self):
        cs = [control("SEG-Y", "no_evaluado", None)]
        veredictos.ajustar(cs, res(criticos={"SEG-Y": ["H-1"]}))
        self.assertTrue(roadmap.es_motivo_fp_ia(cs[0]["motivo"]))
        self.assertNotIn("; ", cs[0]["motivo"].split("sin ella", 1)[1])

    def test_recorte_no_pierde_la_frase_fp(self):
        cs = [control("SEG-Y", "no_evaluado", "x" * 1000)]
        veredictos.ajustar(cs, res(criticos={"SEG-Y": ["H-1", "H-2", "H-3", "H-4"]}))
        m = cs[0]["motivo"]
        self.assertLessEqual(len(m), 300)
        self.assertTrue(roadmap.es_motivo_fp_ia(m))
        self.assertIn("requiere verificación humana", m)

    def test_idempotente(self):
        cs = [control("DAT-RLS-PERMISIVA", "no_evaluado", PREVIO)]
        r = res(criticos={"DAT-RLS-PERMISIVA": ["H-1"]})
        veredictos.ajustar(cs, r)
        primero = cs[0]["motivo"]
        veredictos.ajustar(cs, r)
        self.assertEqual(cs[0]["motivo"], primero)
        self.assertEqual(primero.count("falso positivo"), 1)

    def test_con_forzar_la_frase_fp_va_primero(self):
        cs = [control("SEG-Y", "no_evaluado", "semgrep: herramienta ausente")]
        veredictos.ajustar(cs, res(criticos={"SEG-Y": ["H-1"]}, forzar={"SEG-Y": "veredicto inválido descartado"}))
        m = cs[0]["motivo"]
        self.assertTrue(roadmap.es_motivo_fp_ia(m), m)
        self.assertIn("veredicto inválido descartado", m)
        self.assertIn("semgrep: herramienta ausente", m)

    def test_idempotente_con_forzar_desde_pass(self):
        # verificador: la rama forzar anteponía su motivo antes de comprobar la frase FP → doble frase
        cs = [control("X", "pass", None)]
        r = res(criticos={"X": ["H-1"]}, forzar={"X": "la IA no pudo evaluar (línea 3): bla"})
        veredictos.ajustar(cs, r)
        primero = cs[0]["motivo"]
        self.assertTrue(roadmap.es_motivo_fp_ia(primero), primero)
        veredictos.ajustar(cs, r)
        self.assertEqual(cs[0]["motivo"], primero)
        self.assertEqual(primero.count("falso positivo"), 1)
        self.assertEqual(primero.count("la IA no pudo evaluar"), 1)

    def test_idempotente_con_forzar_desde_no_evaluado(self):
        cs = [control("X", "no_evaluado", PREVIO)]
        r = res(graves={"X": ["H-2"]}, forzar={"X": "veredicto inválido descartado"})
        veredictos.ajustar(cs, r)
        primero = cs[0]["motivo"]
        veredictos.ajustar(cs, r)
        self.assertEqual(cs[0]["motivo"], primero)
        self.assertEqual(primero.count("veredicto inválido descartado"), 1)

    def test_nunca_toca_un_fail(self):
        cs = [control("SEG-Y", "fail", None)]
        cs[0]["hallazgos"] = ["H-2"]
        veredictos.ajustar(cs, res(criticos={"SEG-Y": ["H-1"]}))
        self.assertEqual((cs[0]["estado"], cs[0]["motivo"], cs[0]["hallazgos"]), ("fail", None, ["H-2"]))

    def test_sin_fp_no_cambia_el_motivo(self):
        cs = [control("SEG-Y", "no_evaluado", PREVIO)]
        veredictos.ajustar(cs, res(criticos={"OTRO": ["H-1"]}))
        self.assertEqual(cs[0]["motivo"], PREVIO)

    def test_pass_sigue_igual_que_antes(self):
        cs = [control("SEG-Y", "pass", None)]
        veredictos.ajustar(cs, res(criticos={"SEG-Y": ["H-1"]}))
        self.assertEqual(cs[0]["estado"], "no_evaluado")
        self.assertEqual(cs[0]["motivo"], "falso positivo crítico según IA (H-1): requiere verificación humana; "
                                          "no hay pass sin ella")

    def test_gates_reconoce_el_bloqueo_pendiente_ia(self):
        cs = [control("DAT-RLS-PERMISIVA", "no_evaluado", PREVIO)]
        veredictos.ajustar(cs, res(criticos={"DAT-RLS-PERMISIVA": ["H-1"]}))
        indice = {"DAT-RLS-PERMISIVA": {"id": "DAT-RLS-PERMISIVA", "dominio": "DAT", "gate": "N1",
                                        "severidad_base": "critica"}}
        h = {"id": "H-1", "control": "DAT-RLS-PERMISIVA", "severidad": "critica", "confianza": "alta",
             "estado_hallazgo": "falso_positivo", "triage": {"veredicto": "falso_positivo", "razon": "x"}}
        g = gates.calcular(cs, indice, [h], {}, set())
        bl = [b for b in g["global"]["bloqueos"] if b["control"] == "DAT-RLS-PERMISIVA"]
        self.assertTrue(bl, "el bloqueo no debe desaparecer")
        for b in bl:
            self.assertTrue(b["pendiente_ia"])
            self.assertIn("IA", b["nota"])


class TestPuntaAPunta(Base):
    """Pipeline real (digest → veredictos.main → estado → gates.json): crítico de gitleaks cuyo adaptador no dejó
    meta (herramienta sin datos). Sin el hallazgo, el control queda no_evaluado por la herramienta, no por la IA."""

    def test_fp_critico_con_herramienta_sin_datos_mantiene_bloqueo(self):
        h = hallazgo(1, "SEG-SECRETO-BUNDLE", "critica", "dist/assets/index.js", 1, gate="N1", herramienta="gitleaks")
        self.poner_hallazgos([h])
        self.assertEqual(self.estado()["SEG-SECRETO-BUNDLE"]["estado"], "fail")
        self.poner_veredictos([ver("triage-fp", "SEG-SECRETO-BUNDLE", "falso_positivo", hallazgo_id=h["id"],
                                   ubicaciones=["dist/assets/index.js:1"])])
        self.assertEqual(veredictos.main([str(self.corrida)]), 0)
        est = json.loads((self.corrida / "estado.json").read_text(encoding="utf-8"))
        e = next(c for c in est["controles"] if c["control"] == "SEG-SECRETO-BUNDLE")
        self.assertEqual(e["estado"], "no_evaluado")
        self.assertTrue(roadmap.es_motivo_fp_ia(e["motivo"]), e["motivo"])
        g = json.loads((self.corrida / "gates.json").read_text(encoding="utf-8"))
        bl = [b for b in g["global"]["bloqueos"] if b["control"] == "SEG-SECRETO-BUNDLE"]
        self.assertTrue(any(b["tipo"] == "secreto_vivo" and b["tope"] == "N0" for b in bl), bl)
        for b in bl:
            self.assertTrue(b["pendiente_ia"])
            self.assertEqual(b["hallazgos"], [h["id"]])
        self.assertEqual(g["global"]["nivel_demostrado"], "N0")


if __name__ == "__main__":
    unittest.main()
