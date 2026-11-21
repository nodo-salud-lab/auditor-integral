"""Ronda 9 (DECISIONES.md #13): DAT-PII-REPO nunca da pass en análisis estático.

La detección de datos personales por patrones nunca es exhaustiva (formatos, codificaciones, anidamientos), así que
la ausencia de hallazgos no demuestra ausencia de PII. Se comprueba: el pase interno del check no basta; un hallazgo
sigue dando fail y bloqueando; «nada que analizar» sigue siendo no_aplica; el motivo lo declara.
"""
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import catalogo  # noqa: E402
import estado  # noqa: E402
import gates  # noqa: E402
import utiles  # noqa: E402

FECHA = "2026-11-21"
PASE = "check:datos_confidenciales.no_trackeado"


def ctl():
    indice = {c["id"]: c for c in catalogo.cargar_catalogo()}
    c = dict(indice["DAT-PII-REPO"])
    c["aplicabilidad"] = "aplica"
    return c, indice


def herr(est):
    return {utiles.canon_herramienta("datos_confidenciales"): est}


class TestPiiNoDemostrable(unittest.TestCase):
    def test_catalogo(self):
        c, _ = ctl()
        self.assertEqual(c["evidencia_pass"], "no_demostrable_estatico")
        self.assertTrue(c["bloquea_global"])
        self.assertIn("no lo demuestra", c["motivo_no_demostrable"])

    def test_pase_interno_del_check_no_basta(self):
        c, _ = ctl()
        for modo in ("estandar", "profundo"):
            with self.subTest(modo=modo):
                r = estado.calcular({c["id"]: c}, [], herr("ok"), {PASE}, modo, FECHA)[0]
                self.assertEqual(r["estado"], "no_evaluado", r)
                self.assertIn("no lo demuestra", r["motivo"])

    def test_motivo_cita_lo_no_inspeccionado(self):
        c, _ = ctl()
        r = estado.calcular({c["id"]: c}, [], herr("ok"), {PASE}, "estandar", FECHA,
                            motivos_sin_pase={"datos_confidenciales": "2 archivo(s) de datos no inspeccionables"})[0]
        self.assertEqual(r["estado"], "no_evaluado")
        self.assertIn("2 archivo(s) de datos no inspeccionables", r["motivo"])

    def test_hallazgo_sigue_dando_fail_y_bloquea(self):
        c, indice = ctl()
        h = {"id": "H-1", "control": "DAT-PII-REPO", "severidad": "critica", "confianza": "alta",
             "fuente": [{"herramienta": "check", "regla": "check:datos_confidenciales.pii_tabular"}],
             "ubicacion": {"archivo": "data/u.csv", "linea": 1, "commit": None}}
        r = estado.calcular({c["id"]: c}, [h], herr("ok"), {PASE}, "estandar", FECHA)[0]
        self.assertEqual(r["estado"], "fail")
        g = gates.calcular([r], indice, [h], {}, set())
        self.assertIn("DAT-PII-REPO", [b["control"] for b in g["global"]["bloqueos"]])

    def test_nada_que_analizar_es_no_aplica(self):
        c, _ = ctl()
        r = estado.calcular({c["id"]: c}, [], herr("no_aplica"), set(), "estandar", FECHA)[0]
        self.assertEqual(r["estado"], "no_aplica", r)

    def test_herramienta_con_error_no_evaluado(self):
        c, _ = ctl()
        for est in ("error", "timeout", "ausente"):
            with self.subTest(est=est):
                r = estado.calcular({c["id"]: c}, [], herr(est), set(), "estandar", FECHA)[0]
                self.assertEqual(r["estado"], "no_evaluado", r)


if __name__ == "__main__":
    unittest.main()
