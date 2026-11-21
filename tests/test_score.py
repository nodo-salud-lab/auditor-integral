"""Tests de scripts/score.py: puntaje 0-100, cobertura y letra A-E por dominio (§4.4; informativos, no deciden el nivel).

DECISIONES.md #1: pesos de OpenSSF Scorecard (10/7,5/5/2,5; info 0), agregación G1 de Scorecard
(Σw·m·pass / Σw·m sobre controles evaluados) y letra A-E por el peor fail abierto (SonarQube MQR).
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import score  # noqa: E402
from normalizar import run as n_run  # noqa: E402

PESOS = {"critica": 10, "alta": 7.5, "media": 5, "baja": 2.5, "info": 0}


def c(id_, sev):
    return {"id": id_, "dominio": id_.split("-")[0], "severidad_base": sev, "gate": "N1"}


def calc(controles, estados, banderas=None, umbral=70, metodo="agrupado_scorecard"):
    ind = {x["id"]: x for x in controles}
    est = [{"control": k, "estado": v} for k, v in estados.items()]
    return score.calcular(est, ind, PESOS, umbral, banderas or {}, factor=1.5, dominios_factor=("SEG", "DAT"),
                          banderas_factor=("salud", "pagos"), metodo=metodo)


class TestScore(unittest.TestCase):
    def test_puntaje_ponderado(self):
        ctrls = [c("SEG-A", "critica"), c("SEG-B", "alta"), c("SEG-C", "media")]
        s = calc(ctrls, {"SEG-A": "pass", "SEG-B": "fail", "SEG-C": "pass"})
        self.assertAlmostEqual(s["dominios"]["SEG"]["puntaje"], round(100 * 15 / 22.5, 1))
        self.assertEqual(s["dominios"]["SEG"]["cobertura"], 1.0)
        self.assertFalse(s["dominios"]["SEG"]["gris"])

    def test_no_evaluados_fuera_del_puntaje_y_bajan_cobertura(self):
        ctrls = [c("SEG-A", "critica"), c("SEG-B", "alta"), c("SEG-C", "media"), c("SEG-D", "baja")]
        s = calc(ctrls, {"SEG-A": "pass", "SEG-B": "no_evaluado", "SEG-C": "manual_pendiente", "SEG-D": "no_aplica"})
        d = s["dominios"]["SEG"]
        self.assertEqual(d["puntaje"], 100.0)
        self.assertEqual(d["aplicables"], 3)
        self.assertEqual(d["evaluados"], 1)
        self.assertAlmostEqual(d["cobertura"], 0.333, places=3)
        self.assertTrue(d["gris"])
        self.assertIn("insuficiente", d["leyenda"])

    def test_sin_evaluados(self):
        s = calc([c("UX-A", "alta")], {"UX-A": "no_evaluado"})
        self.assertIsNone(s["dominios"]["UX"]["puntaje"])
        self.assertTrue(s["dominios"]["UX"]["gris"])
        self.assertIsNone(s["dominios"]["UX"]["letra"])

    def test_umbral_cobertura(self):
        ctrls = [c("SEG-A", "alta"), c("SEG-B", "alta"), c("SEG-C", "alta"), c("SEG-D", "alta")]
        est = {"SEG-A": "pass", "SEG-B": "pass", "SEG-C": "fail", "SEG-D": "no_evaluado"}
        self.assertFalse(calc(ctrls, est, umbral=70)["dominios"]["SEG"]["gris"])
        self.assertTrue(calc(ctrls, est, umbral=80)["dominios"]["SEG"]["gris"])


class TestGlobalG1(unittest.TestCase):
    """G1: Global = 100·Σ w(c)·m(c)·[pass] / Σ w(c)·m(c) sobre TODOS los controles evaluados (Scorecard)."""

    def test_global_agrupado_sobre_controles(self):
        ctrls = [c("SEG-A", "critica"), c("SEG-B", "baja"), c("COD-A", "alta")]
        s = calc(ctrls, {"SEG-A": "pass", "SEG-B": "fail", "COD-A": "fail"})
        self.assertAlmostEqual(s["global"]["puntaje"], round(100 * 10 / (10 + 2.5 + 7.5), 1))
        self.assertEqual(s["global"]["metodo"], "agrupado_scorecard")

    def test_global_no_es_media_de_dominios(self):
        # Con G3 (media de dominios ponderada por aplicables) daría 50; con G1 pesa cada control.
        ctrls = [c("SEG-A", "critica"), c("COD-A", "baja")]
        s = calc(ctrls, {"SEG-A": "pass", "COD-A": "fail"})
        self.assertAlmostEqual(s["global"]["puntaje"], 80.0)

    def test_no_evaluados_excluidos_del_global(self):
        ctrls = [c("SEG-A", "alta"), c("COD-A", "alta"), c("UX-A", "critica")]
        s = calc(ctrls, {"SEG-A": "pass", "COD-A": "fail", "UX-A": "no_evaluado"})
        self.assertAlmostEqual(s["global"]["puntaje"], 50.0)
        self.assertAlmostEqual(s["global"]["cobertura"], round(2 / 3, 3))

    def test_factor_salud_o_pagos_por_control(self):
        ctrls = [c("SEG-A", "alta"), c("COD-A", "alta")]
        s = calc(ctrls, {"SEG-A": "pass", "COD-A": "fail"}, banderas={"pagos": True})
        self.assertAlmostEqual(s["global"]["puntaje"], round(100 * 7.5 * 1.5 / (7.5 * 1.5 + 7.5), 1))
        self.assertTrue(s["global"]["factor_aplicado"])
        s = calc(ctrls, {"SEG-A": "pass", "COD-A": "fail"}, banderas={"pagos": None})
        self.assertAlmostEqual(s["global"]["puntaje"], 50.0)
        self.assertFalse(s["global"]["factor_aplicado"])

    def test_factor_no_cambia_puntaje_de_dominio(self):
        ctrls = [c("SEG-A", "alta"), c("SEG-B", "media")]
        sin = calc(ctrls, {"SEG-A": "pass", "SEG-B": "fail"})
        con = calc(ctrls, {"SEG-A": "pass", "SEG-B": "fail"}, banderas={"salud": True})
        self.assertEqual(sin["dominios"]["SEG"]["puntaje"], con["dominios"]["SEG"]["puntaje"])

    def test_metodo_legado_g3(self):
        ctrls = [c("SEG-A", "alta"), c("SEG-B", "alta"), c("COD-A", "alta")]
        s = calc(ctrls, {"SEG-A": "pass", "SEG-B": "pass", "COD-A": "fail"},
                 metodo="media de dominios ponderada por controles aplicables")
        self.assertAlmostEqual(s["global"]["puntaje"], round((100 * 2 + 0 * 1) / 3, 1))

    def test_metodo_media_simple_g2(self):
        ctrls = [c("SEG-A", "alta"), c("SEG-B", "alta"), c("COD-A", "alta")]
        s = calc(ctrls, {"SEG-A": "pass", "SEG-B": "pass", "COD-A": "fail"}, metodo="media_simple_dominios")
        self.assertAlmostEqual(s["global"]["puntaje"], 50.0)

    def test_metodo_desconocido_falla(self):
        with self.assertRaises(ValueError):
            calc([c("SEG-A", "alta")], {"SEG-A": "pass"}, metodo="inventado")

    def test_sin_evaluados_global_none(self):
        s = calc([c("SEG-A", "alta")], {"SEG-A": "no_evaluado"})
        self.assertIsNone(s["global"]["puntaje"])
        self.assertTrue(s["global"]["gris"])


class TestLetra(unittest.TestCase):
    """Letra A-E por el peor fail abierto del dominio, estilo SonarQube MQR (no compensatoria)."""

    def test_letras_por_peor_fail(self):
        casos = {"critica": "E", "alta": "D", "media": "C", "baja": "B", "info": "A"}
        for sev, letra in casos.items():
            with self.subTest(sev=sev):
                ctrls = [c("SEG-A", sev), c("SEG-B", "baja"), c("SEG-C", "critica")]
                est = {"SEG-A": "fail", "SEG-B": "pass", "SEG-C": "pass"}
                self.assertEqual(calc(ctrls, est)["dominios"]["SEG"]["letra"], letra)

    def test_a_sin_fallos(self):
        ctrls = [c("COD-A", "critica"), c("COD-B", "alta")]
        self.assertEqual(calc(ctrls, {"COD-A": "pass", "COD-B": "pass"})["dominios"]["COD"]["letra"], "A")

    def test_peor_gana_aunque_el_puntaje_sea_alto(self):
        ctrls = [c(f"SEG-{i}", "critica") for i in range(20)] + [c("SEG-X", "critica")]
        est = {f"SEG-{i}": "pass" for i in range(20)}
        est["SEG-X"] = "fail"
        d = calc(ctrls, est)["dominios"]["SEG"]
        self.assertGreater(d["puntaje"], 90)
        self.assertEqual(d["letra"], "E")

    def test_no_evaluado_y_manual_no_cuentan_como_fallo(self):
        ctrls = [c("UX-A", "critica"), c("UX-B", "alta"), c("UX-C", "baja")]
        est = {"UX-A": "no_evaluado", "UX-B": "manual_pendiente", "UX-C": "pass"}
        self.assertEqual(calc(ctrls, est)["dominios"]["UX"]["letra"], "A")

    def test_letra_global_es_la_peor_de_los_dominios(self):
        ctrls = [c("SEG-A", "media"), c("COD-A", "alta"), c("UX-A", "baja")]
        s = calc(ctrls, {"SEG-A": "fail", "COD-A": "fail", "UX-A": "pass"})
        self.assertEqual(s["global"]["letra"], "D")

    def test_letra_global_none_sin_evaluados(self):
        s = calc([c("SEG-A", "alta")], {"SEG-A": "no_evaluado"})
        self.assertIsNone(s["global"]["letra"])


class TestConfigReal(unittest.TestCase):
    def test_cargar_config_lee_pesos_scorecard(self):
        cfg = score.cargar_config()
        self.assertEqual(cfg["severidad"], {"critica": 10, "alta": 7.5, "media": 5, "baja": 2.5, "info": 0})
        self.assertEqual(cfg["metodo"], "agrupado_scorecard")
        self.assertEqual(cfg["letras"], {"ninguno": "A", "baja": "B", "media": "C", "alta": "D", "critica": "E"})
        self.assertEqual(cfg["origen"], "plataforma")
        self.assertEqual(cfg["umbral"], 70)


class TestCli(unittest.TestCase):
    def test_cli(self):
        tmp = ap.tmp_dir()
        try:
            corrida = ap.preparar_corrida(tmp)
            n_run.main([str(corrida)])
            subprocess.run([sys.executable, str(RAIZ / "scripts" / "gates.py"), str(corrida)], check=True,
                           capture_output=True)
            p = subprocess.run([sys.executable, str(RAIZ / "scripts" / "score.py"), "--corrida", str(corrida)],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            s = json.loads((corrida / "score.json").read_text(encoding="utf-8"))
            self.assertIn("SEG", s["dominios"])
            self.assertIn(s["dominios"]["SEG"]["letra"], ("A", "B", "C", "D", "E"))
            self.assertEqual(s["umbral_cobertura"], 0.7)
            self.assertEqual(s["origen_pesos"], "plataforma")
            self.assertEqual(s["global"]["metodo"], "agrupado_scorecard")
            self.assertEqual(s["pesos"]["alta"], 7.5)
        finally:
            ap.limpiar(tmp)


if __name__ == "__main__":
    unittest.main()
