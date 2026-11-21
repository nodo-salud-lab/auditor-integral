"""Tests de validacion/metricas.py (§11.3 y §11.5 del PLAN_MAESTRO).

Cubre: intervalo de Wilson al 95 %, coincidencia hallazgo↔defecto
(control + archivo + línea ±3, ausencias, paquetes, asignación uno a uno),
falsos positivos en controles limpios, métricas por estrato y export CSV.
"""

import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "validacion"))

import metricas  # noqa: E402


def hallazgo(control, archivo, linea=None, evidencia="", **extra):
    h = {
        "id": "H-x",
        "control": control,
        "ubicacion": {"archivo": archivo, "linea": linea},
        "evidencia": evidencia,
        "fuente": [{"herramienta": "prueba", "version": "0", "regla": "r"}],
        "estado_hallazgo": "abierto",
        "triage": None,
    }
    h.update(extra)
    return h


def defecto(id_, control, archivo, linea=None, gate="N1", severidad="critica", **extra):
    d = {"id": id_, "control": control, "archivo": archivo, "gate": gate,
         "severidad": severidad, "detectable_en_F1": True, "reservado": False}
    if linea is not None:
        d["linea"] = linea
    d.update(extra)
    return d


def limpio(id_, control, archivo, linea=None, **extra):
    l = {"id": id_, "control": control, "archivo": archivo, "reservado": False}
    if linea is not None:
        l["linea"] = linea
    l.update(extra)
    return l


class TestWilson(unittest.TestCase):
    def test_valor_conocido_36_de_40(self):
        # §11.2: con 40 positivos y sensibilidad 0,90 el IC95 % es 0,77-0,96
        inf, sup = metricas.wilson(36, 40)
        self.assertAlmostEqual(inf, 0.7695, places=3)
        self.assertAlmostEqual(sup, 0.9604, places=3)
        self.assertEqual(round(inf, 2), 0.77)
        self.assertEqual(round(sup, 2), 0.96)

    def test_valor_conocido_54_de_60(self):
        # §11.2: con 60 y 0,90 es 0,80-0,95
        inf, sup = metricas.wilson(54, 60)
        self.assertEqual(round(inf, 2), 0.80)
        self.assertEqual(round(sup, 2), 0.95)

    def test_extremos(self):
        inf, sup = metricas.wilson(0, 10)
        self.assertEqual(inf, 0.0)
        self.assertAlmostEqual(sup, 0.2775, places=3)
        inf, sup = metricas.wilson(10, 10)
        self.assertAlmostEqual(inf, 0.7225, places=3)
        self.assertEqual(sup, 1.0)

    def test_n_cero_devuelve_none(self):
        self.assertEqual(metricas.wilson(0, 0), (None, None))

    def test_entradas_invalidas(self):
        with self.assertRaises(ValueError):
            metricas.wilson(5, 3)
        with self.assertRaises(ValueError):
            metricas.wilson(-1, 3)


class TestCoincidencia(unittest.TestCase):
    def test_vp_con_linea_dentro_de_tolerancia(self):
        r = metricas.cruzar([hallazgo("SEG-X", "a.js", 13)], [defecto("D01", "SEG-X", "a.js", 10)], [])
        self.assertEqual(r["defectos"]["D01"]["detectado"], True)
        self.assertEqual(r["vp"], 1)
        self.assertEqual(r["fp"], 0)

    def test_fn_fuera_de_tolerancia(self):
        r = metricas.cruzar([hallazgo("SEG-X", "a.js", 14)], [defecto("D01", "SEG-X", "a.js", 10)], [])
        self.assertFalse(r["defectos"]["D01"]["detectado"])
        self.assertEqual(r["fp"], 1)

    def test_tolerancia_configurable(self):
        r = metricas.cruzar([hallazgo("SEG-X", "a.js", 20)], [defecto("D01", "SEG-X", "a.js", 10)], [], tolerancia=10)
        self.assertTrue(r["defectos"]["D01"]["detectado"])

    def test_control_distinto_no_coincide(self):
        r = metricas.cruzar([hallazgo("SEG-Y", "a.js", 10)], [defecto("D01", "SEG-X", "a.js", 10)], [])
        self.assertFalse(r["defectos"]["D01"]["detectado"])

    def test_archivo_distinto_no_coincide(self):
        r = metricas.cruzar([hallazgo("SEG-X", "b.js", 10)], [defecto("D01", "SEG-X", "a.js", 10)], [])
        self.assertFalse(r["defectos"]["D01"]["detectado"])

    def test_normaliza_rutas(self):
        h = hallazgo("SEG-X", "/repo/app/./src/a.js", 10)
        r = metricas.cruzar([h], [defecto("D01", "SEG-X", "src/a.js", 10)], [], raiz="/repo/app")
        self.assertTrue(r["defectos"]["D01"]["detectado"])
        r = metricas.cruzar([hallazgo("SEG-X", "./src/a.js", 10)], [defecto("D01", "SEG-X", "src/a.js", 10)], [])
        self.assertTrue(r["defectos"]["D01"]["detectado"])

    def test_sin_linea_en_hallazgo_o_defecto(self):
        r = metricas.cruzar([hallazgo("COD-REPRO", "README.md", None)], [defecto("D01", "COD-REPRO", "README.md")], [])
        self.assertTrue(r["defectos"]["D01"]["detectado"])
        r = metricas.cruzar([hallazgo("SEG-X", "a.js", None)], [defecto("D01", "SEG-X", "a.js", 7)], [])
        self.assertTrue(r["defectos"]["D01"]["detectado"])

    def test_ausencia_coincide_solo_por_control(self):
        d = defecto("D01", "OPS-HEALTH", "server/index.js", ausencia=True)
        r = metricas.cruzar([hallazgo("OPS-HEALTH", ".", None)], [d], [])
        self.assertTrue(r["defectos"]["D01"]["detectado"])

    def test_paquete_debe_mencionarse(self):
        d1 = defecto("D01", "SEG-DEPS-CVE-CRIT", "package-lock.json", 40, paquete="react")
        d2 = defecto("D02", "SEG-DEPS-CVE-CRIT", "package-lock.json", 50, paquete="lodash")
        hs = [hallazgo("SEG-DEPS-CVE-CRIT", "package-lock.json", None, evidencia="react-dom@18.0.0 GHSA-x"),
              hallazgo("SEG-DEPS-CVE-CRIT", "package-lock.json", None, evidencia="lodash@4.17.4 CVE-2019-10744")]
        r = metricas.cruzar(hs, [d1, d2], [])
        self.assertFalse(r["defectos"]["D01"]["detectado"])  # react-dom no es react
        self.assertTrue(r["defectos"]["D02"]["detectado"])
        self.assertEqual(r["fp"], 1)

    def test_paquete_ignora_linea(self):
        d = defecto("D01", "SEG-DEPS-CVE-CRIT", "package-lock.json", 40, paquete="lodash")
        r = metricas.cruzar([hallazgo("SEG-DEPS-CVE-CRIT", "package-lock.json", 1, evidencia="lodash@4.17.4")], [d], [])
        self.assertTrue(r["defectos"]["D01"]["detectado"])

    def test_asignacion_uno_a_uno(self):
        ds = [defecto("D01", "SEG-X", "a.js", 10), defecto("D02", "SEG-X", "a.js", 11)]
        r = metricas.cruzar([hallazgo("SEG-X", "a.js", 10)], ds, [])
        detectados = [k for k, v in r["defectos"].items() if v["detectado"]]
        self.assertEqual(detectados, ["D01"])  # se asigna al más cercano
        r = metricas.cruzar([hallazgo("SEG-X", "a.js", 10), hallazgo("SEG-X", "a.js", 11)], ds, [])
        self.assertEqual(r["vp"], 2)

    def test_hallazgo_duplicado_es_fp(self):
        ds = [defecto("D01", "SEG-X", "a.js", 10)]
        r = metricas.cruzar([hallazgo("SEG-X", "a.js", 10), hallazgo("SEG-X", "a.js", 10)], ds, [])
        self.assertEqual((r["vp"], r["fp"]), (1, 1))


class TestLimpios(unittest.TestCase):
    def test_limpio_violado_por_hallazgo_no_asignado(self):
        r = metricas.cruzar([hallazgo("SEG-X", "a.js", 20)], [], [limpio("L01", "SEG-X", "a.js", 21)])
        self.assertTrue(r["limpios"]["L01"]["disparado"])
        self.assertEqual(r["fp_limpios"], 1)

    def test_hallazgo_asignado_a_defecto_no_viola_limpio(self):
        r = metricas.cruzar([hallazgo("SEG-X", "a.js", 10)],
                            [defecto("D01", "SEG-X", "a.js", 10)],
                            [limpio("L01", "SEG-X", "a.js", 12)])
        self.assertFalse(r["limpios"]["L01"]["disparado"])

    def test_hallazgo_se_atribuye_al_limpio_mas_cercano(self):
        ls = [limpio("L01", "SEG-X", "a.js", 3), limpio("L02", "SEG-X", "a.js", 4)]
        r = metricas.cruzar([hallazgo("SEG-X", "a.js", 4)], [], ls)
        self.assertFalse(r["limpios"]["L01"]["disparado"])
        self.assertTrue(r["limpios"]["L02"]["disparado"])

    def test_limpio_con_paquete(self):
        ls = [limpio("L01", "SEG-DEPS-CVE-CRIT", "package-lock.json", 10, paquete="react")]
        r = metricas.cruzar([hallazgo("SEG-DEPS-CVE-CRIT", "package-lock.json", None, evidencia="react-dom@1")], [], ls)
        self.assertFalse(r["limpios"]["L01"]["disparado"])
        r = metricas.cruzar([hallazgo("SEG-DEPS-CVE-CRIT", "package-lock.json", None, evidencia="react@1 GHSA")], [], ls)
        self.assertTrue(r["limpios"]["L01"]["disparado"])


class TestTriageYFiltros(unittest.TestCase):
    def test_tras_triage_excluye_falsos_positivos(self):
        hs = [hallazgo("SEG-X", "a.js", 10),
              hallazgo("SEG-X", "b.js", 1, triage={"veredicto": "falso_positivo", "razon": "x", "modelo": "m"}),
              hallazgo("SEG-X", "c.js", 1, estado_hallazgo="falso_positivo")]
        ds = [defecto("D01", "SEG-X", "a.js", 10)]
        antes = metricas.cruzar(hs, ds, [])
        despues = metricas.cruzar(hs, ds, [], tras_triage=True)
        self.assertEqual(antes["fp"], 2)
        self.assertEqual(despues["fp"], 0)

    def test_filtrar_por_subconjunto(self):
        ds = [defecto("D01", "SEG-X", "a.js", 1, reservado=True),
              defecto("D02", "SEG-X", "a.js", 30, detectable_en_F1=False)]
        self.assertEqual([d["id"] for d in metricas.filtrar(ds, "reservado")], ["D01"])
        self.assertEqual([d["id"] for d in metricas.filtrar(ds, "desarrollo")], ["D02"])
        self.assertEqual([d["id"] for d in metricas.filtrar(ds, "f1")], ["D01"])
        self.assertEqual(len(metricas.filtrar(ds, "todo")), 2)


class TestResumenYCsv(unittest.TestCase):
    def setUp(self):
        self.ds = [defecto("D01", "SEG-A", "a.js", 1, gate="N1", severidad="critica"),
                   defecto("D02", "SEG-A", "a.js", 30, gate="N1", severidad="critica"),
                   defecto("D03", "SEG-B", "b.js", 5, gate="N2", severidad="alta")]
        self.ls = [limpio("L01", "SEG-A", "a.js", 60), limpio("L02", "SEG-B", "b.js", 40)]
        self.hs = [hallazgo("SEG-A", "a.js", 1), hallazgo("SEG-B", "b.js", 5), hallazgo("SEG-A", "a.js", 60)]

    def test_resumen(self):
        r = metricas.cruzar(self.hs, self.ds, self.ls)
        filas = metricas.resumen(r, self.ds, self.ls)
        por = {(f["metrica"], f["estrato"]): f for f in filas}
        g = por[("sensibilidad", "global")]
        self.assertEqual((g["x"], g["n"]), (2, 3))
        self.assertAlmostEqual(g["proporcion"], 2 / 3)
        self.assertIsNotNone(g["ic95_inf"])
        self.assertEqual((por[("sensibilidad", "gate=N1")]["x"], por[("sensibilidad", "gate=N1")]["n"]), (1, 2))
        self.assertEqual((por[("sensibilidad", "severidad=alta")]["x"], por[("sensibilidad", "severidad=alta")]["n"]), (1, 1))
        self.assertEqual((por[("sensibilidad", "control=SEG-B")]["x"], por[("sensibilidad", "control=SEG-B")]["n"]), (1, 1))
        v = por[("vpp", "global")]
        self.assertEqual((v["x"], v["n"]), (2, 3))
        f = por[("fp_limpios", "global")]
        self.assertEqual((f["x"], f["n"]), (1, 2))

    def test_csv_exporta_y_se_lee(self):
        r = metricas.cruzar(self.hs, self.ds, self.ls)
        with tempfile.TemporaryDirectory() as tmp:
            rutas = metricas.exportar_csv(r, self.ds, self.ls, Path(tmp))
            for ruta in rutas:
                self.assertTrue(Path(ruta).exists())
            with open(Path(tmp) / "metricas_resumen.csv", newline="", encoding="utf-8") as fh:
                filas = list(csv.DictReader(fh))
            self.assertIn("ic95_inf", filas[0])
            with open(Path(tmp) / "metricas_defectos.csv", newline="", encoding="utf-8") as fh:
                defs = list(csv.DictReader(fh))
            self.assertEqual(len(defs), 3)
            self.assertEqual({d["detectado"] for d in defs}, {"0", "1"})


class TestCli(unittest.TestCase):
    def test_cli_de_punta_a_punta(self):
        verdad = (
            '[[defecto]]\nid = "D01"\ncontrol = "SEG-A"\narchivo = "a.js"\nlinea = 3\n'
            'gate = "N1"\nseveridad = "critica"\ndetectable_en_F1 = true\nreservado = false\n\n'
            '[[limpio]]\nid = "L01"\ncontrol = "SEG-A"\narchivo = "a.js"\nlinea = 40\nreservado = false\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            (t / "verdad.toml").write_text(verdad, encoding="utf-8")
            (t / "hallazgos.jsonl").write_text(json.dumps(hallazgo("SEG-A", "a.js", 4)) + "\n\n", encoding="utf-8")
            salida = io.StringIO()
            codigo = metricas.main(["--hallazgos", str(t / "hallazgos.jsonl"), "--verdad", str(t / "verdad.toml"),
                                    "--csv", str(t / "out")], salida=salida)
            self.assertEqual(codigo, 0)
            self.assertIn("sensibilidad", salida.getvalue())
            self.assertTrue((t / "out" / "metricas_resumen.csv").exists())


class TestFiltrosCombinados(unittest.TestCase):
    """Integración F1: filtros por dominio/gate/F1 y hallazgos de defectos fuera del subconjunto."""

    def test_hallazgo_de_defecto_fuera_del_subconjunto_no_es_fp(self):
        ds = [defecto("D01", "SEG-A", "a.js", 1)]
        fuera = [defecto("D03", "SEG-A", "a.js", 20, reservado=True)]
        ls = [limpio("L01", "SEG-A", "a.js", 22)]
        hs = [hallazgo("SEG-A", "a.js", 1), hallazgo("SEG-A", "a.js", 20)]
        r = metricas.cruzar(hs, ds, ls, defectos_fuera=fuera)
        self.assertEqual((r["vp"], r["fp"], r["fn"]), (1, 0, 0))
        self.assertEqual(r["fp_limpios"], 0)
        self.assertEqual(r["fuera_de_subconjunto"], 1)

    def test_asignacion_conjunta_con_defectos_fuera(self):
        # Un solo hallazgo en la línea 10: está más cerca del defecto excluido (línea 10) que del
        # medido (línea 12). La asignación es conjunta: no debe acreditarse al medido.
        ds = [defecto("D01", "SEG-A", "a.js", 12)]
        fuera = [defecto("D03", "SEG-A", "a.js", 10, reservado=True)]
        r = metricas.cruzar([hallazgo("SEG-A", "a.js", 10)], ds, [], defectos_fuera=fuera)
        self.assertEqual((r["vp"], r["fn"], r["fuera_de_subconjunto"]), (0, 1, 1))

    def test_filtrar_dominio_gate_y_f1(self):
        ds = [defecto("D01", "SEG-A", "a.js", 1, gate="N1"),
              defecto("D02", "DAT-B", "b.sql", 1, gate="N1"),
              defecto("D04", "SEG-C", "c.js", 1, gate="N2"),
              defecto("D05", "SEG-D", "d.js", 1, gate="N1", detectable_en_F1=False)]
        r = metricas.filtrar_extra(ds, dominio="SEG", gate="N1", solo_f1=True)
        self.assertEqual([d["id"] for d in r], ["D01"])
        self.assertEqual(len(metricas.filtrar_extra(ds)), 4)

    def test_cli_con_filtros(self):
        verdad = (
            '[[defecto]]\nid = "D01"\ncontrol = "SEG-A"\narchivo = "a.js"\nlinea = 3\n'
            'gate = "N1"\nseveridad = "critica"\ndetectable_en_F1 = true\nreservado = false\n\n'
            '[[defecto]]\nid = "D02"\ncontrol = "DAT-A"\narchivo = "b.sql"\nlinea = 3\n'
            'gate = "N1"\nseveridad = "critica"\ndetectable_en_F1 = true\nreservado = false\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            (t / "verdad.toml").write_text(verdad, encoding="utf-8")
            (t / "h.jsonl").write_text(json.dumps(hallazgo("SEG-A", "a.js", 3)) + "\n"
                                       + json.dumps(hallazgo("DAT-A", "b.sql", 3)) + "\n", encoding="utf-8")
            salida = io.StringIO()
            metricas.main(["--hallazgos", str(t / "h.jsonl"), "--verdad", str(t / "verdad.toml"),
                           "--dominio", "SEG", "--gate", "N1", "--solo-f1"], salida=salida)
            texto = salida.getvalue()
            self.assertIn("VP 1 · FP 0 · FN 0", texto)
            self.assertIn("1/1", texto)


if __name__ == "__main__":
    unittest.main()
