"""Tests de config/*.toml y herramientas.lock (§4.3, §4.4, §5.1, §9)."""
import tomllib
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CONFIG = RAIZ / "config"
MODOS = ("rapido", "estandar", "profundo")


def leer(nombre):
    with open(CONFIG / nombre, "rb") as f:
        return tomllib.load(f)


class TestUmbrales(unittest.TestCase):
    def setUp(self):
        self.u = leer("umbrales.toml")["umbral"]

    def test_cada_umbral_tiene_origen_y_fuente(self):
        self.assertGreaterEqual(len(self.u), 15)
        for nombre, d in self.u.items():
            with self.subTest(umbral=nombre):
                self.assertIn("valor", d)
                self.assertIn(d.get("origen"), ("norma", "default-herramienta", "propuesta"))
                self.assertTrue(str(d.get("fuente", "")).strip())
                self.assertTrue(str(d.get("unidad", "")).strip())
                if d["origen"] in ("norma", "default-herramienta"):
                    self.assertTrue(d["fuente"].startswith("https://"), "norma o default citan URL verificable")

    def test_valores_de_norma_del_plan(self):
        self.assertEqual(self.u["cwv_lcp_p75"]["valor"], 2.5)
        self.assertEqual(self.u["cwv_inp_p75"]["valor"], 200)
        self.assertEqual(self.u["cwv_cls_p75"]["valor"], 0.1)
        self.assertEqual(self.u["objetivo_tactil_min"]["valor"], 24)
        self.assertEqual(self.u["cobertura_codigo_nuevo"]["valor"], 80)
        self.assertEqual(self.u["duplicacion_codigo_nuevo"]["valor"], 3)
        for k in ("cwv_lcp_p75", "objetivo_tactil_min"):
            self.assertEqual(self.u[k]["origen"], "norma")
        # DECISIONES.md #2: Sonar way es default de herramienta, no norma.
        self.assertEqual(self.u["cobertura_codigo_nuevo"]["origen"], "default-herramienta")

    def test_valores_del_plan_con_origen_de_la_decision_2(self):
        # Los valores del plan no cambian; el origen se reetiquetó con evidencia (investigacion/12).
        esperado = {"cobertura_global": (60, "norma"), "duplicacion_global": (5, "propuesta"),
                    "complejidad_ciclomatica_max": (15, "default-herramienta"),
                    "mutacion_criticos": (60, "default-herramienta"),
                    "cobertura_controles_puntaje": (70, "propuesta"), "sus_n4": (68, "norma")}
        for k, (v, origen) in esperado.items():
            self.assertEqual(self.u[k]["valor"], v, k)
            self.assertEqual(self.u[k]["origen"], origen, k)

    def test_elecciones_de_la_decision_2(self):
        self.assertEqual(self.u["complejidad_cognitiva_max"]["valor"], 15)
        self.assertEqual(self.u["lighthouse_performance_min"]["valor"], 90)
        self.assertEqual(self.u["recuperacion_despliegue_fallido_h"]["valor"], 24)
        self.assertEqual(self.u["iua_bandas"]["valor"], [50, 90])
        self.assertEqual(self.u["iua_bandas"]["origen"], "default-herramienta")


class TestPesos(unittest.TestCase):
    def setUp(self):
        self.p = leer("pesos.toml")

    def test_pesos_severidad(self):
        s = self.p["severidad"]
        # DECISIONES.md #1: pesos de riesgo de OpenSSF Scorecard (investigacion/11-pesos-evidencia.md).
        self.assertEqual((s["critica"], s["alta"], s["media"], s["baja"], s["info"]), (10, 7.5, 5, 2.5, 0))
        self.assertEqual(s["origen"], "plataforma")
        self.assertTrue(s["fuente"].startswith("https://github.com/ossf/scorecard/"))
        self.assertEqual(self.p["puntaje_global"]["metodo"], "agrupado_scorecard")
        self.assertEqual({k: self.p["rating_dominio"][k] for k in ("ninguno", "baja", "media", "alta", "critica")},
                         {"ninguno": "A", "baja": "B", "media": "C", "alta": "D", "critica": "E"})

    def test_iua_suma_100(self):
        iua = self.p["iua"]["componentes"]
        self.assertEqual(sum(iua.values()), 100)
        self.assertEqual(len(iua), 6)

    def test_multiplicador_contextual(self):
        m = self.p["multiplicador_contextual"]
        self.assertEqual(m["factor"], 1.5)
        self.assertEqual(sorted(m["dominios"]), ["DAT", "SEG"])
        self.assertEqual(sorted(m["banderas"]), ["pagos", "salud"])


class TestPresupuesto(unittest.TestCase):
    def setUp(self):
        self.t = leer("presupuesto_tokens.toml")

    def test_metas_suman_total_y_bajo_techo(self):
        esperado = {"rapido": (11000, 15000, 25000), "estandar": (49000, 60000, 100000),
                    "profundo": (79000, 130000, 130000)}
        for modo in MODOS:
            with self.subTest(modo=modo):
                fases = self.t["fase"]
                suma = sum(f[modo] for f in fases.values())
                meta, tope, techo = esperado[modo]
                self.assertEqual(suma, meta)
                self.assertEqual(self.t["total"][modo]["meta"], meta)
                self.assertEqual(self.t["total"][modo]["tope_meta"], tope)
                self.assertEqual(self.t["total"][modo]["techo_duro"], techo)

    def test_fases_deterministas_cero_tokens(self):
        for nombre in ("f0_preparar", "f2_3_escaneos", "f5_compuertas"):
            for modo in MODOS:
                self.assertEqual(self.t["fase"][nombre][modo], 0)

    def test_digest_y_diff(self):
        self.assertEqual(self.t["mecanismos"]["digest_tope_por_juicio"], 4000)
        self.assertEqual(self.t["auditar_diff"]["estandar"], 15000)
        self.assertEqual(self.t["origen"], "propuesta")


class TestLock(unittest.TestCase):
    def test_lock_versiones_instaladas(self):
        lock = leer("herramientas.lock")
        h = lock["herramientas"]
        for nombre in ("gitleaks", "semgrep", "osv-scanner", "zizmor"):
            with self.subTest(herramienta=nombre):
                self.assertTrue(h[nombre]["disponible"])
                self.assertRegex(h[nombre]["version"], r"^\d+\.\d+")
                self.assertRegex(h[nombre]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(h["gitleaks"]["version"], "8.30.1")
        self.assertEqual(h["semgrep"]["version"], "1.181.0")
        self.assertIn("generado", lock)


if __name__ == "__main__":
    unittest.main()
