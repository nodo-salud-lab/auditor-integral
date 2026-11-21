"""Tests de scripts/gates.py: algoritmo §4.2 (nivel demostrado/potencial, global = mínimo, bloqueos, cobertura)."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import gates  # noqa: E402
import utiles  # noqa: E402
from normalizar import run as n_run  # noqa: E402

NIVELES = ("N1", "N2", "N3", "N4", "N5")


def c(id_, gate, sev="media", bloquea=False):
    return {"id": id_, "titulo": id_, "dominio": id_.split("-")[0], "gate": gate, "severidad_base": sev,
            "bloquea_global": bloquea, "metodo": "determinista", "esfuerzo": "S"}


def base_indice():
    """Dos dominios (SEG y COD) con un control por nivel; OPS con un control legal."""
    ind = {}
    for d in ("SEG", "COD"):
        for n in NIVELES:
            ind[f"{d}-{n}"] = c(f"{d}-{n}", n)
    ind["OPS-LEGAL"] = c("OPS-LEGAL", "N2", sev="critica")
    return ind


def estados(ind, **cambios):
    """Todos pass salvo los indicados: cambios = {id: estado}."""
    return [{"control": k, "estado": cambios.get(k.replace("-", "_"), cambios.get(k, "pass")), "hallazgos": []}
            for k in ind]


def calc(ind, est, hallazgos=(), banderas=None, exposicion=None):
    return gates.calcular(est, ind, list(hallazgos), banderas or {}, exposicion or set())


class TestNiveles(unittest.TestCase):
    def test_todo_pass_n5(self):
        ind = base_indice()
        g = calc(ind, estados(ind))
        self.assertEqual(g["global"]["nivel_demostrado"], "N5")
        self.assertEqual(g["global"]["nivel_potencial"], "N5")
        self.assertEqual(g["dominios"]["SEG"]["nivel_demostrado"], "N5")

    def test_fail_n1_da_n0(self):
        ind = base_indice()
        g = calc(ind, estados(ind, SEG_N1="fail"))
        self.assertEqual(g["dominios"]["SEG"]["nivel_demostrado"], "N0")
        self.assertEqual(g["dominios"]["SEG"]["nivel_potencial"], "N0")
        self.assertEqual(g["global"]["nivel_demostrado"], "N0")

    def test_fail_n3(self):
        ind = base_indice()
        g = calc(ind, estados(ind, COD_N3="fail"))
        self.assertEqual(g["dominios"]["COD"]["nivel_demostrado"], "N2")
        self.assertEqual(g["dominios"]["COD"]["nivel_potencial"], "N2")
        self.assertEqual(g["dominios"]["SEG"]["nivel_demostrado"], "N5")
        self.assertEqual(g["global"]["nivel_demostrado"], "N2")
        self.assertEqual(g["global"]["cuello_de_botella"], ["COD"])

    def test_no_evaluado_bloquea_demostrado_no_potencial(self):
        ind = base_indice()
        g = calc(ind, estados(ind, SEG_N3="no_evaluado"))
        self.assertEqual(g["dominios"]["SEG"]["nivel_demostrado"], "N2")
        self.assertEqual(g["dominios"]["SEG"]["nivel_potencial"], "N5")
        self.assertIn("N3 no verificado", g["dominios"]["SEG"]["leyenda"])
        self.assertEqual(g["global"]["nivel_demostrado"], "N2")
        self.assertEqual(g["global"]["nivel_potencial"], "N5")

    def test_manual_pendiente_bloquea_tambien_el_potencial(self):
        # §4.2.3: solo no_evaluado es "desconocido" en el potencial (corrección post-verificación).
        ind = base_indice()
        g = calc(ind, estados(ind, COD_N2="manual_pendiente"))
        self.assertEqual(g["dominios"]["COD"]["nivel_demostrado"], "N1")
        self.assertEqual(g["dominios"]["COD"]["nivel_potencial"], "N1")

    def test_fail_despues_de_no_evaluado(self):
        ind = base_indice()
        g = calc(ind, estados(ind, SEG_N2="no_evaluado", SEG_N4="fail"))
        self.assertEqual(g["dominios"]["SEG"]["nivel_demostrado"], "N1")
        self.assertEqual(g["dominios"]["SEG"]["nivel_potencial"], "N3")

    def test_no_aplica_cuenta_como_ok(self):
        ind = base_indice()
        g = calc(ind, estados(ind, SEG_N2="no_aplica"))
        self.assertEqual(g["dominios"]["SEG"]["nivel_demostrado"], "N5")

    def test_dominio_inactivo_no_cuenta(self):
        ind = base_indice()
        ind["UX-N1"] = c("UX-N1", "N1")
        g = calc(ind, estados(ind, UX_N1="no_aplica"))
        self.assertFalse(g["dominios"]["UX"]["activo"])
        self.assertIsNone(g["dominios"]["UX"]["nivel_demostrado"])
        self.assertEqual(g["global"]["nivel_demostrado"], "N5")

    def test_nivel_sin_controles_es_vacuo(self):
        ind = {"ESC-N2": c("ESC-N2", "N2"), "ESC-N4": c("ESC-N4", "N4")}
        g = calc(ind, estados(ind, ESC_N4="fail"))
        self.assertEqual(g["dominios"]["ESC"]["nivel_demostrado"], "N3")

    def test_global_es_minimo(self):
        ind = base_indice()
        g = calc(ind, estados(ind, SEG_N4="fail", COD_N3="no_evaluado"))
        self.assertEqual(g["global"]["nivel_demostrado"], "N2")
        self.assertEqual(g["global"]["nivel_potencial"], "N3")


class TestBloqueos(unittest.TestCase):
    def test_bloquea_global(self):
        ind = base_indice()
        ind["COD-N3"]["bloquea_global"] = True
        g = calc(ind, estados(ind, COD_N3="fail"))
        self.assertEqual(g["dominios"]["COD"]["nivel_demostrado"], "N2")
        self.assertEqual(g["global"]["nivel_demostrado"], "N1")
        self.assertEqual(g["global"]["nivel_potencial"], "N1")
        self.assertEqual(g["global"]["bloqueos"][0]["tipo"], "bloquea_global")
        self.assertEqual(g["global"]["nivel_demostrado_sin_bloqueos"], "N2")

    def test_critico_en_seg(self):
        ind = base_indice()
        est = estados(ind, SEG_N4="fail")
        est[[e["control"] for e in est].index("SEG-N4")]["hallazgos"] = ["H-111111111111"]
        h = [{"id": "H-111111111111", "control": "SEG-N4", "severidad": "critica", "estado_hallazgo": "abierto"}]
        g = calc(ind, est, h)
        self.assertEqual(g["global"]["nivel_demostrado"], "N1")
        self.assertEqual(g["global"]["bloqueos"][0]["tipo"], "critico_seg_dat")

    def test_critico_por_catalogo_sin_detalle(self):
        ind = base_indice()
        ind["COD-N4"]["severidad_base"] = "critica"
        ind["SEG-N4"]["severidad_base"] = "critica"
        g = calc(ind, estados(ind, SEG_N4="fail"))
        self.assertEqual(g["global"]["nivel_demostrado"], "N1")
        g = calc(ind, estados(ind, COD_N4="fail"))  # COD no está en la regla de bloqueo
        self.assertEqual(g["global"]["nivel_demostrado"], "N3")

    def test_alta_en_seg_no_bloquea(self):
        ind = base_indice()
        est = estados(ind, SEG_N4="fail")
        est[[e["control"] for e in est].index("SEG-N4")]["hallazgos"] = ["H-2"]
        g = calc(ind, est, [{"id": "H-2", "control": "SEG-N4", "severidad": "alta", "estado_hallazgo": "abierto"}])
        self.assertEqual(g["global"]["nivel_demostrado"], "N3")
        self.assertEqual(g["global"]["bloqueos"], [])

    def test_ops_legal_critico_no_bloquea(self):  # DECISIONES.md #4
        ind = base_indice()
        g = calc(ind, estados(ind, OPS_LEGAL="fail"))
        self.assertEqual(g["global"]["bloqueos"], [])
        self.assertEqual(g["dominios"]["OPS"]["nivel_demostrado"], "N1")
        self.assertEqual(g["global"]["nivel_demostrado"], "N1")  # por el mínimo, no por bloqueo

    def test_secreto_vivo_n0(self):
        ind = base_indice()
        ind["SEG-SECRETO-REPO"] = c("SEG-SECRETO-REPO", "N3", sev="critica", bloquea=True)  # gate artificial
        g = calc(ind, estados(ind, SEG_SECRETO_REPO="fail"))
        self.assertEqual(g["dominios"]["SEG"]["nivel_demostrado"], "N2")
        self.assertEqual(g["global"]["nivel_demostrado"], "N0")
        self.assertIn("secreto_vivo", {b["tipo"] for b in g["global"]["bloqueos"]})

    def test_datos_reales_expuestos_n0(self):
        ind = base_indice()
        ind["DAT-BUCKETS"] = c("DAT-BUCKETS", "N2", sev="alta")
        est = estados(ind, DAT_BUCKETS="fail")
        g = calc(ind, est, banderas={"datos_reales_cargados": True}, exposicion={"DAT-BUCKETS"})
        self.assertEqual(g["global"]["nivel_demostrado"], "N0")
        self.assertIn("datos_reales_expuestos", {b["tipo"] for b in g["global"]["bloqueos"]})
        g = calc(ind, est, banderas={"datos_reales_cargados": None}, exposicion={"DAT-BUCKETS"})
        self.assertEqual(g["global"]["nivel_demostrado"], "N1")  # por el mínimo de DAT, sin N0
        self.assertNotIn("datos_reales_expuestos", {b["tipo"] for b in g["global"]["bloqueos"]})

    def test_bloqueo_no_sube_nivel(self):
        ind = base_indice()
        ind["SEG-N1"]["bloquea_global"] = True
        g = calc(ind, estados(ind, SEG_N1="fail"))
        self.assertEqual(g["global"]["nivel_demostrado"], "N0")


class TestCoberturaYVeredicto(unittest.TestCase):
    def test_cobertura_por_nivel(self):
        ind = base_indice()
        g = calc(ind, estados(ind, SEG_N2="no_evaluado", COD_N2="fail"))
        n2 = g["cobertura_por_nivel"]["N2"]
        self.assertEqual(n2["aplicables"], 3)
        self.assertEqual(n2["evaluados"], 2)
        self.assertAlmostEqual(n2["cobertura"], 0.667, places=3)
        self.assertFalse(n2["verificado"])
        self.assertIn("N2", g["global"]["niveles_no_verificados"])
        self.assertTrue(g["cobertura_por_nivel"]["N1"]["verificado"])
        self.assertEqual(g["dominios"]["SEG"]["niveles"]["N2"]["pendientes"], ["SEG-N2"])
        self.assertEqual(g["dominios"]["COD"]["niveles"]["N2"]["fallidos"], ["COD-N2"])

    def test_listo_datos_reales(self):
        ind = base_indice()
        self.assertEqual(calc(ind, estados(ind))["global"]["listo_datos_reales"], "SI")
        self.assertEqual(calc(ind, estados(ind, SEG_N2="no_evaluado"))["global"]["listo_datos_reales"], "CONDICIONAL")
        self.assertEqual(calc(ind, estados(ind, SEG_N2="fail"))["global"]["listo_datos_reales"], "NO")
        self.assertEqual(calc(ind, estados(ind, SEG_N1="fail"))["global"]["listo_datos_reales"], "NO")

    def test_hito(self):
        ind = base_indice()
        self.assertIn("Ninguno", calc(ind, estados(ind, SEG_N1="fail"))["global"]["hito"])
        self.assertIn("Demo privada", calc(ind, estados(ind, SEG_N2="fail"))["global"]["hito"])

    def test_determinista(self):
        ind = base_indice()
        a = utiles.volcar_json(calc(ind, estados(ind, SEG_N3="no_evaluado", COD_N2="fail")))
        b = utiles.volcar_json(calc(ind, estados(ind, SEG_N3="no_evaluado", COD_N2="fail")))
        self.assertEqual(a, b)


class TestCorrida(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)

    def tearDown(self):
        ap.limpiar(self.tmp)

    def test_app_sembrada(self):
        corrida = ap.preparar_corrida(self.tmp)
        n_run.main([str(corrida)])
        p = subprocess.run([sys.executable, str(RAIZ / "scripts" / "gates.py"), "--corrida", str(corrida)],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        g = json.loads((corrida / "gates.json").read_text(encoding="utf-8"))
        self.assertTrue((corrida / "estado.json").is_file())
        self.assertEqual(g["global"]["nivel_demostrado"], "N0")
        self.assertEqual(g["dominios"]["SEG"]["nivel_demostrado"], "N0")
        tipos = {b["tipo"] for b in g["global"]["bloqueos"]}
        self.assertIn("secreto_vivo", tipos)
        self.assertEqual(g["global"]["listo_datos_reales"], "NO")


if __name__ == "__main__":
    unittest.main()
