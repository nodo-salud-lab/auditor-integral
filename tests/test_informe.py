"""Tests de scripts/roadmap.py y scripts/render_informe.py (informe.md, hoja-de-ruta.md, merged.sarif), sin LLM."""
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import render_informe  # noqa: E402
import roadmap  # noqa: E402
from normalizar import run as n_run  # noqa: E402


def c(id_, gate, sev="media", esfuerzo="M", bloquea=False):
    return {"id": id_, "titulo": f"Título {id_}", "dominio": id_.split("-")[0], "gate": gate, "severidad_base": sev,
            "esfuerzo": esfuerzo, "bloquea_global": bloquea, "metodo": "determinista", "herramientas": ["x"],
            "fuente": "investigacion/02-seguridad.md"}


def g_dom(**niveles):
    return {"global": {"nivel_demostrado": min(niveles.values()), "cuello_de_botella": [
        d for d, n in niveles.items() if n == min(niveles.values())]},
        "dominios": {d: {"activo": True, "nivel_demostrado": n} for d, n in niveles.items()}}


class TestRoadmap(unittest.TestCase):
    def setUp(self):
        self.ind = {x["id"]: x for x in [
            c("SEG-A1", "N1", "critica", "S", bloquea=True), c("SEG-A2", "N2", "alta", "S"),
            c("SEG-A3", "N3", "critica", "L"), c("SEG-A4", "N4", "media"),
            c("COD-B2", "N2", "media", "S"), c("COD-B3", "N3", "alta", "M"), c("COD-B4", "N4", "critica", "S"),
        ]}

    def _est(self, **e):
        return [{"control": k, "estado": e.get(k.replace("-", "_"), "pass"), "motivo": None, "hallazgos": []}
                for k in self.ind]

    def test_solo_siguiente_nivel_mas_criticos(self):
        est = self._est(SEG_A1="fail", SEG_A2="fail", SEG_A3="fail", SEG_A4="no_evaluado", COD_B3="fail", COD_B4="fail")
        items = roadmap.calcular(est, self.ind, g_dom(SEG="N0", COD="N2"), [])
        ids = [i["control"] for i in items]
        self.assertEqual(set(ids), {"SEG-A1", "COD-B3", "SEG-A3", "COD-B4"})
        self.assertNotIn("SEG-A2", ids)  # N2 de SEG: más adelante (SEG está en N0)
        self.assertNotIn("SEG-A4", ids)

    def test_orden_bloqueo_y_grupos(self):
        est = self._est(SEG_A1="fail", SEG_A3="fail", COD_B3="fail", COD_B4="fail")
        items = roadmap.calcular(est, self.ind, g_dom(SEG="N0", COD="N2"), [])
        self.assertEqual(items[0]["control"], "SEG-A1")
        self.assertEqual(items[0]["grupo"], "esta_semana")
        grupos = {i["control"]: i["grupo"] for i in items}
        self.assertEqual(grupos["COD-B4"], "esta_semana")   # crítico de esfuerzo S
        self.assertEqual(grupos["COD-B3"], "siguiente_nivel")
        self.assertEqual(grupos["SEG-A3"], "criticos_otros_niveles")

    def test_no_evaluado_del_siguiente_nivel_entra(self):
        est = self._est(COD_B3="no_evaluado")
        items = roadmap.calcular(est, self.ind, g_dom(SEG="N5", COD="N2"), [])
        self.assertEqual([i["control"] for i in items], ["COD-B3"])
        self.assertEqual(items[0]["grupo"], "siguiente_nivel")

    def test_severidad_por_hallazgo(self):
        est = self._est(COD_B3="fail")
        est[[e["control"] for e in est].index("COD-B3")]["hallazgos"] = ["H-1"]
        items = roadmap.calcular(est, self.ind, g_dom(SEG="N5", COD="N2"),
                                 [{"id": "H-1", "control": "COD-B3", "severidad": "critica"}])
        self.assertEqual(items[0]["severidad"], "critica")


class TestRender(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = ap.tmp_dir(cls)
        cls.corrida = ap.preparar_corrida(cls.tmp)
        n_run.main([str(cls.corrida)])
        p = subprocess.run([sys.executable, str(RAIZ / "scripts" / "render_informe.py"), "--corrida", str(cls.corrida)],
                           capture_output=True, text=True)
        assert p.returncode == 0, p.stderr
        cls.informe = (cls.corrida / "informe.md").read_text(encoding="utf-8")
        cls.ruta = (cls.corrida / "hoja-de-ruta.md").read_text(encoding="utf-8")
        cls.sarif = json.loads((cls.corrida / "merged.sarif").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        ap.limpiar(cls.tmp)

    def test_genera_dependencias_faltantes(self):
        for f in ("estado.json", "gates.json", "score.json", "roadmap.json"):
            self.assertTrue((self.corrida / f).is_file(), f)

    def test_veredicto(self):
        self.assertIn("Nivel global demostrado: **N0**", self.informe)
        self.assertRegex(self.informe, r"potencial: \*\*N\d\*\*")
        self.assertIn("¿Listo para datos reales? **NO**", self.informe)
        self.assertIn("SEG-SECRETO-REPO", self.informe)

    def test_tabla_por_dominio(self):
        for d in ("SEG", "DAT", "COD", "UX", "INF", "ESC", "OPS"):
            self.assertRegex(self.informe, rf"\| {d} \|")

    def test_hallazgos_con_evidencia_y_remediacion(self):
        self.assertRegex(self.informe, r"## (\d\. )?Hallazgos críticos y altos")
        self.assertIn("Remediación:", self.informe)
        self.assertIn("****", self.informe)
        # Ronda 1: el tope ya no descarta críticos de N1, así que la fixture (12 secretos en .env) no deja instancias
        # extra entre los graves; el «(y N más)» se prueba con un hallazgo alto topado.
        h = {"control": "SEG-X", "severidad": "alta", "gate": "N2", "estado_hallazgo": "abierto",
             "ubicacion": {"archivo": "a.js", "linea": 1}, "fuente": [{"herramienta": "semgrep", "regla": "r"}],
             "confianza": "media", "metodo": "determinista", "evidencia": "x", "instancias_extra": 3}
        self.assertIn("(y 3 más)", render_informe._seccion_hallazgos([h], {}))

    def test_no_evaluados_con_motivo(self):
        self.assertRegex(self.informe, r"## (\d\. )?Lo que NO se evaluó")
        self.assertIn("juicio LLM no ejecutado en F1", self.informe)
        self.assertIn("timeout", self.informe)

    def test_limitaciones_y_sellos(self):
        self.assertIn("no certifica seguridad", self.informe)
        self.assertIn("SÍNTESIS", self.informe)
        self.assertIn("ESTIMACIÓN", self.informe)

    def test_sin_placeholders(self):
        for plantilla, texto in (("informe.md.tmpl", self.informe), ("hoja-de-ruta.md.tmpl", self.ruta)):
            fuente = (RAIZ / "plantillas" / plantilla).read_text(encoding="utf-8")
            for var in set(re.findall(r"\$\{?([a-z_]+)", fuente)):
                self.assertNotRegex(texto, r"\$\{?" + var + r"\b", var)

    def test_bloqueo_una_vez_por_control(self):
        seccion = self.informe.split("**Bloqueos del nivel global:**")[1].split("## 2.")[0]
        self.assertEqual(seccion.count("- SEG-ENV-PUBLICAS "), 1)

    def test_hoja_de_ruta(self):
        self.assertIn("# Hoja de ruta", self.ruta)
        self.assertIn("Esta semana", self.ruta)
        self.assertIn("/auditar", self.ruta)

    def test_sarif_minimo_valido(self):
        s = self.sarif
        self.assertEqual(s["version"], "2.1.0")
        self.assertIn("$schema", s)
        run = s["runs"][0]
        reglas = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertTrue(run["results"])
        for r in run["results"]:
            self.assertIn(r["ruleId"], reglas)
            self.assertIn(r["level"], ("error", "warning", "note", "none"))
            self.assertTrue(r["message"]["text"])
            for loc in r.get("locations", []):
                reg = loc["physicalLocation"].get("region")
                if reg:
                    self.assertGreaterEqual(reg["startLine"], 1)
            self.assertRegex(r["partialFingerprints"]["auditorIntegral/v1"], r"^[0-9a-f]{64}$")

    def test_sin_llm(self):  # criterio F1-5
        fuente = (RAIZ / "scripts" / "render_informe.py").read_text(encoding="utf-8") + \
            (RAIZ / "scripts" / "roadmap.py").read_text(encoding="utf-8")
        for prohibido in ("anthropic", "urllib.request", "http.client", "requests", "socket"):
            self.assertNotIn(prohibido, fuente)

    def test_avisos_legales(self):
        self.assertIn("no afirma cumplimiento", self.informe)


class TestPlantillas(unittest.TestCase):
    def test_existen_y_usan_template(self):
        for nombre in ("informe.md.tmpl", "hoja-de-ruta.md.tmpl"):
            t = (RAIZ / "plantillas" / nombre).read_text(encoding="utf-8")
            self.assertTrue(re.search(r"\$[a-z_]+", t), nombre)


if __name__ == "__main__":
    unittest.main()
