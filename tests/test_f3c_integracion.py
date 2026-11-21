"""F3-C integración: interfaz digest/indice.json ↔ veredictos.py (regla f).

1. indice.json → digests.<juicio>.controles es la lista que manda: si la clave existe (aunque sea []) se respeta;
   solo si falta en el índice y en el digest se cae al catálogo. El digest de triage lista sus controles del
   catálogo (SEG-SAST-TRIAGE) en el índice, aunque el digest no los lleve (no gasta tokens).
2. Un juez que el modo no lanza (lanzar=false, omitir_juez=false) y que no emitió líneas queda registrado con
   motivo «juez no lanzado…»: sus controles llm/mixto quedan no_evaluado con motivo; nunca pass; nunca toca un fail.
"""
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

from test_f3a_veredictos import Base, hallazgo, ver  # noqa: E402


class BaseI(Base):
    def indice(self):
        return json.loads((self.corrida / "digest" / "indice.json").read_text(encoding="utf-8"))

    def editar_indice(self, fn):
        ruta = self.corrida / "digest" / "indice.json"
        ind = json.loads(ruta.read_text(encoding="utf-8"))
        fn(ind)
        ruta.write_text(json.dumps(ind), encoding="utf-8")

    def omitidos(self):
        return {o["juicio"]: o for o in self.decisiones()["jueces_omitidos"]}


class TestControlesDelIndice(BaseI):
    def test_indice_de_triage_lista_sus_controles_del_catalogo(self):
        m = self.indice()["digests"]["triage"]
        self.assertIn("SEG-SAST-TRIAGE", m["controles"])
        d = json.loads((self.corrida / "digest" / "triage.json").read_text(encoding="utf-8"))
        self.assertEqual(d["controles"], [])  # el digest no gasta tokens en la lista

    def test_triage_omitido_registra_seg_sast_triage(self):
        self.assertTrue(self.indice()["digests"]["triage"]["omitir_juez"])
        self.poner_veredictos([])
        e = self.estado()
        om = self.omitidos()["triage"]
        self.assertEqual([x["control"] for x in om["controles"]], ["SEG-SAST-TRIAGE"])
        self.assertNotEqual(e["SEG-SAST-TRIAGE"]["estado"], "pass")
        self.assertIn("juez omitido", e["SEG-SAST-TRIAGE"]["motivo"])

    def test_lista_vacia_explicita_no_cae_al_catalogo(self):
        def vaciar(ind):
            ind["digests"]["ux"]["controles"] = []
        self.editar_indice(vaciar)
        self.poner_veredictos([])
        self.estado()
        self.assertEqual(self.omitidos()["ux"]["controles"], [])

    def test_lista_del_indice_manda_sobre_la_del_digest(self):
        def solo_uno(ind):
            ind["digests"]["ux"]["controles"] = ["UX-HEURISTICA"]
        self.editar_indice(solo_uno)
        self.poner_veredictos([])
        self.estado()
        self.assertEqual([x["control"] for x in self.omitidos()["ux"]["controles"]], ["UX-HEURISTICA"])


class TestJuezNoLanzado(BaseI):
    def setUp(self):
        super().setUp()
        self.poner_hallazgos([hallazgo(1, "UX-HEURISTICA", "media", "src/api.js", 3)])

    def test_indice_marca_ux_no_lanzado_en_estandar(self):
        m = self.indice()["digests"]["ux"]
        self.assertFalse(m["omitir_juez"])
        self.assertFalse(m["lanzar"])

    def test_no_lanzado_registra_no_evaluado_con_motivo(self):
        self.poner_veredictos([])
        e = self.estado()
        om = self.omitidos()
        self.assertIn("ux", om)
        self.assertTrue(om["ux"]["motivo"].startswith("juez no lanzado"))
        self.assertIn("estandar", om["ux"]["motivo"])
        self.assertIn("UX-HEURISTICA", {x["control"] for x in om["ux"]["controles"]})
        for x in om["ux"]["controles"]:
            self.assertNotEqual(e[x["control"]]["estado"], "pass")
        self.assertIn("ux", self.decisiones()["resumen"]["jueces_omitidos"])

    def test_no_lanzado_que_emitio_lineas_no_se_registra(self):
        self.poner_veredictos([ver("revisor-ux", "UX-HEURISTICA", "fail", ubicaciones=["src/api.js:3"])])
        self.estado()
        self.assertNotIn("ux", self.omitidos())

    def test_no_lanzado_no_toca_fail(self):
        self.poner_veredictos([])
        e = self.estado()
        self.assertEqual(e["UX-HEURISTICA"]["estado"], "fail")

    def test_indice_sin_clave_lanzar_no_registra(self):
        def sin_lanzar(ind):
            for m in ind["digests"].values():
                m.pop("lanzar", None)
        self.editar_indice(sin_lanzar)
        self.poner_veredictos([])
        self.estado()
        self.assertNotIn("ux", self.omitidos())


if __name__ == "__main__":
    unittest.main()
