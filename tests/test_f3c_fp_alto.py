"""F3-C (decisión del usuario, 18-11-2026): la regla (a) protege también los hallazgos de severidad ALTA.

Antes: un falso_positivo de triage-fp sobre un hallazgo «critica» dejaba el control en no_evaluado (verificación
humana), pero sobre un hallazgo «alta» lo descartaba y el control podía terminar en pass solo por el juicio de la IA.
Eso viola fail-closed. Ahora:
1. FP de la IA sobre un hallazgo alto → el control no queda en pass: no_evaluado con motivo «falso positivo alto
   según IA (ids): requiere verificación humana; no hay pass sin ella».
2. FP sobre un hallazgo crítico → igual que antes («falso positivo crítico según IA»), también si se mezcla con altos.
3. FP sobre medio/bajo → sin cambio (el triage puede descartarlos; un pass del control sigue siendo posible).
4. Un fail determinista sigue intacto (sin veredicto o con un FP inválido); alto FP + otro hallazgo efectivo → fail.
5. Informe y hoja de ruta muestran verificación humana para el alto (no «quedó en pass por el juicio de la IA»).
6. Compatibilidad: un res antiguo con solo fp_criticos sigue degradando el pass.
7. Alcance 0 (verificadores, ronda 2): si tras el FP el control caería en no_aplica por sin_alcance (gitleaks con
   bundles=0, semgrep con fuentes=0), tampoco queda en un estado OK: no_evaluado con el mismo motivo, sigue en
   «aplicables» y en la hoja de ruta con «Verificación humana».
8. El motivo del FP sobrevive al recorte de 300 caracteres aunque el control traiga un «forzar» largo.
"""
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import render_informe  # noqa: E402
import roadmap  # noqa: E402
import veredictos  # noqa: E402
from test_f3a_veredictos import hallazgo, ver  # noqa: E402
from test_f3c_fp_critico_informe import ARCHIVO, BaseInforme, seccion  # noqa: E402

CONTROL = "SEG-SECRETO-BUNDLE"


class TestFPAlto(BaseInforme):
    def h(self, n, sev, linea):
        h = hallazgo(n, CONTROL, sev, ARCHIVO, linea, gate="N1", conf="baja", herramienta="gitleaks")
        h["remediacion"] = "Rotar la clave y moverla al servidor; volver a construir el bundle."
        return h

    def estado_de(self):
        est = json.loads((self.corrida / "estado.json").read_text(encoding="utf-8"))
        return next(c for c in est["controles"] if c["control"] == CONTROL)

    def test_fp_sobre_alto_queda_no_evaluado_con_motivo(self):
        h = self.h(0, "alta", 4)
        self.poner_hallazgos([h])
        self.poner_veredictos([self.fp(h)])
        self.render()
        e = self.estado_de()
        self.assertEqual(e["estado"], "no_evaluado")
        self.assertIn("falso positivo alto según IA", e["motivo"])
        self.assertIn(h["id"], e["motivo"])
        self.assertIn("requiere verificación humana; no hay pass sin ella", e["motivo"])
        self.assertTrue(roadmap.es_motivo_fp_ia(e["motivo"]))
        self.assertEqual(render_informe.clasificar_pendiente(e, {})[0], "fp_ia")

    def test_fp_sobre_critico_conserva_el_motivo_previo(self):
        h = self.h(0, "critica", 4)
        self.poner_hallazgos([h])
        self.poner_veredictos([self.fp(h)])
        self.render()
        e = self.estado_de()
        self.assertEqual(e["estado"], "no_evaluado")
        self.assertIn(roadmap.MOTIVO_FP_CRITICO, e["motivo"])

    def test_mezcla_critico_y_alto_fp_se_nombra_por_el_critico(self):
        hs = [self.h(0, "alta", 4), self.h(1, "critica", 9)]
        self.poner_hallazgos(hs)
        self.poner_veredictos([self.fp(h) for h in hs])
        self.render()
        e = self.estado_de()
        self.assertEqual(e["estado"], "no_evaluado")
        self.assertIn(roadmap.MOTIVO_FP_CRITICO, e["motivo"])
        for h in hs:
            self.assertIn(h["id"], e["motivo"])

    def test_fp_sobre_medio_sin_cambio(self):
        h = self.h(0, "media", 4)
        self.poner_hallazgos([h])
        self.poner_veredictos([self.fp(h)])
        self.render()
        e = self.estado_de()
        self.assertEqual(e["estado"], "pass")   # decisión documentada: medio/bajo los sigue pudiendo descartar
        self.assertFalse(roadmap.es_motivo_fp_ia(e.get("motivo") or ""))
        self.assertEqual(veredictos.SEVERIDADES_FP_HUMANO, ("critica", "alta"))

    def test_fail_determinista_intacto(self):
        h = self.h(0, "alta", 4)
        self.poner_hallazgos([h])
        self.render()
        self.assertEqual(self.estado_de()["estado"], "fail")
        # FP inválido (línea lejana): no se aplica, sigue fail
        self.poner_veredictos([dict(self.fp(h), ubicaciones=[f"{ARCHIVO}:19"])])
        self.render()
        self.assertEqual(self.estado_de()["estado"], "fail")

    def test_alto_fp_mas_otro_hallazgo_efectivo_es_fail(self):
        h, otro = self.h(0, "alta", 4), self.h(1, "media", 12)
        self.poner_hallazgos([h, otro])
        self.poner_veredictos([self.fp(h)])
        self.render()
        e = self.estado_de()
        self.assertEqual(e["estado"], "fail")
        self.assertFalse(roadmap.es_motivo_fp_ia(e.get("motivo") or ""))

    def test_informe_y_hoja_de_ruta_piden_verificacion_humana(self):
        h = self.h(0, "alta", 4)
        self.poner_hallazgos([h])
        self.poner_veredictos([self.fp(h)])
        informe, hoja, _ = self.render()
        s6 = self.sec6(informe)
        self.assertNotIn("quedó en `pass`", informe + hoja)
        self.assertNotIn(roadmap._cierre_estado("pass"), informe + hoja)
        self.assertIn("queda `no_evaluado`", s6)
        self.assertIn("⚠ La IA lo marcó como posible falso positivo", s6)
        no_ev = seccion(informe, "## 7. Lo que NO se evaluó", "\n## ")
        self.assertIn("verificación humana del hallazgo que la IA marcó como posible falso positivo", no_ev)
        rm = json.loads((self.corrida / "roadmap.json").read_text(encoding="utf-8"))
        item = next(i for i in rm["items"] if i["control"] == CONTROL)
        self.assertEqual(item["estado"], "no_evaluado")
        self.assertTrue(item["verificacion"].startswith("Verificación humana"))
        self.assertIn("severidad alta", item["verificacion"])
        self.assertIn("Verificación humana", hoja)


class TestFPAlcanceCero(BaseInforme):
    """Ataques A1/A2/A5 de los verificadores: tras el FP, estado.calcular aplicaba sin_alcance = no_aplica."""

    def meta_gitleaks(self, bundles):
        (self.corrida / "crudo" / "gitleaks.meta.json").write_text(json.dumps(
            {"herramienta": "gitleaks", "version": "8", "estado": "ok",
             "alcance": {"bundles": bundles, "archivos": 3, "commits": 0, "historial": 0}}), encoding="utf-8")

    def gates(self):
        return json.loads((self.corrida / "gates.json").read_text(encoding="utf-8"))

    def caso_bundle(self, sev):
        self.meta_gitleaks(0)
        h = hallazgo(0, CONTROL, sev, ARCHIVO, 4, gate="N1", conf="alta", herramienta="semgrep")
        h["remediacion"] = "Rotar la clave y moverla al servidor; volver a construir el bundle."
        self.poner_hallazgos([h])
        informe, hoja, _ = self.render()
        self.assertEqual(self.estado()[CONTROL]["estado"], "fail")   # sin veredicto: fail determinista
        self.poner_veredictos([self.fp(h)])
        informe, hoja, _ = self.render()
        est = json.loads((self.corrida / "estado.json").read_text(encoding="utf-8"))
        e = next(c for c in est["controles"] if c["control"] == CONTROL)
        return h, e, informe, hoja

    def comprobar(self, h, e, hoja, etiqueta):
        self.assertEqual(e["estado"], "no_evaluado")
        self.assertIn(f"falso positivo {etiqueta} según IA ({h['id']})", e["motivo"])
        n1 = self.gates()["dominios"]["SEG"]["niveles"]["N1"]
        self.assertIn(CONTROL, n1["pendientes"])
        rm = json.loads((self.corrida / "roadmap.json").read_text(encoding="utf-8"))
        item = next(i for i in rm["items"] if i["control"] == CONTROL)
        self.assertEqual(item["estado"], "no_evaluado")
        self.assertTrue(item["verificacion"].startswith("Verificación humana"))
        self.assertIn("Verificación humana", hoja)
        dec = json.loads((self.corrida / "decisiones_ia.json").read_text(encoding="utf-8"))
        finales = {a.get("estado_final") for a in dec["aplicadas"] if a.get("control") == CONTROL}
        self.assertNotIn("no_aplica", finales)
        self.assertNotIn("pass", finales)

    def test_A1_critico_bundles_cero_no_queda_no_aplica(self):
        h, e, _, hoja = self.caso_bundle("critica")
        self.comprobar(h, e, hoja, "crítico")

    def test_A2_alto_bundles_cero_no_queda_no_aplica(self):
        h, e, _, hoja = self.caso_bundle("alta")
        self.comprobar(h, e, hoja, "alto")

    def test_A5_sast_alto_fuentes_cero_no_queda_no_aplica(self):
        cid = "SEG-SAST-INY"
        crudo = self.corrida / "crudo"
        (crudo / "semgrep.sarif").write_text(json.dumps({"runs": []}), encoding="utf-8")
        (crudo / "semgrep.meta.json").write_text(json.dumps(
            {"herramienta": "semgrep", "version": "1", "estado": "ok",
             "alcance": {"fuentes": 0, "fuentes_sin_reglas": 0, "fuentes_no_escaneadas": 0, "bundle": 0}}),
            encoding="utf-8")
        h = hallazgo(0, cid, "alta", "src/api.js", 12, gate="N2", herramienta="bandit")
        self.poner_hallazgos([h])
        self.assertEqual(self.estado()[cid]["estado"], "fail")
        self.poner_veredictos([ver("triage-fp", cid, "falso_positivo", razon="no es entrada de usuario",
                                   hallazgo_id=h["id"], ubicaciones=["src/api.js:12"])])
        self.assertEqual(veredictos.main([str(self.corrida)]), 0)
        est = json.loads((self.corrida / "estado.json").read_text(encoding="utf-8"))
        e = next(c for c in est["controles"] if c["control"] == cid)
        self.assertEqual(e["estado"], "no_evaluado")
        self.assertIn(f"falso positivo alto según IA ({h['id']})", e["motivo"])
        self.assertIn(cid, self.gates()["dominios"]["SEG"]["niveles"]["N2"]["pendientes"])

    def test_medio_con_alcance_cero_sin_cambio(self):
        # decisión documentada: medio/bajo los sigue pudiendo descartar el triage (aquí cae en no_aplica)
        h, e, _, _ = self.caso_bundle("media")
        self.assertEqual(e["estado"], "no_aplica")
        self.assertFalse(roadmap.es_motivo_fp_ia(e.get("motivo") or ""))


class TestAjustarUnitario(unittest.TestCase):
    def reg(self):
        return [{"control": CONTROL, "estado": "pass", "motivo": None, "metodo": "determinista",
                 "duracion_s": None, "herramienta": "gitleaks", "hallazgos": []}]

    def test_fp_graves_alto_degrada_pass(self):
        controles = self.reg()
        veredictos.ajustar(controles, {"forzar": {}, "fp_criticos": {}, "fp_graves": {CONTROL: ["H-a1"]}})
        self.assertEqual(controles[0]["estado"], "no_evaluado")
        self.assertIn("falso positivo alto según IA (H-a1)", controles[0]["motivo"])

    def test_res_antiguo_solo_fp_criticos_sigue_funcionando(self):
        controles = self.reg()
        veredictos.ajustar(controles, {"forzar": {}, "fp_criticos": {CONTROL: ["H-c1"]}})
        self.assertEqual(controles[0]["estado"], "no_evaluado")
        self.assertIn("falso positivo crítico según IA (H-c1)", controles[0]["motivo"])

    def test_degrada_no_aplica(self):
        controles = self.reg()
        controles[0].update(estado="no_aplica", motivo="sin bundle: gitleaks analizó 0 de gitleaks.bundles")
        veredictos.ajustar(controles, {"forzar": {}, "fp_graves": {CONTROL: ["H-a1"]}})
        self.assertEqual(controles[0]["estado"], "no_evaluado")
        self.assertIn("falso positivo alto según IA (H-a1)", controles[0]["motivo"])

    def test_motivo_fp_sobrevive_a_forzar_largo(self):
        for largo in (120, 280, 400):
            controles = self.reg()
            forzar = {CONTROL: "veredicto de IA descartado (línea 3): " + "x" * largo}
            veredictos.ajustar(controles, {"forzar": forzar, "fp_graves": {CONTROL: ["H-0123456789ab"]}})
            m = controles[0]["motivo"]
            self.assertEqual(controles[0]["estado"], "no_evaluado")
            self.assertTrue(roadmap.es_motivo_fp_ia(m), (largo, m))
            self.assertTrue(m.startswith("falso positivo alto según IA"), m)
            self.assertLessEqual(len(m), 300)
            self.assertEqual(render_informe.clasificar_pendiente(controles[0], {})[0], "fp_ia")
            self.assertTrue(roadmap._verificacion({"id": CONTROL}, controles[0], "estandar").startswith(
                "Verificación humana"))

    def test_no_toca_fail(self):
        controles = self.reg()
        controles[0]["estado"] = "fail"
        veredictos.ajustar(controles, {"forzar": {}, "fp_graves": {CONTROL: ["H-a1"]}})
        self.assertEqual(controles[0]["estado"], "fail")


if __name__ == "__main__":
    unittest.main()
