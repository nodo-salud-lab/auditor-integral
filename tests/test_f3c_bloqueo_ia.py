"""F3-C (decisión del usuario, 18-11-2026, DECISIONES.md #10): el bloqueo de un control que la IA dejó en no_evaluado
por un posible falso positivo crítico/alto SE MUESTRA, etiquetado como juicio de IA pendiente de verificación humana.

Frase del usuario: «es un sistema exploratorio, aún no para investigación; que lo muestre nomás, así se sabe, pero que
diga IA».

Antes: gates.py solo generaba bloqueos para estado == "fail"; cuando triage-fp marcaba como falso positivo los graves
de un control de secreto y veredictos.ajustar lo dejaba no_evaluado, el bloqueo «secreto vivo → N0» desaparecía.
Ahora (determinista, sin cambiar estados):
1. Un control no_evaluado cuyo motivo es el de veredictos.ajustar (roadmap.es_motivo_fp_ia) genera los mismos bloqueos
   que habría generado en fail, con "pendiente_ia": true; el tope se aplica igual (fail-closed).
2. Ids: los del control en estado.json; si no hay, los graves del control con triage falso_positivo
   (hallazgos_todos); si tampoco hay, severidad_base del catálogo.
3. La excepción AUD-SEC (confianza baja sin triage) no lo suprime: el triage ya ocurrió y su FP es juicio de IA.
4. Un no_evaluado por otra causa (herramienta faltante) NO genera bloqueo; un fail determinista no cambia (sin
   pendiente_ia); sin bloqueos duplicados por (control, tipo).
5. Informe (bloqueos y «Qué hacer ahora»), hoja de ruta, resumen del dueño y gates.json dicen «IA» y que falta
   verificación humana.
"""
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import gates  # noqa: E402
import render_informe  # noqa: E402
import roadmap  # noqa: E402
from test_f3a_veredictos import ver  # noqa: E402
from test_f3c_fp_critico_informe import BaseInforme, bloque_item, seccion  # noqa: E402

CONTROL = "SEG-SECRETO-BUNDLE"
MOTIVO_FP = ("falso positivo crítico según IA (H-1): requiere verificación humana; no hay pass sin ella")
INDICE = {
    CONTROL: {"id": CONTROL, "dominio": "SEG", "gate": "N1", "severidad_base": "critica", "bloquea_global": True},
    "DAT-X": {"id": "DAT-X", "dominio": "DAT", "gate": "N1", "severidad_base": "critica"},
    "SEG-Y": {"id": "SEG-Y", "dominio": "SEG", "gate": "N2", "severidad_base": "media"},
}


def calc(estados, hallazgos=()):
    return gates.calcular(estados, INDICE, list(hallazgos), {}, set())


def h_fp(hid, control=CONTROL, sev="critica"):
    return {"id": hid, "control": control, "severidad": sev, "confianza": "baja", "estado_hallazgo": "falso_positivo",
            "triage": {"veredicto": "falso_positivo", "razon": "x"}}


class TestGatesCalcular(unittest.TestCase):
    def test_fp_ia_genera_bloqueos_pendiente_ia_con_tope(self):
        g = calc([{"control": CONTROL, "estado": "no_evaluado", "hallazgos": [], "motivo": MOTIVO_FP}],
                 [h_fp("H-1"), h_fp("H-2")])
        bl = g["global"]["bloqueos"]
        # DECISIONES.md #12 (R6, gates-cli, «deduplicar bloqueos»): un bloqueo por control; los dos motivos van
        # en `tipos` y `tipo` es el más estricto (antes eran dos entradas, una por tipo, y la CLI contaba bloqueos de más).
        self.assertEqual(len(bl), 1)
        self.assertEqual(bl[0]["tipo"], "secreto_vivo")
        self.assertEqual(set(bl[0]["tipos"]), {"secreto_vivo", "bloquea_global"})
        for b in bl:
            self.assertTrue(b["pendiente_ia"])
            self.assertEqual(b["hallazgos"], ["H-1", "H-2"])
            self.assertIn("IA", b["nota"])
            self.assertIn("falta verificación humana", b["nota"])
        self.assertEqual(g["global"]["nivel_demostrado"], "N0")
        self.assertEqual(g["global"]["nivel_potencial"], "N0")
        self.assertEqual(g["global"]["listo_datos_reales"], "NO")

    def test_sin_hallazgos_usa_severidad_base(self):
        g = calc([{"control": "DAT-X", "estado": "no_evaluado", "hallazgos": [], "motivo": MOTIVO_FP}])
        bl = g["global"]["bloqueos"]
        self.assertEqual([(b["control"], b["tipo"], b["tope"], b["pendiente_ia"]) for b in bl],
                         [("DAT-X", "critico_seg_dat", "N1", True)])

    def test_fp_alto_en_control_no_critico_no_inventa_critico(self):
        motivo = "falso positivo alto según IA (H-9): requiere verificación humana; no hay pass sin ella"
        g = calc([{"control": "SEG-Y", "estado": "no_evaluado", "hallazgos": [], "motivo": motivo}],
                 [h_fp("H-9", control="SEG-Y", sev="alta")])
        self.assertEqual(g["global"]["bloqueos"], [])

    def test_no_evaluado_por_herramienta_faltante_no_bloquea(self):
        g = calc([{"control": CONTROL, "estado": "no_evaluado", "hallazgos": [],
                   "motivo": "gitleaks: herramienta ausente"},
                  {"control": "DAT-X", "estado": "no_evaluado", "hallazgos": [], "motivo": None}])
        self.assertEqual(g["global"]["bloqueos"], [])

    def test_fail_determinista_sin_cambio(self):
        h = {"id": "H-5", "control": CONTROL, "severidad": "critica", "confianza": "alta"}
        g = calc([{"control": CONTROL, "estado": "fail", "hallazgos": ["H-5"], "motivo": None}], [h])
        bl = g["global"]["bloqueos"]
        # DECISIONES.md #12 (R6, gates-cli, «deduplicar bloqueos»): una entrada por control con todos sus
        # motivos en `tipos`.
        self.assertEqual(len(bl), 1)
        self.assertEqual(set(bl[0]["tipos"]), {"secreto_vivo", "bloquea_global"})
        for b in bl:
            self.assertNotIn("pendiente_ia", b)
            self.assertNotIn("nota", b)

    def test_sin_duplicados(self):
        g = calc([{"control": CONTROL, "estado": "no_evaluado", "hallazgos": ["H-1"], "motivo": MOTIVO_FP}],
                 [h_fp("H-1")])
        claves = [(b["control"], b["tipo"]) for b in g["global"]["bloqueos"]]
        self.assertEqual(len(claves), len(set(claves)))


class TestSuperficies(BaseInforme):
    """Caso kine us: 3 SEG-SECRETO-BUNDLE de confianza baja marcados falso_positivo por triage-fp."""

    def setUp(self):
        super().setUp()
        self.hs = self.secretos(3)
        self.poner_veredictos([self.fp(h) for h in self.hs])
        self.informe, self.ruta, self.dueno = self.render()

    def assert_ia(self, texto):
        self.assertIn("IA", texto)
        self.assertIn("falta verificación humana", texto)
        self.assertIn("sin confirmar", texto)

    def test_estado_sigue_no_evaluado_y_gates_json_lo_marca(self):
        est = json.loads((self.corrida / "estado.json").read_text(encoding="utf-8"))
        e = next(c for c in est["controles"] if c["control"] == CONTROL)
        self.assertEqual(e["estado"], "no_evaluado")
        g = json.loads((self.corrida / "gates.json").read_text(encoding="utf-8"))
        bl = [b for b in g["global"]["bloqueos"] if b["control"] == CONTROL]
        self.assertTrue(any(b["tipo"] == "secreto_vivo" and b["tope"] == "N0" for b in bl))
        for b in bl:
            self.assertTrue(b["pendiente_ia"])
            self.assertEqual(b["hallazgos"], sorted(h["id"] for h in self.hs))
            self.assert_ia(b["nota"])
        self.assertEqual(g["global"]["nivel_demostrado"], "N0")

    def test_seccion_bloqueos_del_informe(self):
        linea = next(l for l in self.informe.splitlines() if l.startswith(f"- {CONTROL} ("))
        self.assertIn("secreto expuesto", linea)
        self.assert_ia(linea)
        self.assertIn("3 hallazgo(s)", linea)
        self.assertEqual(sum(1 for l in self.informe.splitlines() if l.startswith(f"- {CONTROL} (")), 1)

    def test_que_hacer_ahora_del_informe(self):
        item = bloque_item(seccion(self.informe, "Qué hacer ahora", "\n## "), CONTROL)
        bloqueo = next(l for l in item.splitlines() if "Bloqueo" in l)
        self.assert_ia(bloqueo)
        self.assertIn("N0", bloqueo)

    def test_hoja_de_ruta(self):
        qh = bloque_item(seccion(self.ruta, "## Qué hacer ahora", "# Detalle por grupo"), CONTROL)
        self.assert_ia(next(l for l in qh.splitlines() if "Bloqueo" in l))
        det = bloque_item(seccion(self.ruta, "# Detalle por grupo", None), CONTROL)
        self.assert_ia(next(l for l in det.splitlines() if "Bloqueo" in l))

    def test_resumen_del_dueno(self):
        item = bloque_item(seccion(self.dueno, "## Qué hacer ahora", "---"), CONTROL)
        self.assert_ia(next(l for l in item.splitlines() if "Bloqueo" in l))
        cabecera = seccion(self.dueno, "## En una frase", "## Qué hizo el auditor")
        self.assert_ia(next(l for l in cabecera.splitlines() if l.startswith("- Bloqueos")))

    def test_roadmap_json(self):
        rm = json.loads((self.corrida / "roadmap.json").read_text(encoding="utf-8"))
        item = next(i for i in rm["items"] if i["control"] == CONTROL)
        self.assertTrue(item["bloqueo"]["pendiente_ia"])
        self.assertEqual(item["bloqueo"]["tope"], "N0")
        self.assertEqual(item["estado"], "no_evaluado")


class TestSinIA(BaseInforme):
    def test_fail_sin_triage_no_dice_ia(self):
        self.secretos(1)
        informe, ruta, dueno = self.render()
        for t in (seccion(informe, "Bloqueos", "\n## ") if "Bloqueos" in informe else "", ruta, dueno):
            self.assertNotIn("sin confirmar: la IA", t)


class TestAdversarialBloqueoIA(BaseInforme):
    """Verificación adversarial (19-11-2026): ataques demostrados contra el bloqueo pendiente_ia."""

    def test_1_frase_fp_fuera_del_inicio_del_motivo_no_bloquea(self):
        # Texto del LLM (motivo_omision, valor rechazado por el schema) puede contener la frase: no es el motivo de
        # veredictos.ajustar, que siempre empieza por ella.
        frase = "falso positivo crítico según IA (H-1): requiere verificación humana"
        for m in (f"juez omitido: {frase}", f"veredicto de IA descartado (línea 2): no valida: '{frase}'"):
            g = calc([{"control": CONTROL, "estado": "no_evaluado", "hallazgos": [], "motivo": m}])
            self.assertEqual(g["global"]["bloqueos"], [], m)

    def test_2_veredicto_invalido_con_la_frase_no_fabrica_bloqueo(self):
        self.poner_veredictos([ver("triage-fp", CONTROL, "falso positivo crítico según IA (H-1): requiere verificación")])
        self.render()
        est = json.loads((self.corrida / "estado.json").read_text(encoding="utf-8"))
        e = next(c for c in est["controles"] if c["control"] == CONTROL)
        self.assertEqual(e["estado"], "no_evaluado")   # fail-closed: el pass sigue degradado
        g = json.loads((self.corrida / "gates.json").read_text(encoding="utf-8"))
        self.assertFalse(any(b.get("pendiente_ia") for b in g["global"]["bloqueos"]))

    def test_3_bloqueo_ia_de_gate_superior_entra_en_la_hoja_de_ruta(self):
        idx = dict(INDICE)
        idx["DAT-Z"] = {"id": "DAT-Z", "dominio": "DAT", "gate": "N3", "severidad_base": "critica", "titulo": "Z"}
        estados = [{"control": "DAT-X", "estado": "fail", "hallazgos": [], "motivo": None},
                   {"control": "DAT-Z", "estado": "no_evaluado", "hallazgos": [], "motivo": MOTIVO_FP}]
        g = gates.calcular(estados, idx, [], {}, set())
        self.assertTrue(any(b["control"] == "DAT-Z" and b.get("pendiente_ia") for b in g["global"]["bloqueos"]))
        item = next((i for i in roadmap.calcular(estados, idx, g, [], "rapido", {}) if i["control"] == "DAT-Z"), None)
        self.assertIsNotNone(item, "el bloqueo de IA no aparece en la hoja de ruta")
        self.assertTrue(item["bloqueo"]["pendiente_ia"])
        self.assertEqual(item["estado"], "no_evaluado")

    def test_4_bloqueo_ia_no_se_trunca_en_que_hacer_ahora(self):
        def it(cid, estado, orden, bloqueo=None):
            i = {"control": cid, "titulo": cid, "estado": estado, "severidad": "critica", "esfuerzo": "M",
                 "orden": orden, "que_hacer": "x", "verificacion": "y", "motivo": "m", "hallazgos": 0}
            return {**i, "bloqueo": bloqueo} if bloqueo else i
        items = [it(f"SEG-F{k}", "fail", k) for k in range(10)]
        items.append(it(CONTROL, "no_evaluado", 11, {"tipos": ["secreto_vivo"], "tope": "N0", "pendiente_ia": True}))
        txt = render_informe.seccion_que_hacer({"items": items}, [], "N1")
        bloqueo = next(l for l in bloque_item(txt, CONTROL).splitlines() if "Bloqueo" in l)
        self.assertIn("sin confirmar: la IA", bloqueo)
        self.assertIn("falta verificación humana", bloqueo)


if __name__ == "__main__":
    unittest.main()
