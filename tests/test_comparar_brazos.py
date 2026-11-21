"""Tests de validacion/comparar_brazos.py (comparación de brazos A-D en la app sembrada y recall F3 en kine us).

Cubre: acuerdo entre corridas LLM (% y κ de Cohen), filtro del brazo D (semgrep con reglas del registry),
hallazgos tras aplicar veredictos (triage + hallazgos_ia), métricas por brazo y subconjunto, detección de
defectos puntuales y recall de F3 contra los hallazgos confirmados de la revisión libre (kine us).
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "validacion"))

import comparar_brazos as cb  # noqa: E402


def h(id_, control, archivo, linea=None, herramienta="prueba", regla="r", **extra):
    d = {"id": id_, "control": control, "ubicacion": {"archivo": archivo, "linea": linea},
         "evidencia": "", "fuente": [{"herramienta": herramienta, "version": "0", "regla": regla}],
         "estado_hallazgo": "abierto", "triage": None}
    d.update(extra)
    return d


def d(id_, control, archivo, linea=None, gate="N1", reservado=False):
    x = {"id": id_, "control": control, "archivo": archivo, "gate": gate, "severidad": "critica",
         "detectable_en_F1": True, "reservado": reservado}
    if linea is not None:
        x["linea"] = linea
    return x


def l(id_, control, archivo, linea=None, reservado=False):
    x = {"id": id_, "control": control, "archivo": archivo, "reservado": reservado}
    if linea is not None:
        x["linea"] = linea
    return x


def v(agente, control, veredicto, hallazgo_id=None):
    return {"agente": agente, "control": control, "veredicto": veredicto, "hallazgo_id": hallazgo_id}


class TestAcuerdo(unittest.TestCase):
    def test_acuerdo_total(self):
        a = [v("triage-fp", "SEG-X", "verdadero", "H-1"), v("revisor-autorizacion", "SEG-IDOR", "fail")]
        r = cb.acuerdo(a, list(a))
        self.assertEqual(r["n_comunes"], 2)
        self.assertEqual(r["acuerdos"], 2)
        self.assertAlmostEqual(r["pct"], 1.0)
        # una sola categoría por corrida no da κ definido salvo acuerdo perfecto: se informa 1,0
        self.assertAlmostEqual(r["kappa"], 1.0)

    def test_kappa_cohen_conocido(self):
        # 4 ítems: A=[s,s,n,n], B=[s,n,n,n] → po=0,75; pe=0,5·0,25+0,5·0,75=0,5; κ=0,5
        a = [v("x", f"C{i}", c) for i, c in enumerate("ssnn")]
        b = [v("x", f"C{i}", c) for i, c in enumerate("snnn")]
        r = cb.acuerdo(a, b)
        self.assertAlmostEqual(r["pct"], 0.75)
        self.assertAlmostEqual(r["kappa"], 0.5)

    def test_claves_solo_en_una_corrida(self):
        a = [v("x", "C1", "fail"), v("x", "C2", "fail")]
        b = [v("x", "C1", "fail"), v("x", "C3", "fail")]
        r = cb.acuerdo(a, b)
        self.assertEqual(r["n_comunes"], 1)
        self.assertEqual(r["solo_1"], 1)
        self.assertEqual(r["solo_2"], 1)

    def test_sin_comunes(self):
        r = cb.acuerdo([v("x", "C1", "fail")], [v("x", "C2", "fail")])
        self.assertEqual(r["n_comunes"], 0)
        self.assertIsNone(r["pct"])
        self.assertIsNone(r["kappa"])


class TestBrazoD(unittest.TestCase):
    def test_solo_semgrep_registry(self):
        hs = [h("H-1", "SEG-SAST-INY", "a.js", herramienta="semgrep", regla="javascript.lang.security.x"),
              h("H-2", "SEG-ERRORES", "a.js", herramienta="semgrep", regla="vibe-coding.catch-vacio"),
              h("H-3", "SEG-SECRETO-REPO", ".env", herramienta="gitleaks", regla="jwt")]
        self.assertEqual([x["id"] for x in cb.brazo_d(hs)], ["H-1"])

    def test_fuente_multiple_conserva_si_alguna_es_registry(self):
        x = h("H-1", "SEG-SAST-INY", "a.js", herramienta="semgrep", regla="vibe-coding.eval-dinamico")
        x["fuente"].append({"herramienta": "semgrep", "version": "0", "regla": "javascript.browser.eval"})
        self.assertEqual(len(cb.brazo_d([x])), 1)


class TestHallazgosDespues(unittest.TestCase):
    def test_aplica_triage_y_suma_hallazgos_ia(self):
        with tempfile.TemporaryDirectory() as t:
            c = Path(t)
            (c / "hallazgos_todos.jsonl").write_text(
                json.dumps(h("H-1", "SEG-X", "a.js", 1)) + "\n" + json.dumps(h("H-2", "SEG-Y", "b.js", 2)) + "\n",
                encoding="utf-8")
            (c / "decisiones_ia.json").write_text(json.dumps(
                {"triage": {"H-1": {"veredicto": "falso_positivo", "razon": "r", "modelo": "m"}}}), encoding="utf-8")
            (c / "hallazgos_ia.jsonl").write_text(json.dumps(h("H-9", "SEG-IDOR", "c.js", 8)) + "\n",
                                                  encoding="utf-8")
            res = cb.hallazgos_despues(c)
            ids = {x["id"]: x for x in res}
            self.assertEqual(set(ids), {"H-1", "H-2", "H-9"})
            self.assertEqual(ids["H-1"]["estado_hallazgo"], "falso_positivo")

    def test_sin_decisiones_falla_cerrado(self):
        with tempfile.TemporaryDirectory() as t:
            c = Path(t)
            (c / "hallazgos_todos.jsonl").write_text(json.dumps(h("H-1", "SEG-X", "a.js")) + "\n", encoding="utf-8")
            with self.assertRaises(FileNotFoundError):
                cb.hallazgos_despues(c)


class TestMetricasBrazo(unittest.TestCase):
    def setUp(self):
        self.defectos = [d("D01", "SEG-A", "a.js", 1, gate="N1"), d("D02", "DAT-B", "b.sql", 5, gate="N2"),
                         d("D03", "SEG-C", "c.js", 9, gate="N1", reservado=True)]
        self.limpios = [l("L01", "SEG-A", "z.js", 3), l("L03", "SEG-C", "y.js", 4, reservado=True)]

    def test_todo(self):
        hs = [h("H-1", "SEG-A", "a.js", 2), h("H-2", "SEG-C", "c.js", 9), h("H-3", "SEG-A", "z.js", 3)]
        m = cb.metricas_brazo(hs, self.defectos, self.limpios, "todo")
        self.assertEqual((m["sens_global"]["x"], m["sens_global"]["n"]), (2, 3))
        self.assertEqual((m["sens_seg_n1"]["x"], m["sens_seg_n1"]["n"]), (2, 2))
        self.assertEqual((m["vpp"]["x"], m["vpp"]["n"]), (2, 3))
        self.assertEqual((m["fp_limpios"]["x"], m["fp_limpios"]["n"]), (1, 2))
        self.assertIsNotNone(m["sens_global"]["ic"][0])

    def test_desarrollo_no_cuenta_vp_de_reservados_como_fp(self):
        hs = [h("H-1", "SEG-A", "a.js", 1), h("H-2", "SEG-C", "c.js", 9)]
        m = cb.metricas_brazo(hs, self.defectos, self.limpios, "desarrollo")
        self.assertEqual((m["sens_global"]["x"], m["sens_global"]["n"]), (1, 2))
        self.assertEqual((m["vpp"]["x"], m["vpp"]["n"]), (1, 1))
        self.assertEqual(m["fp_limpios"]["n"], 1)

    def test_reservado(self):
        hs = [h("H-2", "SEG-C", "c.js", 9)]
        m = cb.metricas_brazo(hs, self.defectos, self.limpios, "reservado")
        self.assertEqual((m["sens_global"]["x"], m["sens_global"]["n"]), (1, 1))
        self.assertEqual((m["sens_seg_n1"]["x"], m["sens_seg_n1"]["n"]), (1, 1))

    def test_tras_triage_excluye_falsos_positivos(self):
        fp = h("H-3", "SEG-A", "q.js", 3, estado_hallazgo="falso_positivo")
        hs = [h("H-1", "SEG-A", "a.js", 1), fp]
        antes = cb.metricas_brazo(hs, self.defectos, self.limpios, "todo")
        despues = cb.metricas_brazo(hs, self.defectos, self.limpios, "todo", tras_triage=True)
        self.assertEqual(antes["vpp"]["n"], 2)
        self.assertEqual(despues["vpp"]["n"], 1)

    def test_detectados(self):
        hs = [h("H-1", "SEG-A", "a.js", 3)]
        self.assertEqual(cb.detectados(hs, self.defectos, ["D01", "D03"]), {"D01": True, "D03": False})


class TestRecallKine(unittest.TestCase):
    def setUp(self):
        self.items = [
            {"id": "S01", "tipo": "falso_positivo", "hallazgo_id": "H-a", "controles": ["SEG-SECRETO-BUNDLE"]},
            {"id": "S09", "tipo": "falso_positivo", "hallazgo_id": "H-b", "controles": ["SEG-ENV-EJEMPLO"]},
            {"id": "S16", "tipo": "verdadero", "hallazgo_id": "H-c", "controles": ["SEG-DEPS-CVE-MEDIO"]},
            {"id": "K01", "tipo": "verdadero", "controles": ["COD-CI-BASICO"]},
            {"id": "K02", "tipo": "verdadero", "controles": ["COD-LINT"], "archivos": ["package.json"]},
            {"id": "A03", "tipo": "verdadero", "controles": ["INF-PLATAFORMA"]},
            {"id": "C01", "tipo": "verdadero", "controles": ["COD-COMPLEJIDAD"], "archivos": ["pdf.ts"]},
        ]
        self.ver = [v("triage-fp", "SEG-SECRETO-BUNDLE", "falso_positivo", "H-a"),
                    v("triage-fp", "SEG-ENV-EJEMPLO", "verdadero", "H-b"),
                    v("revisor-arquitectura", "INF-PLATAFORMA", "no_evaluado")]
        self.det = [h("H-a", "SEG-SECRETO-BUNDLE", "dist/x.js", 5), h("H-b", "SEG-ENV-EJEMPLO", None),
                    h("H-c", "SEG-DEPS-CVE-MEDIO", "package-lock.json", 5729),
                    h("H-d", "COD-CI-BASICO", None),
                    h("H-e", "COD-COMPLEJIDAD", "src/app/App.tsx", 54)]

    def test_por_item(self):
        r = {x["id"]: x for x in cb.recall_kine(self.items, self.ver, self.det)}
        self.assertTrue(r["S01"]["llm"])
        self.assertFalse(r["S09"]["llm"])            # la IA dijo verdadero; la revisión, falso positivo
        self.assertTrue(r["S09"]["contradice"])
        self.assertFalse(r["S16"]["llm"])            # nadie lo trió
        self.assertTrue(r["S16"]["completo"])        # pero el determinista lo reporta
        self.assertTrue(r["K01"]["completo"])        # ausencia: coincide por control
        self.assertFalse(r["K02"]["completo"])
        self.assertTrue(r["A03"]["no_evaluado_ia"])
        self.assertFalse(r["A03"]["completo"])
        self.assertFalse(r["C01"]["completo"])       # control coincide pero el archivo no

    def test_falso_positivo_no_cuenta_por_determinista(self):
        r = {x["id"]: x for x in cb.recall_kine(self.items, [], self.det)}
        self.assertFalse(r["S01"]["completo"])       # el determinista no descarta falsos positivos

    def test_triage_verdadero_cuenta_para_item_verdadero(self):
        ver = [v("triage-fp", "SEG-DEPS-CVE-MEDIO", "incierto", "H-c")]
        r = {x["id"]: x for x in cb.recall_kine(self.items, ver, self.det)}
        self.assertTrue(r["S16"]["llm"])

    def test_fail_de_control_cuenta_para_item_verdadero(self):
        ver = [v("revisor-arquitectura", "INF-PLATAFORMA", "fail")]
        r = {x["id"]: x for x in cb.recall_kine(self.items, ver, self.det)}
        self.assertTrue(r["A03"]["llm"])
        self.assertTrue(r["A03"]["completo"])


@unittest.skipUnless((RAIZ / "validacion" / "brazo-c-kine-us").is_dir(),
                     "brazo C (auditoría de un proyecto clínico real) no se publica en el repositorio")
class TestDatosKine(unittest.TestCase):
    def test_archivo_de_confirmados_tiene_42(self):
        items = cb.leer_confirmados(RAIZ / "validacion" / "brazo-c-kine-us" / "confirmados-revision-libre.toml")
        self.assertEqual(len(items), 42)
        self.assertEqual(len({x["id"] for x in items}), 42)
        for x in items:
            self.assertIn(x["tipo"], ("verdadero", "falso_positivo"))
            self.assertTrue(x["controles"])


if __name__ == "__main__":
    unittest.main()
