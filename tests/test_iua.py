"""Tests de scripts/iua.py: Índice de Usabilidad Automatizado (PLAN_MAESTRO §5.1; DECISIONES.md #1 y #2).

- Accesibilidad: fórmula de Lighthouse (media ponderada pass/fail por regla axe; critical 10, serious 7,
  moderate 3, minor 1 si WCAG A/AA y 0 si no; experimental 0).
- Rendimiento: puntaje Performance de Lighthouse (mediana de corridas) o, si solo hay métricas,
  media ponderada FCP 10 / SI 10 / LCP 25 / TBT 30 / CLS 25.
- Teclado, responsive/táctil, robustez de estados y limpieza: fórmulas del plan.
- Componente sin datos → no_evaluado; el IUA se informa con su cobertura.
- Hallazgos de fallbacks UX estáticos: se consumen como señal de cobertura parcial; nunca dan puntaje.
- Bandas de Lighthouse: 0-49 / 50-89 / 90-100.
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
import iua  # noqa: E402

WCAG = ["wcag2a", "cat.text-alternatives"]
BP = ["best-practice"]


def regla(id_, impacto, tags=None):
    return {"id": id_, "impact": impacto, "tags": tags if tags is not None else WCAG}


def axe(violations=(), passes=(), incomplete=(), inapplicable=()):
    return {"violations": list(violations), "passes": list(passes), "incomplete": list(incomplete),
            "inapplicable": list(inapplicable)}


def lhr(score=None, audits=None):
    d = {"categories": {}, "audits": audits or {}}
    if score is not None:
        d["categories"]["performance"] = {"score": score}
    return d


def hallazgo_fallback(control, regla_, herramienta="ux_estatico", archivo="src/App.jsx"):
    return {"control": control, "dominio": "UX", "severidad": "media", "estado_hallazgo": "abierto",
            "fuente": [{"herramienta": herramienta, "version": None, "regla": regla_}],
            "ubicacion": {"archivo": archivo, "linea": 3}}


class TestPesoRegla(unittest.TestCase):
    def test_tabla_lighthouse(self):
        cfg = iua.cargar_config()
        casos = [("critical", WCAG, 10), ("serious", WCAG, 7), ("moderate", WCAG, 3), ("minor", ["wcag2aa"], 1),
                 ("minor", ["wcag21a"], 1), ("minor", BP, 0), ("critical", BP, 10), ("serious", BP, 7),
                 ("moderate", BP, 3), ("critical", ["wcag2a", "experimental"], 0), ("minor", ["wcag2aaa"], 0)]
        for impacto, tags, peso in casos:
            with self.subTest(impacto=impacto, tags=tags):
                self.assertEqual(iua.peso_regla(impacto, tags, cfg), peso)

    def test_sin_impacto_es_none(self):
        self.assertIsNone(iua.peso_regla(None, WCAG, iua.cargar_config()))


class TestAccesibilidad(unittest.TestCase):
    def setUp(self):
        self.cfg = iua.cargar_config()

    def test_media_ponderada_pass_fail(self):
        r = iua.accesibilidad([axe(violations=[regla("label", "serious")], passes=[regla("image-alt", "critical")])],
                              self.cfg)
        self.assertAlmostEqual(r["puntaje"], round(100 * 10 / 17, 1))
        self.assertEqual(r["reglas_evaluadas"], 2)

    def test_excluye_incomplete_e_inapplicable(self):
        r = iua.accesibilidad([axe(passes=[regla("a", "critical")], incomplete=[regla("b", "critical")],
                                   inapplicable=[regla("c", "serious")])], self.cfg)
        self.assertEqual(r["puntaje"], 100.0)
        self.assertEqual(r["reglas_evaluadas"], 1)

    def test_sin_credito_parcial_por_nodos(self):
        una = dict(regla("color-contrast", "serious"), nodes=[{}] * 50)
        r = iua.accesibilidad([axe(violations=[una], passes=[regla("x", "serious")])], self.cfg)
        self.assertEqual(r["puntaje"], 50.0)

    def test_regla_sin_impacto_se_excluye_y_se_informa(self):
        r = iua.accesibilidad([axe(violations=[regla("a", "moderate")], passes=[regla("b", None)])], self.cfg)
        self.assertEqual(r["puntaje"], 0.0)
        self.assertEqual(r["reglas_sin_impacto"], ["b"])

    def test_varias_paginas_regla_falla_si_falla_en_alguna(self):
        p1 = axe(passes=[regla("label", "critical"), regla("lang", "serious")])
        p2 = axe(violations=[regla("label", "critical")], passes=[regla("lang", "serious")])
        r = iua.accesibilidad([p1, p2], self.cfg)
        self.assertAlmostEqual(r["puntaje"], round(100 * 7 / 17, 1))
        self.assertEqual(r["paginas"], 2)

    def test_impacto_de_la_violacion_vale_para_la_regla(self):
        # En axe, passes[].impact suele venir null; si la misma regla falló en otra página se usa ese impacto.
        p1 = axe(passes=[regla("label", None)])
        p2 = axe(violations=[regla("label", "critical")], passes=[regla("x", "critical")])
        r = iua.accesibilidad([p1, p2], self.cfg)
        self.assertEqual(r["puntaje"], 50.0)
        self.assertEqual(r["reglas_sin_impacto"], [])

    def test_todas_peso_cero(self):
        r = iua.accesibilidad([axe(violations=[regla("a", "minor", BP)])], self.cfg)
        self.assertIsNone(r["puntaje"])

    def test_sin_datos(self):
        self.assertIsNone(iua.accesibilidad([], self.cfg)["puntaje"])


class TestRendimiento(unittest.TestCase):
    def setUp(self):
        self.cfg = iua.cargar_config()

    def test_mediana_de_corridas(self):
        r = iua.rendimiento([lhr(0.8), lhr(0.9), lhr(0.7)], self.cfg)
        self.assertEqual(r["puntaje"], 80.0)
        self.assertEqual(r["corridas"], 3)
        self.assertEqual(r["metodo"], "categoria_lighthouse")

    def test_metricas_con_pesos_lighthouse(self):
        aud = {"first-contentful-paint": {"score": 1}, "speed-index": {"score": 1},
               "largest-contentful-paint": {"score": 1}, "total-blocking-time": {"score": 0},
               "cumulative-layout-shift": {"score": 1}}
        r = iua.rendimiento([lhr(None, aud)], self.cfg)
        self.assertEqual(r["puntaje"], 70.0)
        self.assertEqual(r["metodo"], "metricas_ponderadas")

    def test_metricas_incompletas_se_renormalizan_y_se_avisan(self):
        aud = {"largest-contentful-paint": {"score": 0.5}, "cumulative-layout-shift": {"score": 1}}
        r = iua.rendimiento([lhr(None, aud)], self.cfg)
        self.assertEqual(r["puntaje"], 75.0)
        self.assertEqual(sorted(r["metricas_faltantes"]), ["fcp", "si", "tbt"])

    def test_sin_datos(self):
        self.assertIsNone(iua.rendimiento([], self.cfg)["puntaje"])
        self.assertIsNone(iua.rendimiento([lhr(None, {})], self.cfg)["puntaje"])


class TestComponentesPlaywright(unittest.TestCase):
    def setUp(self):
        self.cfg = iua.cargar_config()

    def test_teclado(self):
        self.assertEqual(iua.teclado({"interactivos": 10, "alcanzables_foco_visible": 8})["puntaje"], 80.0)
        self.assertIsNone(iua.teclado({"interactivos": 0, "alcanzables_foco_visible": 0})["puntaje"])
        self.assertIsNone(iua.teclado(None)["puntaje"])

    def test_responsive_tactil(self):
        d = {"viewports": [{"ancho": 360, "scroll_horizontal": True}, {"ancho": 768, "scroll_horizontal": False},
                           {"ancho": 1280, "scroll_horizontal": False}],
             "objetivos_total": 10, "objetivos_24px": 9}
        self.assertAlmostEqual(iua.responsive_tactil(d)["puntaje"], 60.0)
        self.assertIsNone(iua.responsive_tactil({"viewports": []})["puntaje"])

    def test_responsive_sin_objetivos_usa_solo_viewports(self):
        d = {"viewports": [{"ancho": 360, "scroll_horizontal": False}], "objetivos_total": 0, "objetivos_24px": 0}
        r = iua.responsive_tactil(d)
        self.assertEqual(r["puntaje"], 100.0)
        self.assertIn("sin objetivos", r["nota"])

    def test_robustez_estados(self):
        self.assertEqual(iua.robustez_estados({"llamadas": 4, "con_estados_visibles": 3})["puntaje"], 75.0)
        self.assertIsNone(iua.robustez_estados({"llamadas": 0, "con_estados_visibles": 0})["puntaje"])

    def test_limpieza(self):
        self.assertEqual(iua.limpieza({"tipos_error": []}, self.cfg)["puntaje"], 100.0)
        self.assertEqual(iua.limpieza({"tipos_error": ["consola", "stack visible"]}, self.cfg)["puntaje"], 60.0)
        self.assertEqual(iua.limpieza({"tipos_error": ["a", "a", "b"]}, self.cfg)["puntaje"], 60.0)
        self.assertEqual(iua.limpieza({"tipos_error": list("abcdef")}, self.cfg)["puntaje"], 0.0)
        self.assertIsNone(iua.limpieza(None, self.cfg)["puntaje"])


class TestIndice(unittest.TestCase):
    def setUp(self):
        self.cfg = iua.cargar_config()

    def completo(self):
        return {"axe": [axe(passes=[regla("a", "critical")])], "lighthouse": [lhr(0.5)],
                "playwright": {"teclado": {"interactivos": 10, "alcanzables_foco_visible": 10},
                               "responsive": {"viewports": [{"ancho": 360, "scroll_horizontal": False}],
                                              "objetivos_total": 1, "objetivos_24px": 1},
                               "estados": {"llamadas": 2, "con_estados_visibles": 1},
                               "limpieza": {"tipos_error": []}},
                "hallazgos": []}

    def test_iua_completo_ponderado(self):
        r = iua.calcular(self.completo(), self.cfg)
        esperado = (25 * 100 + 15 * 100 + 15 * 100 + 15 * 50 + 15 * 50 + 15 * 100) / 100
        self.assertAlmostEqual(r["iua"], round(esperado, 1))
        self.assertEqual(r["cobertura"]["componentes_medidos"], 6)
        self.assertEqual(r["cobertura"]["fraccion"], 1.0)
        self.assertFalse(r["parcial"])
        self.assertEqual(r["banda"], "mejorable")  # 85: banda 50-89 de Lighthouse

    def test_iua_parcial_renormaliza_e_informa_cobertura(self):
        datos = {"axe": [axe(passes=[regla("a", "critical")], violations=[regla("b", "critical")])],
                 "lighthouse": [], "playwright": {}, "hallazgos": []}
        r = iua.calcular(datos, self.cfg)
        self.assertEqual(r["iua"], 50.0)
        self.assertEqual(r["cobertura"]["peso_medido"], 25)
        self.assertEqual(r["cobertura"]["peso_total"], 100)
        self.assertEqual(r["cobertura"]["fraccion"], 0.25)
        self.assertTrue(r["parcial"])
        for comp in ("teclado", "responsive_tactil", "robustez_estados", "rendimiento", "limpieza"):
            self.assertEqual(r["componentes"][comp]["estado"], "no_evaluado", comp)
            self.assertTrue(r["componentes"][comp]["motivo"])

    def test_sin_datos(self):
        r = iua.calcular({"axe": [], "lighthouse": [], "playwright": {}, "hallazgos": []}, self.cfg)
        self.assertIsNone(r["iua"])
        self.assertIsNone(r["banda"])
        self.assertEqual(r["cobertura"]["componentes_medidos"], 0)

    def test_bandas_lighthouse(self):
        for valor, banda in ((0, "pobre"), (49.9, "pobre"), (50, "mejorable"), (89.9, "mejorable"),
                             (90, "bueno"), (100, "bueno")):
            with self.subTest(valor=valor):
                self.assertEqual(iua.banda(valor, self.cfg["bandas"]), banda)
        self.assertIsNone(iua.banda(None, self.cfg["bandas"]))


class TestFallback(unittest.TestCase):
    def setUp(self):
        self.cfg = iua.cargar_config()

    def test_fallback_sin_sonda_da_parcial_sin_puntaje(self):
        datos = {"axe": [], "lighthouse": [], "playwright": {},
                 "hallazgos": [hallazgo_fallback("UX-TECLADO", "check:ux_estatico.click_en_div"),
                               hallazgo_fallback("UX-FOCO-OCULTO", "check:ux_estatico.outline_none"),
                               hallazgo_fallback("UX-AXE-CRIT", "check:ux_estatico.img_sin_alt")]}
        r = iua.calcular(datos, self.cfg)
        t = r["componentes"]["teclado"]
        self.assertEqual(t["estado"], "parcial_fallback")
        self.assertIsNone(t["puntaje"])
        self.assertEqual(t["cobertura"], "parcial (fallback)")
        self.assertEqual(t["hallazgos_fallback"], 2)
        self.assertEqual(r["componentes"]["accesibilidad"]["hallazgos_fallback"], 1)
        self.assertIsNone(r["iua"])
        self.assertEqual(r["cobertura"]["componentes_medidos"], 0)
        self.assertEqual(r["cobertura"]["componentes_parcial_fallback"], 2)

    def test_sonda_prevalece_sobre_fallback(self):
        datos = {"axe": [], "lighthouse": [],
                 "playwright": {"teclado": {"interactivos": 4, "alcanzables_foco_visible": 3}},
                 "hallazgos": [hallazgo_fallback("UX-TECLADO", "check:ux_estatico.click_en_div")]}
        t = iua.calcular(datos, self.cfg)["componentes"]["teclado"]
        self.assertEqual(t["estado"], "medido")
        self.assertEqual(t["puntaje"], 75.0)
        self.assertEqual(t["hallazgos_fallback"], 1)
        self.assertEqual(t["cobertura"], "completa")

    def test_hallazgos_no_fallback_se_ignoran(self):
        h = hallazgo_fallback("UX-TECLADO", "semgrep:algo", herramienta="semgrep")
        r = iua.calcular({"axe": [], "lighthouse": [], "playwright": {}, "hallazgos": [h]}, self.cfg)
        self.assertEqual(r["componentes"]["teclado"]["estado"], "no_evaluado")

    def test_marca_cobertura_parcial_explicita(self):
        h = hallazgo_fallback("UX-ESTADOS", "check:otro.x", herramienta="otro")
        h["cobertura"] = "parcial (fallback)"
        r = iua.calcular({"axe": [], "lighthouse": [], "playwright": {}, "hallazgos": [h]}, self.cfg)
        self.assertEqual(r["componentes"]["robustez_estados"]["estado"], "parcial_fallback")

    def test_presupuesto_build_va_a_rendimiento(self):
        h = hallazgo_fallback("UX-LIGHTHOUSE", "check:presupuesto_build.chunk_grande", herramienta="presupuesto_build")
        r = iua.calcular({"axe": [], "lighthouse": [], "playwright": {}, "hallazgos": [h]}, self.cfg)
        self.assertEqual(r["componentes"]["rendimiento"]["estado"], "parcial_fallback")

    def test_hallazgo_cerrado_no_cuenta(self):
        h = hallazgo_fallback("UX-TECLADO", "check:ux_estatico.click_en_div")
        h["estado_hallazgo"] = "falso_positivo"
        r = iua.calcular({"axe": [], "lighthouse": [], "playwright": {}, "hallazgos": [h]}, self.cfg)
        self.assertEqual(r["componentes"]["teclado"]["estado"], "no_evaluado")


class TestConfig(unittest.TestCase):
    def test_config_real(self):
        cfg = iua.cargar_config()
        self.assertEqual(cfg["componentes"], {"accesibilidad": 25, "teclado": 15, "responsive_tactil": 15,
                                              "robustez_estados": 15, "rendimiento": 15, "limpieza": 15})
        self.assertEqual(cfg["bandas"], [50, 90])
        self.assertEqual(cfg["rendimiento"], {"fcp": 10, "si": 10, "lcp": 25, "tbt": 30, "cls": 25})
        self.assertEqual(cfg["penalizacion_limpieza"], 20)


class TestCorrida(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)
        self.corrida = ap.preparar_corrida(self.tmp, crudo=None)
        self.crudo = self.corrida / "crudo"

    def tearDown(self):
        ap.limpiar(self.tmp)

    def escribir(self, nombre, obj):
        (self.crudo / nombre).write_text(json.dumps(obj), encoding="utf-8")

    def test_cli_sin_datos_rc0(self):
        p = subprocess.run([sys.executable, str(RAIZ / "scripts" / "iua.py"), "--corrida", str(self.corrida)],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads((self.corrida / "iua.json").read_text(encoding="utf-8"))
        self.assertIsNone(r["iua"])
        self.assertEqual(set(r["componentes"]), {"accesibilidad", "teclado", "responsive_tactil",
                                                 "robustez_estados", "rendimiento", "limpieza"})

    def test_lee_crudo_de_sondas_y_hallazgos(self):
        self.escribir("axe.json", [axe(passes=[regla("a", "critical")]), axe(passes=[regla("b", "serious")])])
        self.escribir("lighthouse.json", [lhr(0.9), lhr(0.95), lhr(0.85)])
        self.escribir("playwright_ux.json", {"teclado": {"interactivos": 5, "alcanzables_foco_visible": 5},
                                             "limpieza": {"tipos_error": ["consola"]}})
        h = hallazgo_fallback("UX-ESTADOS", "check:ux_estatico.fetch_sin_catch")
        (self.corrida / "hallazgos_todos.jsonl").write_text(json.dumps(h) + "\n", encoding="utf-8")
        r = iua.generar(self.corrida)
        self.assertEqual(r["componentes"]["accesibilidad"]["puntaje"], 100.0)
        self.assertEqual(r["componentes"]["accesibilidad"]["detalle"]["paginas"], 2)
        self.assertEqual(r["componentes"]["rendimiento"]["puntaje"], 90.0)
        self.assertEqual(r["componentes"]["teclado"]["puntaje"], 100.0)
        self.assertEqual(r["componentes"]["limpieza"]["puntaje"], 80.0)
        self.assertEqual(r["componentes"]["robustez_estados"]["estado"], "parcial_fallback")
        self.assertEqual(r["cobertura"]["componentes_medidos"], 4)
        self.assertTrue((self.corrida / "iua.json").is_file())

    def test_axe_embebido_en_playwright(self):
        self.escribir("playwright_ux.json", {"axe": [axe(violations=[regla("a", "critical")])]})
        r = iua.generar(self.corrida)
        self.assertEqual(r["componentes"]["accesibilidad"]["puntaje"], 0.0)

    def test_meta_con_error_no_se_usa(self):
        self.escribir("lighthouse.json", [lhr(0.9)])
        self.escribir("lighthouse.meta.json", {"herramienta": "lighthouse", "estado": "error", "error": "timeout"})
        r = iua.generar(self.corrida)
        rend = r["componentes"]["rendimiento"]
        self.assertEqual(rend["estado"], "no_evaluado")
        self.assertIn("lighthouse", rend["motivo"])

    def test_json_invalido_no_rompe(self):
        (self.crudo / "axe.json").write_text("{no es json", encoding="utf-8")
        r = iua.generar(self.corrida)
        self.assertEqual(r["componentes"]["accesibilidad"]["estado"], "no_evaluado")

    def test_determinista(self):
        self.escribir("axe.json", axe(passes=[regla("a", "critical")], violations=[regla("b", "minor")]))
        iua.generar(self.corrida)
        a = (self.corrida / "iua.json").read_bytes()
        iua.generar(self.corrida)
        self.assertEqual(a, (self.corrida / "iua.json").read_bytes())


class TestInformeYAuditar(unittest.TestCase):
    """Integración: render_informe muestra letra A-E y el IUA con cobertura; bin/auditar gates corre iua.py."""

    @classmethod
    def setUpClass(cls):
        from normalizar import run as n_run
        cls.tmp = ap.tmp_dir(cls)
        cls.corrida = ap.preparar_corrida(cls.tmp)
        (cls.corrida / "crudo" / "axe.json").write_text(
            json.dumps(axe(passes=[regla("image-alt", "critical")], violations=[regla("label", "critical")])),
            encoding="utf-8")
        n_run.main([str(cls.corrida)])
        p = subprocess.run([sys.executable, str(RAIZ / "scripts" / "render_informe.py"), "--corrida",
                            str(cls.corrida)], capture_output=True, text=True)
        assert p.returncode == 0, p.stderr
        cls.informe = (cls.corrida / "informe.md").read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        ap.limpiar(cls.tmp)

    def test_render_genera_iua_si_falta(self):
        self.assertTrue((self.corrida / "iua.json").is_file())

    def test_tabla_con_letra(self):
        self.assertIn("Letra (A-E)", self.informe)
        self.assertRegex(self.informe, r"\| SEG \| N\d \| N\d \| [A-E] \|")
        self.assertRegex(self.informe, r"Puntaje global: [\d.]+/100 · letra [A-E]")

    def test_seccion_iua_con_cobertura(self):
        self.assertIn("Índice de Usabilidad Automatizado (IUA)", self.informe)
        self.assertIn("IUA: 50/100", self.informe)
        self.assertIn("cobertura 25 %", self.informe)
        self.assertIn("1/6 componentes", self.informe)
        self.assertRegex(self.informe, r"\| accesibilidad \| medido \| 50/100 \|")
        self.assertRegex(self.informe, r"\| teclado \| no_evaluado \| — \|")
        self.assertIn("SUS: sin datos de usuarios. El IUA no lo reemplaza.", self.informe)
        self.assertIn("0-49 pobre", self.informe)

    def test_iua_fallback_en_informe(self):
        tmp = ap.tmp_dir()
        try:
            corrida = ap.preparar_corrida(tmp, crudo=None)
            h = hallazgo_fallback("UX-TECLADO", "check:ux_estatico.click_en_div")
            (corrida / "hallazgos_todos.jsonl").write_text(json.dumps(h) + "\n", encoding="utf-8")
            iua.generar(corrida)
            import render_informe
            texto = render_informe._seccion_iua(json.loads((corrida / "iua.json").read_text(encoding="utf-8")))
            self.assertIn("parcial (fallback)", texto)
            self.assertIn("IUA: sin datos", texto)
        finally:
            ap.limpiar(tmp)

    def test_bin_auditar_gates_corre_iua(self):
        tmp = ap.tmp_dir()
        try:
            corrida = ap.preparar_corrida(tmp)
            p = subprocess.run([str(RAIZ / "bin" / "auditar"), "gates", str(ap.APP), "--salida", str(corrida)],
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue((corrida / "iua.json").is_file())
            run = json.loads((corrida / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(run["fases"]["iua"]["estado"], "ok")
        finally:
            ap.limpiar(tmp)


if __name__ == "__main__":
    unittest.main()
