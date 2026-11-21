"""F3-B: secciones fáciles del informe para el desarrollador y del resumen del dueño.

«Qué hizo el auditor» (herramientas, qué revisó la IA, qué no se pudo evaluar, tokens), «Qué falta» (pendientes
agrupados por lo que los resolvería) y «Qué hacer ahora» (críticos, luego siguiente nivel, con esfuerzo y comando o
archivo concreto). Las llena render_informe.py sin LLM; el texto del redactor-dueno solo se usa si valida.
"""
import json
import re
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import render_informe as ri  # noqa: E402
from normalizar import run as n_run  # noqa: E402

INDICE = {
    "SEG-A": {"id": "SEG-A", "gate": "N1", "titulo": "A", "herramientas": ["gitleaks"], "dominio": "SEG"},
    "UX-B": {"id": "UX-B", "gate": "N2", "titulo": "B", "herramientas": ["playwright_ux"], "dominio": "UX"},
    "OPS-C": {"id": "OPS-C", "gate": "N2", "titulo": "C", "herramientas": ["entrevista"], "dominio": "OPS",
              "condicion": "datos_personales == true"},
    "OPS-D": {"id": "OPS-D", "gate": "N2", "titulo": "D", "herramientas": [], "dominio": "OPS", "aviso_legal": True},
    "SEG-E": {"id": "SEG-E", "gate": "N2", "titulo": "E", "herramientas": ["revisor-autorizacion"], "dominio": "SEG"},
    "COD-F": {"id": "COD-F", "gate": "N4", "titulo": "F", "herramientas": ["lizard"], "dominio": "COD"},
    "SEG-G": {"id": "SEG-G", "gate": "N2", "titulo": "G", "herramientas": ["semgrep"], "dominio": "SEG"},
}
ESTADOS = [
    {"control": "SEG-A", "estado": "no_evaluado", "motivo": "gitleaks: herramienta ausente"},
    {"control": "UX-B", "estado": "no_evaluado", "motivo": "playwright_ux: sin datos de la herramienta (no se ejecutó)"},
    {"control": "OPS-C", "estado": "no_evaluado", "motivo": "falta respuesta en la entrevista: datos_personales"},
    {"control": "OPS-D", "estado": "manual_pendiente", "motivo": "aviso legal: verificación pendiente del creador"},
    {"control": "SEG-E", "estado": "no_evaluado", "motivo": "juicio LLM no ejecutado en F1 (revisor-autorizacion)"},
    {"control": "COD-F", "estado": "no_evaluado", "motivo": "fuera del alcance del modo rapido (N4 > N2)"},
    {"control": "SEG-G", "estado": "no_evaluado", "motivo": "semgrep: timeout de la herramienta"},
]
HERRAMIENTAS = {"herramientas": {"gitleaks": {"estado": "ausente", "instalacion_sugerida": "brew install gitleaks"}}}


class TestClasificar(unittest.TestCase):
    def test_grupos(self):
        cats = {e["control"]: ri.clasificar_pendiente(e, INDICE)[0] for e in ESTADOS}
        self.assertEqual(cats, {"SEG-A": "instalar", "UX-B": "levantar_app", "OPS-C": "entrevista",
                                "OPS-D": "verificacion_humana", "SEG-E": "juicio_ia", "COD-F": "modo",
                                "SEG-G": "reintentar"})

    def test_pregunta_de_la_entrevista(self):
        self.assertEqual(ri.clasificar_pendiente(ESTADOS[2], INDICE)[1], [3])

    def test_que_falta_agrupado(self):
        t = ri.seccion_que_falta(ESTADOS, INDICE, HERRAMIENTAS)
        for titulo in ("Instalar o habilitar herramientas", "Responder preguntas de la entrevista", "Levantar la app",
                       "Verificación humana", "Juicio de la IA pendiente", "Cambiar de modo"):
            self.assertIn(titulo, t)
        self.assertIn("brew install gitleaks", t)
        self.assertIn("sin ejecutar", t)
        self.assertIn("pregunta 3", t)
        self.assertIn("SEG-A", t)
        self.assertLess(t.index("Instalar o habilitar"), t.index("Verificación humana"))

    def test_que_falta_vacio(self):
        self.assertIn("Nada pendiente", ri.seccion_que_falta([{"control": "SEG-A", "estado": "pass"}], INDICE, {}))


class TestQueHizo(unittest.TestCase):
    RESUMEN = {"herramientas": {"gitleaks": {"estado": "ok", "version": "8.30.1"},
                                "trufflehog": {"estado": "ausente", "version": None},
                                "registro_deps": {"estado": "timeout", "version": "0.1.0"}}}

    def test_sin_ia_y_sin_tokens(self):
        t = ri.seccion_que_hizo(self.RESUMEN, ESTADOS, INDICE, [], None, "estandar")
        self.assertIn("gitleaks 8.30.1", t)
        self.assertIn("trufflehog", t)
        self.assertIn("La IA no emitió juicios", t)
        self.assertRegex(t, r"Tokens.*no medido")
        self.assertIn("7 controles", t)

    def test_con_ia_y_tokens(self):
        ver = [{"agente": "triage-fp", "control": "SEG-A", "veredicto": "verdadero", "razon": "x", "modelo": "m"},
               {"agente": "revisor-autorizacion", "control": "SEG-E", "veredicto": "fail", "razon": "y", "modelo": "m",
                "requiere_verificacion_humana": True}]
        tok = {"total": 12345, "por_fase": {"f4d_triage": 3000, "f4a_autorizacion": 9345}}
        t = ri.seccion_que_hizo(self.RESUMEN, ESTADOS, INDICE, ver, tok, "estandar")
        self.assertIn("triage-fp", t)
        self.assertIn("revisor-autorizacion", t)
        self.assertIn("requiere verificación humana", t)
        self.assertIn("12345", t)
        self.assertIn("f4a_autorizacion", t)
        self.assertRegex(t, r"techo duro.*100000")

    def test_tokens_ilegibles_no_inventa(self):
        t = ri.seccion_que_hizo(self.RESUMEN, ESTADOS, INDICE, [], {"raro": "x"}, "rapido")
        self.assertRegex(t, r"Tokens.*no medido")


class TestQueHacer(unittest.TestCase):
    RM = {"items": [
        {"orden": 1, "control": "SEG-A", "titulo": "Secreto", "estado": "fail", "severidad": "critica", "esfuerzo": "S",
         "grupo": "esta_semana", "que_hacer": "Rotar la clave.", "verificacion": "/auditar --modo estandar", "gate": "N1",
         "bloquea_global": True, "hallazgos": 1},
        {"orden": 2, "control": "COD-F", "titulo": "CI", "estado": "fail", "severidad": "media", "esfuerzo": "M",
         "grupo": "siguiente_nivel", "que_hacer": "Agregar CI.", "verificacion": "/auditar --modo estandar", "gate": "N2",
         "bloquea_global": False, "hallazgos": 0},
        {"orden": 3, "control": "UX-B", "titulo": "UX", "estado": "no_evaluado", "severidad": "alta", "esfuerzo": "L",
         "grupo": "siguiente_nivel", "que_hacer": "x", "verificacion": "Habilitar lo que falta", "gate": "N2",
         "bloquea_global": False, "hallazgos": 0, "motivo": "playwright_ux: sin datos"}]}
    HALLAZGOS = [{"control": "SEG-A", "severidad": "critica", "ubicacion": {"archivo": "src/a.js", "linea": 7}}]

    def test_orden_y_campos(self):
        t = ri.seccion_que_hacer(self.RM, self.HALLAZGOS, "N2")
        self.assertLess(t.index("SEG-A"), t.index("COD-F"))
        self.assertLess(t.index("COD-F"), t.index("UX-B"))
        self.assertIn("`src/a.js:7`", t)
        self.assertRegex(t, r"esfuerzo \*\*S\*\*")
        self.assertRegex(t, r"esfuerzo \*\*L\*\*")
        self.assertIn("Críticos", t)
        self.assertIn("N2", t)

    def test_tope(self):
        rm = {"items": [dict(self.RM["items"][1], orden=i, control=f"COD-{i}") for i in range(1, 30)]}
        t = ri.seccion_que_hacer(rm, [], "N2", maximo=5)
        self.assertIn("y 24 más", t)
        self.assertNotIn("COD-6 ", t)

    def test_vacio(self):
        self.assertIn("Nada urgente", ri.seccion_que_hacer({"items": []}, [], "N3"))


class TestRedactor(unittest.TestCase):
    RM = TestQueHacer.RM

    def test_valido(self):
        r = {"agente": "redactor-dueno", "resumen": "Su app guarda una clave a la vista.",
             "por_que_importa": {"SEG-A": "Cualquiera puede usar la clave y gastar a su nombre."}, "modelo": "m"}
        ok, motivo = ri.validar_redaccion(r, self.RM)
        self.assertTrue(ok, motivo)

    def test_rechazos(self):
        base = {"agente": "redactor-dueno", "resumen": "ok", "por_que_importa": {}, "modelo": "m"}
        malos = [dict(base, por_que_importa={"SEG-ZZZ": "inventado"}),
                 dict(base, resumen=" ".join(["palabra"] * 201)),
                 dict(base, por_que_importa={"SEG-A": " ".join(["p"] * 26)}),
                 dict(base, extra=1), dict(base, agente="triage-fp"), "no es objeto"]
        for m in malos:
            self.assertFalse(ri.validar_redaccion(m, self.RM)[0], m)


class TestRenderCompleto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = ap.tmp_dir(cls)
        cls.corrida = ap.preparar_corrida(cls.tmp)
        n_run.main([str(cls.corrida)])
        ri.generar(cls.corrida)
        cls.informe = (cls.corrida / "informe.md").read_text(encoding="utf-8")
        cls.dueno = (cls.corrida / "resumen-dueno.md").read_text(encoding="utf-8")
        cls.ruta = (cls.corrida / "hoja-de-ruta.md").read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        ap.limpiar(cls.tmp)

    def test_tres_secciones_en_orden(self):
        a = self.informe.index("## 2. Qué hizo el auditor")
        b = self.informe.index("## 3. Qué falta")
        c = self.informe.index("## 4. Qué hacer ahora")
        self.assertLess(self.informe.index("## 1. Veredicto"), a)
        self.assertLess(a, b)
        self.assertLess(b, c)
        self.assertLess(c, self.informe.index("Tablero por dominio"))

    def test_contenido_real(self):
        self.assertIn("gitleaks 8.30.1", self.informe)
        self.assertIn("La IA no emitió juicios", self.informe)
        self.assertIn("SEG-SECRETO-REPO", self.informe.split("## 4. Qué hacer ahora")[1])

    def test_resumen_dueno(self):
        for s in ("Qué hizo el auditor", "Qué falta", "Qué hacer ahora"):
            self.assertIn(s, self.dueno)
        self.assertNotRegex(self.dueno, r"\$\{?[a-z_]+")
        self.assertIn("no certifica", self.dueno)

    def test_hoja_de_ruta(self):
        self.assertIn("## Qué hacer ahora", self.ruta)

    def test_sin_placeholders(self):
        fuente = (RAIZ / "plantillas" / "resumen-dueno.md.tmpl").read_text(encoding="utf-8")
        for var in set(re.findall(r"\$\{?([a-z_]+)", fuente)):
            self.assertNotRegex(self.dueno, r"\$\{?" + var + r"\b", var)


class TestRedactorEnRender(unittest.TestCase):
    def test_usa_y_descarta(self):
        tmp = ap.tmp_dir()
        try:
            corrida = ap.preparar_corrida(tmp)
            n_run.main([str(corrida)])
            ri.generar(corrida)
            rm = json.loads((corrida / "roadmap.json").read_text(encoding="utf-8"))
            c0 = rm["items"][0]["control"]
            red = {"agente": "redactor-dueno", "resumen": "Texto del redactor para el dueño.",
                   "por_que_importa": {c0: "Importa porque expone datos."}, "modelo": "m"}
            (corrida / "redaccion-dueno.json").write_text(json.dumps(red), encoding="utf-8")
            ri.generar(corrida)
            d = (corrida / "resumen-dueno.md").read_text(encoding="utf-8")
            self.assertIn("Texto del redactor para el dueño.", d)
            self.assertIn("Importa porque expone datos.", d)
            red["por_que_importa"] = {"SEG-NO-EXISTE": "x"}
            (corrida / "redaccion-dueno.json").write_text(json.dumps(red), encoding="utf-8")
            ri.generar(corrida)
            d = (corrida / "resumen-dueno.md").read_text(encoding="utf-8")
            self.assertNotIn("Texto del redactor para el dueño.", d)
            self.assertIn("descartado", d)
        finally:
            ap.limpiar(tmp)


if __name__ == "__main__":
    unittest.main()


class TestIntegracionF3AyF3B(unittest.TestCase):
    """Choque F3-A/F3-B: «Qué hizo el auditor» (F3-B) y «Decisiones de la IA» (F3-A) deben contar lo mismo.

    Si existe decisiones_ia.json (veredictos.py corrió), los juicios de IA son SOLO los aplicados por las reglas
    duras; un veredicto que valida el schema pero lo descartan las reglas (p. ej. pass sin método) no puede
    aparecer como juicio de la IA (fail-closed). Sin decisiones_ia.json se usa la lectura por schema.
    """

    def _corrida(self, decisiones=None, lineas=()):
        import shutil
        import tempfile
        ap.TMP_BASE.mkdir(parents=True, exist_ok=True)
        d = Path(tempfile.mkdtemp(dir=ap.TMP_BASE))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "veredictos.jsonl").write_text("\n".join(json.dumps(x) for x in lineas) + "\n", encoding="utf-8")
        if decisiones is not None:
            (d / "decisiones_ia.json").write_text(json.dumps(decisiones), encoding="utf-8")
        return d

    PASS_SIN_METODO = {"agente": "revisor-autorizacion", "control": "SEG-E", "veredicto": "pass", "razon": "ok",
                       "modelo": "m", "ubicaciones": ["src/a.js:3"]}
    FAIL = {"agente": "triage-fp", "control": "SEG-A", "veredicto": "verdadero", "razon": "x", "modelo": "m",
            "requiere_verificacion_humana": True}

    def test_usa_decisiones_si_existen(self):
        dec = {"version_esquema": "1", "aplicadas": [dict(self.FAIL, linea=2, efecto="confirma", hallazgo_id=None)],
               "descartadas": [{"linea": 1, "agente": "revisor-autorizacion", "control": "SEG-E",
                                "veredicto": "pass", "motivo": "pass sin metodo"}], "triage": {}}
        c = self._corrida(dec, [self.PASS_SIN_METODO, self.FAIL])
        ver, desc = ri.veredictos_de_corrida(c)
        self.assertEqual([v["control"] for v in ver], ["SEG-A"])
        self.assertEqual(desc, 1)
        t = ri.seccion_que_hizo({}, ESTADOS, INDICE, ver, None, "estandar", desc)
        self.assertNotIn("revisor-autorizacion", t)
        self.assertRegex(t, r"1 línea\(s\).*descartadas.*reglas")

    def test_sin_decisiones_usa_schema(self):
        c = self._corrida(None, [self.FAIL, {"basura": 1}])
        ver, desc = ri.veredictos_de_corrida(c)
        self.assertEqual(len(ver), 1)
        self.assertEqual(desc, 1)

    def test_decisiones_corruptas_no_cuenta_juicios(self):
        c = self._corrida(None, [self.FAIL])
        (c / "decisiones_ia.json").write_text("{no json", encoding="utf-8")
        ver, desc = ri.veredictos_de_corrida(c)
        self.assertEqual(ver, [])
        self.assertGreaterEqual(desc, 1)
