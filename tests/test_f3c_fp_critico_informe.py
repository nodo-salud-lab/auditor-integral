"""F3-C: un hallazgo crítico/alto que la IA (triage-fp) marcó como falso positivo o incierto se ADVIERTE en el informe.

Caso real (kine us, corrida 2026-11-18_2110-8f38a6d): triage-fp marcó falso_positivo los 3 SEG-SECRETO-BUNDLE de
dist/. veredictos.py dejó el control en no_evaluado (correcto, fail-closed), pero la sección 6 seguía listándolos
como críticos abiertos con «Rotar la clave…» y «Qué hacer ahora» decía «ver /auditar-doctor».

Comportamiento esperado (determinista, sin red ni LLM):
1. El hallazgo NO desaparece de la sección 6, pero lleva «⚠ La IA lo marcó como posible falso positivo (triage-fp):
   <razón escapada>. Requiere verificación humana antes de actuar.». 'incierto' también se advierte (cuenta como
   verdadero).
2. Si TODAS las instancias del control están marcadas falso_positivo, la remediación es condicional: primero
   verificar a mano en archivo:línea; si es real → remediación del catálogo; si no → el auditor dice que no tiene
   un mecanismo para registrarlo (no inventa un comando).
3. «Qué hacer ahora», hoja-de-ruta.md y resumen-dueno.md muestran esa verificación humana, no /auditar-doctor.
4. La razón de la IA pasa por el escape Markdown/HTML (sin <img>, sin enlaces, sin romper el código en línea).
"""
import json
import re
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import gates  # noqa: E402
import render_informe  # noqa: E402
import roadmap  # noqa: E402
from test_f3a_veredictos import Base, hallazgo, ver  # noqa: E402

ARCHIVO = "dist/assets/index.js"
RAZON_FP = "generic-api-key casó con identificadores minificados de una librería: no hay credencial."
MALICIOSA = ("<img src=x onerror=alert(1)> [clic](http://evil.example) `cerrar` | celda\n# Titulo inyectado "
             "<script>alert(2)</script>")


def seccion(texto, inicio, fin):
    i = texto.index(inicio)
    j = texto.index(fin, i + len(inicio)) if fin else len(texto)
    return texto[i:j]


def bloque_item(texto, control):
    """Líneas del ítem numerado «N. **CONTROL**» hasta el siguiente ítem o encabezado."""
    lineas = texto.splitlines()
    for k, l in enumerate(lineas):
        if re.match(rf"^\d+\. \*\*{re.escape(control)}\*\*", l):
            fin = k + 1
            while fin < len(lineas) and not re.match(r"^(\d+\. \*\*|#|\*\*Paso|…)", lineas[fin]):
                fin += 1
            return "\n".join(lineas[k:fin])
    raise AssertionError(f"no hay ítem de {control}")


class BaseInforme(Base):
    def setUp(self):
        super().setUp()
        (self.proyecto / "dist" / "assets" / "index.js").write_text(
            "\n".join(f"var a{i}=1;" for i in range(1, 21)) + "\n", encoding="utf-8")
        (self.corrida / "crudo" / "gitleaks.json").write_text("[]", encoding="utf-8")
        (self.corrida / "crudo" / "gitleaks.meta.json").write_text(json.dumps(
            {"herramienta": "gitleaks", "version": "8", "estado": "ok",
             "alcance": {"bundles": 1, "archivos": 3, "commits": 0, "historial": 0}}), encoding="utf-8")

    def secretos(self, n=1):
        hs = [hallazgo(i, "SEG-SECRETO-BUNDLE", "critica", ARCHIVO, 4 + i, gate="N1", conf="baja",
                       herramienta="gitleaks") for i in range(n)]
        for h in hs:  # normalize copia la remediación de plantillas/remediaciones.toml
            h["remediacion"] = "Rotar la clave y moverla al servidor; volver a construir el bundle."
        self.poner_hallazgos(hs)
        return hs

    def fp(self, h, razon=RAZON_FP):
        return ver("triage-fp", "SEG-SECRETO-BUNDLE", "falso_positivo", razon=razon, hallazgo_id=h["id"],
                   ubicaciones=[f"{ARCHIVO}:{h['ubicacion']['linea']}"], requiere_verificacion_humana=True)

    def render(self):
        if (self.corrida / "veredictos.jsonl").is_file():
            import veredictos
            self.assertEqual(veredictos.main([str(self.corrida)]), 0)
        else:
            gates.generar(self.corrida)
        render_informe.generar(self.corrida)
        leer = lambda n: (self.corrida / n).read_text(encoding="utf-8")  # noqa: E731
        return leer("informe.md"), leer("hoja-de-ruta.md"), leer("resumen-dueno.md")

    def sec6(self, informe):
        return seccion(informe, "## 6. Hallazgos críticos y altos", "## 6b.")


class TestSeccion6FalsoPositivoCritico(BaseInforme):
    def test_fp_critico_se_advierte_y_no_desaparece(self):
        hs = self.secretos(3)
        self.poner_veredictos([self.fp(h) for h in hs])
        informe, _, _ = self.render()
        s6 = self.sec6(informe)
        # fail-closed: el hallazgo sigue en la sección 6, con sus 3 ubicaciones
        self.assertIn("### SEG-SECRETO-BUNDLE", s6)
        for h in hs:
            self.assertIn(f"`{ARCHIVO}:{h['ubicacion']['linea']}`", s6)
        self.assertEqual(s6.count("⚠ La IA lo marcó como posible falso positivo (triage-fp)"), 3)
        self.assertIn(RAZON_FP, s6)
        self.assertIn("Requiere verificación humana antes de actuar.", s6)
        # el control nunca queda en pass
        est = json.loads((self.corrida / "estado.json").read_text(encoding="utf-8"))
        e = next(c for c in est["controles"] if c["control"] == "SEG-SECRETO-BUNDLE")
        self.assertEqual(e["estado"], "no_evaluado")
        # hallazgos.jsonl no se toca (sigue abierto: el triage vive en decisiones_ia.json)
        for linea in (self.corrida / "hallazgos.jsonl").read_text(encoding="utf-8").splitlines():
            self.assertEqual(json.loads(linea)["estado_hallazgo"], "abierto")

    def test_remediacion_condicional_y_concreta(self):
        hs = self.secretos(2)
        self.poner_veredictos([self.fp(h) for h in hs])
        s6 = self.sec6(self.render()[0])
        rem = seccion(s6, "Remediación", "\n- `")
        self.assertIn("condicional", rem)
        self.assertIn(f"`{ARCHIVO}:4`", rem)
        self.assertIn(f"`{ARCHIVO}:5`", rem)
        self.assertIn("credencial real", rem)
        # primero verificar, luego (si es real) la remediación del catálogo
        self.assertLess(rem.index("Verificar a mano"), rem.index("Rotar la clave"))
        self.assertLess(rem.index("Si es una credencial real"), rem.index("Rotar la clave"))
        # sin mecanismo para registrar el FP: se dice, no se inventa un comando
        self.assertIn("no tiene un mecanismo", rem)
        self.assertIn("críticos de N1 nunca se aceptan", rem)
        self.assertNotRegex(rem, r"/auditar-[a-z]+ .*falso")

    def test_incierto_se_advierte_y_cuenta_como_verdadero(self):
        h = self.secretos(1)[0]
        self.poner_veredictos([ver("triage-fp", "SEG-SECRETO-BUNDLE", "incierto", razon="No se puede saber.",
                                   hallazgo_id=h["id"])])
        informe, ruta, _ = self.render()
        s6 = self.sec6(informe)
        self.assertIn("### SEG-SECRETO-BUNDLE", s6)
        self.assertIn("⚠ La IA no pudo confirmarlo ni descartarlo (triage-fp, incierto)", s6)
        self.assertIn("No se puede saber.", s6)
        self.assertIn("cuenta como verdadero", s6)
        # incierto = verdadero: la remediación del catálogo se mantiene sin condición
        self.assertIn("Remediación: Rotar la clave", s6)
        self.assertNotIn("condicional", s6)
        item = bloque_item(seccion(informe, "Qué hacer ahora", "\n## "), "SEG-SECRETO-BUNDLE")
        self.assertIn("Hacer: Rotar la clave", item)

    def test_sin_triage_no_cambia_nada(self):
        self.secretos(1)
        informe, ruta, dueno = self.render()
        s6 = self.sec6(informe)
        self.assertIn("### SEG-SECRETO-BUNDLE", s6)
        self.assertIn("Remediación: Rotar la clave", s6)
        self.assertNotIn("⚠", s6)
        self.assertNotIn("falso positivo", s6)
        self.assertNotIn("condicional", s6)
        rm = json.loads((self.corrida / "roadmap.json").read_text(encoding="utf-8"))
        item = next(i for i in rm["items"] if i["control"] == "SEG-SECRETO-BUNDLE")
        self.assertEqual(item["estado"], "fail")
        self.assertNotIn("revision_ia", item)
        self.assertTrue(item["que_hacer"].startswith("Rotar la clave"))

    def test_razon_maliciosa_queda_escapada(self):
        h = self.secretos(1)[0]
        self.poner_veredictos([self.fp(h, razon=MALICIOSA)])
        informe, _, _ = self.render()
        s6 = self.sec6(informe)
        self.assertIn("⚠ La IA lo marcó como posible falso positivo", s6)
        self.assertNotIn("<img", s6)
        self.assertNotIn("<script", s6)
        self.assertIn("&lt;img", s6)
        self.assertNotRegex(s6, r"(?<!\\)\]\(http")   # corchetes escapados: no es un enlace
        self.assertIn("\\[clic\\]", s6)
        self.assertNotIn("`cerrar`", s6)
        self.assertNotIn("\n# Titulo", s6)
        self.assertNotIn("| celda", s6.replace("\\| celda", ""))


class TestOtrasSuperficies(BaseInforme):
    def setUp(self):
        super().setUp()
        hs = self.secretos(3)
        self.poner_veredictos([self.fp(h) for h in hs])
        self.informe, self.ruta, self.dueno = self.render()

    def assert_verificacion_humana(self, bloque):
        self.assertIn("Verificación humana", bloque)
        self.assertIn(f"`{ARCHIVO}:4`", bloque)
        self.assertIn("falso positivo", bloque)
        self.assertNotIn("/auditar-doctor", bloque)
        self.assertNotIn("Habilitar lo que falta", bloque)

    def test_que_hacer_ahora_del_informe(self):
        self.assert_verificacion_humana(bloque_item(seccion(self.informe, "Qué hacer ahora", "\n## "),
                                                    "SEG-SECRETO-BUNDLE"))

    def test_hoja_de_ruta(self):
        qh = seccion(self.ruta, "## Qué hacer ahora", "# Detalle por grupo")
        self.assert_verificacion_humana(bloque_item(qh, "SEG-SECRETO-BUNDLE"))
        detalle = bloque_item(seccion(self.ruta, "# Detalle por grupo", None), "SEG-SECRETO-BUNDLE")
        self.assert_verificacion_humana(detalle)
        self.assertLess(detalle.index("Verificar a mano"), detalle.index("Rotar la clave"))

    def test_resumen_del_dueno(self):
        self.assert_verificacion_humana(bloque_item(seccion(self.dueno, "## Qué hacer ahora", "---"),
                                                    "SEG-SECRETO-BUNDLE"))
        falta = seccion(self.dueno, "## Qué falta", "## Qué hacer ahora")
        self.assertIn("posible falso positivo de la IA", falta)   # grupo propio (F3-C adv.)

    def test_lo_que_no_se_evaluo(self):
        s7 = seccion(self.informe, "## 7. Lo que NO se evaluó", "## 8.")
        fila = next(l for l in s7.splitlines() if l.startswith("| SEG-SECRETO-BUNDLE"))
        self.assertNotIn("/auditar-doctor", fila)
        self.assertIn("verificación humana", fila)

    def test_roadmap_json_registra_la_revision_de_la_ia(self):
        rm = json.loads((self.corrida / "roadmap.json").read_text(encoding="utf-8"))
        item = next(i for i in rm["items"] if i["control"] == "SEG-SECRETO-BUNDLE")
        self.assertEqual(item["estado"], "no_evaluado")
        self.assertEqual(item["revision_ia"]["veredicto"], "falso_positivo")
        self.assertEqual(len(item["revision_ia"]["hallazgos"]), 3)
        self.assertTrue(item["verificacion"].startswith("Verificación humana"))


class TestFuncionesPuras(unittest.TestCase):
    def h(self, n, linea):
        return {"id": f"H-{n}", "control": "SEG-SECRETO-BUNDLE", "severidad": "critica", "gate": "N1",
                "estado_hallazgo": "abierto", "confianza": "baja", "metodo": "determinista",
                "fuente": [{"herramienta": "gitleaks", "regla": "generic-api-key"}],
                "ubicacion": {"archivo": ARCHIVO, "linea": linea}, "evidencia": "x",
                "remediacion": "Rotar la clave y moverla al servidor."}

    def test_mezcla_fp_y_verdadero_mantiene_remediacion(self):
        hs = [self.h(1, 4), self.h(2, 9)]
        triage = {"H-1": {"veredicto": "falso_positivo", "razon": "minificado", "modelo": "m"},
                  "H-2": {"veredicto": "verdadero", "razon": "es real", "modelo": "m"}}
        s = render_informe._seccion_hallazgos(hs, {}, triage=triage)
        self.assertIn("Remediación: Rotar la clave", s)
        self.assertNotIn("condicional", s)
        self.assertEqual(s.count("⚠ La IA lo marcó como posible falso positivo"), 1)

    def test_sin_triage_igual_que_antes(self):
        hs = [self.h(1, 4)]
        self.assertEqual(render_informe._seccion_hallazgos(hs, {}), render_informe._seccion_hallazgos(hs, {}, triage={}))

    def test_triage_ilegible_es_vacio(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(roadmap.triage_de_corrida(d), {})
            (Path(d) / "decisiones_ia.json").write_text("{no json", encoding="utf-8")
            self.assertEqual(roadmap.triage_de_corrida(d), {})
            (Path(d) / "decisiones_ia.json").write_text(json.dumps({"triage": {"H-1": "x", "H-2": {"veredicto": 3}}}),
                                                       encoding="utf-8")
            self.assertEqual(roadmap.triage_de_corrida(d), {})


class TestAdversarialF3C(BaseInforme):
    """Hallazgos de los verificadores adversariales sobre la corrección F3-C."""

    def estado_de(self, control="SEG-SECRETO-BUNDLE"):
        est = json.loads((self.corrida / "estado.json").read_text(encoding="utf-8"))
        return next(c for c in est["controles"] if c["control"] == control)

    def test_1_fp_sobre_alto_no_promete_no_evaluado_si_quedo_en_pass(self):
        h = hallazgo(0, "SEG-SECRETO-BUNDLE", "alta", ARCHIVO, 4, gate="N1", conf="baja", herramienta="gitleaks")
        h["remediacion"] = "Rotar la clave y moverla al servidor; volver a construir el bundle."
        self.poner_hallazgos([h])
        self.poner_veredictos([self.fp(h)])
        s6 = self.sec6(self.render()[0])
        # Decisión F3-C (18-11-2026): un FP de la IA sobre un alto ya NO deja pass (test_f3c_fp_alto.py);
        # el informe dice no_evaluado y lo cumple.
        self.assertEqual(self.estado_de()["estado"], "no_evaluado")
        self.assertIn("queda `no_evaluado`", s6)
        self.assertNotIn("quedó en `pass`", s6)
        # defensa: si un control con graves marcados FP quedara en pass, el texto no promete un no_evaluado
        defensa = roadmap._cierre_estado("pass")
        self.assertIn("quedó en `pass`", defensa)
        self.assertNotIn("no_evaluado", defensa)

    def test_2_control_en_fail_usa_la_remediacion_del_catalogo_en_la_seccion_6(self):
        h = self.secretos(1)[0]
        otro = hallazgo(7, "SEG-SECRETO-BUNDLE", "media", ARCHIVO, 12, gate="N1", herramienta="gitleaks")
        self.poner_hallazgos([h, otro])
        self.poner_veredictos([self.fp(h)])
        informe = self.render()[0]
        self.assertEqual(self.estado_de()["estado"], "fail")
        s6 = self.sec6(informe)
        self.assertIn("Remediación: Rotar la clave", s6)
        self.assertNotIn("condicional", s6)
        self.assertNotIn("no_evaluado", s6)
        self.assertIn("⚠ La IA lo marcó como posible falso positivo", s6)   # el aviso por instancia se mantiene
        rm = json.loads((self.corrida / "roadmap.json").read_text(encoding="utf-8"))
        item = next(i for i in rm["items"] if i["control"] == "SEG-SECRETO-BUNDLE")
        self.assertTrue(item["que_hacer"].startswith("Rotar la clave"))

    def test_4_url_suelta_en_la_razon_no_queda_como_autolink(self):
        h = self.secretos(1)[0]
        self.poner_veredictos([self.fp(h, razon="ver https://evil.example/x?a=1 y www.evil.example o a@evil.example")])
        s6 = self.sec6(self.render()[0])
        aviso = next(l for l in s6.splitlines() if "⚠" in l)
        self.assertNotIn("://", aviso)
        self.assertNotIn("www.evil", aviso)
        self.assertNotIn("a@evil", aviso)
        self.assertIn("evil", aviso)   # el contenido se conserva, solo se desactiva el enlace

    def test_8_advierte_que_gitleaksignore_no_cierra_el_caso(self):
        hs = self.secretos(1)
        self.poner_veredictos([self.fp(h) for h in hs])
        rem = seccion(self.sec6(self.render()[0]), "Remediación", "\n- `")
        self.assertIn(".gitleaksignore", rem)


class TestAdversarialSuperficies(BaseInforme):
    def setUp(self):
        super().setUp()
        hs = self.secretos(3)
        self.ids = [h["id"] for h in hs]
        self.poner_veredictos([self.fp(h) for h in hs])
        self.informe, self.ruta, self.dueno = self.render()

    def test_5_sin_contradiccion_sobre_el_efecto_de_la_verificacion(self):
        for doc in (self.informe, self.ruta, self.dueno):
            self.assertNotIn("hasta esa verificación", doc)
            self.assertNotIn("seguirá `no_evaluado`", doc)
        item = bloque_item(seccion(self.informe, "Qué hacer ahora", "\n## "), "SEG-SECRETO-BUNDLE")
        self.assertIn("la verificación humana no lo cambia", item)

    def test_6_que_falta_no_manda_a_auditar_informe(self):
        falta = seccion(self.informe, "## 3. Qué falta", "\n## ")
        grupo = seccion(falta, "**Posible falso positivo de la IA por verificar**", "- Cómo:")
        self.assertIn("SEG-SECRETO-BUNDLE", grupo)
        como = falta[falta.index("- Cómo:", falta.index("**Posible falso positivo")):].splitlines()[0]
        self.assertNotIn("/auditar-informe", como)
        self.assertIn("sección 6", como)
        if "**Verificación humana**" in falta:
            self.assertNotIn("SEG-SECRETO-BUNDLE", seccion(falta, "**Verificación humana**", "- Cómo:"))
        d = seccion(self.dueno, "## Qué falta", "## Qué hacer ahora")
        self.assertIn("- revisar a mano un posible falso positivo de la IA (ver «Qué hacer ahora»): 1 punto(s)", d)

    def test_7_tabla_6b_no_dice_que_descarta_un_grave(self):
        s6b = seccion(self.informe, "## 6b.", "\n## 7")
        filas = [l for l in s6b.splitlines() if any(i in l for i in self.ids)]
        self.assertEqual(len(filas), 3)
        for f in filas:
            self.assertNotIn("descarta el hallazgo", f)
            self.assertIn("no se descarta", f.lower())


class TestControlesEnUbicaciones(unittest.TestCase):
    def test_3_retorno_de_carro_y_separadores_no_salen_del_codigo(self):
        malo = "dist/a\r## INYECTADO [clic](https://evil.example)\u2028x\x85y\x0bz\rb.js:5"
        for texto in (roadmap.lista_ubicaciones([malo]), render_informe._codigo(malo), render_informe._celda(malo),
                      roadmap.remediacion_condicional({"id": "SEG-SECRETO-BUNDLE", "gate": "N1"}, "critica",
                                                      [malo], "Rotar.")):
            for ch in "\r\n\u2028\u2029\x85\x0b\x0c":
                self.assertNotIn(ch, texto)


if __name__ == "__main__":
    unittest.main()
