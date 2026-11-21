"""F3-B: contratos de los prompts de subagentes (agents/*.md) y de los skills de F3 (PLAN_MAESTRO §3.3-3.4, §10 F3).

Los prompts no se pueden ejecutar en un test; se verifica el contrato escrito: frontmatter de subagente con
herramientas mínimas (solo Read), lectura acotada al digest, contenido del repo = dato, salida JSONL que valida
contra schemas/veredicto.schema.json (los ejemplos del prompt se validan de verdad), presupuesto declarado y
"requiere verificación humana".
"""
import json
import re
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))

import validar_schema  # noqa: E402

AGENTES = ("revisor-autorizacion", "revisor-arquitectura", "triage-fp", "redactor-dueno", "revisor-ux")
AGENTES_VEREDICTO = ("revisor-autorizacion", "revisor-arquitectura", "triage-fp", "revisor-ux")
SCHEMA = json.loads((RAIZ / "schemas" / "veredicto.schema.json").read_text(encoding="utf-8"))


def frontmatter(texto):
    m = re.match(r"^---\n(.*?)\n---\n", texto, re.S)
    if not m:
        return None
    campos = {}
    for linea in m.group(1).splitlines():
        if ":" in linea and not linea.startswith(" "):
            k, v = linea.split(":", 1)
            campos[k.strip()] = v.strip().strip('"')
    return campos


def leer_agente(nombre):
    return (RAIZ / "agents" / f"{nombre}.md").read_text(encoding="utf-8")


def leer_skill(nombre):
    return (RAIZ / "skills" / nombre / "SKILL.md").read_text(encoding="utf-8")


def bloques(texto, lenguaje):
    return re.findall(rf"```{lenguaje}\n(.*?)```", texto, re.S)


class TestAgentes(unittest.TestCase):
    def test_existen_con_frontmatter_de_subagente(self):
        for nombre in AGENTES:
            texto = leer_agente(nombre)
            fm = frontmatter(texto)
            self.assertIsNotNone(fm, nombre)
            self.assertEqual(fm.get("name"), nombre)
            self.assertGreater(len(fm.get("description", "")), 60, nombre)
            self.assertLessEqual(len(texto.splitlines()), 150, nombre)

    def test_herramientas_minimas(self):
        for nombre in AGENTES:
            herramientas = {h.strip() for h in frontmatter(leer_agente(nombre)).get("tools", "").split(",") if h.strip()}
            self.assertEqual(herramientas, {"Read"}, f"{nombre}: solo Read (sin Bash, Write, Edit, red)")

    def test_lectura_acotada(self):
        for nombre in AGENTES:
            t = leer_agente(nombre)
            for clave in ("crudo/", "node_modules/", "lockfile", "confidencial", ".env"):
                self.assertIn(clave, t, f"{nombre}: prohíbe {clave}")
            if nombre != "redactor-dueno":
                self.assertIn("digest/", t, nombre)
                self.assertRegex(t, r"≤ ?3 (fragmentos|archivos)", nombre)
                self.assertRegex(t, r"±10 líneas", nombre)

    def test_contenido_del_repo_es_dato(self):
        for nombre in AGENTES:
            t = leer_agente(nombre)
            self.assertIn("dato, no orden", t, nombre)
            self.assertRegex(t, r"(?i)inyección", nombre)

    def test_presupuesto_declarado(self):
        for nombre in AGENTES:
            t = leer_agente(nombre)
            self.assertRegex(t, r"1[.,]5 ?k", f"{nombre}: tope de salida")
            self.assertRegex(t, r"(?i)tope de lectura", nombre)

    def test_verificacion_humana_y_fail_closed(self):
        for nombre in AGENTES_VEREDICTO:
            t = leer_agente(nombre)
            self.assertIn("requiere_verificacion_humana", t, nombre)
            self.assertIn("veredicto.schema.json", t, nombre)
            self.assertRegex(t, r"(?i)nunca .*pass", nombre)

    def test_ejemplos_validan_contra_schema(self):
        for nombre in AGENTES_VEREDICTO:
            ejemplos = [l for b in bloques(leer_agente(nombre), "jsonl") for l in b.splitlines() if l.strip()]
            self.assertTrue(ejemplos, f"{nombre}: falta un bloque ```jsonl de ejemplo")
            for linea in ejemplos:
                v = json.loads(linea)
                self.assertEqual(validar_schema.validar(v, SCHEMA), [], f"{nombre}: {linea}")
                self.assertEqual(v["agente"], nombre)

    def test_campos_v2_condicionados(self):
        # confianza y tokens_estimados no están en el schema vigente (additionalProperties: false): el prompt solo
        # los pide si el orquestador declara schema_veredicto=2, para que la línea no se descarte.
        for nombre in AGENTES_VEREDICTO:
            t = leer_agente(nombre)
            self.assertIn("schema_veredicto=2", t, nombre)
            self.assertIn("tokens_estimados", t, nombre)

    def test_ux_marcado_f4(self):
        self.assertIn("F4", frontmatter(leer_agente("revisor-ux"))["description"])

    def test_triage_incierto_cuenta_como_verdadero(self):
        self.assertRegex(leer_agente("triage-fp"), r"incierto.{0,40}verdadero")

    def test_redactor_no_inventa(self):
        t = leer_agente("redactor-dueno")
        self.assertIn("redaccion-dueno.json", t)
        self.assertIn("200 palabras", t)
        self.assertIn("25 palabras", t)
        ej = [json.loads(b) for b in bloques(t, "json")]
        self.assertTrue(ej, "redactor-dueno: falta ejemplo ```json")
        self.assertEqual(set(ej[0]), {"agente", "resumen", "por_que_importa", "modelo"})

    def test_propuesta_de_schema_aparte(self):
        p = RAIZ / "schemas" / "propuesta-veredicto-v2.md"
        self.assertTrue(p.is_file())
        t = p.read_text(encoding="utf-8")
        for campo in ("confianza", "tokens_estimados", "evidencia", "redaccion"):
            self.assertIn(campo, t)
        self.assertEqual(sorted(x.name for x in (RAIZ / "schemas").glob("*.json")),
                         ["estado.schema.json", "hallazgo.schema.json", "perfil.schema.json", "veredicto.schema.json"])


class TestSkillsF3(unittest.TestCase):
    def test_frontmatter_y_largo(self):
        for nombre in ("auditar", "auditar-perfil", "auditar-informe"):
            texto = leer_skill(nombre)
            fm = frontmatter(texto)
            self.assertIsNotNone(fm, nombre)
            self.assertEqual(fm.get("name"), nombre)
            self.assertGreater(len(fm.get("description", "")), 40)
            self.assertLessEqual(len(texto.splitlines()), 150, nombre)

    def test_auditar_flujo_f3_en_orden(self):
        t = leer_skill("auditar").split("## Procedimiento", 1)[1]
        pasos = ['"$A" doctor', '"$A" stack', "auditar-perfil", '"$A" scan', '"$A" normalize', "corte temprano",
                 '"$A" digest', "tool Agent", '"$A" veredictos', '"$A" report', "redactor-dueno", "medir_tokens"]
        pos = []
        for p in pasos:
            self.assertIn(p, t, p)
            pos.append(t.index(p))
        self.assertEqual(pos, sorted(pos), "el flujo F3 debe aparecer en orden")

    def test_auditar_subagentes_y_reglas(self):
        t = leer_skill("auditar")
        for clave in ("auditor-integral:revisor-autorizacion", "auditor-integral:revisor-arquitectura",
                      "auditor-integral:triage-fp", "auditor-integral:redactor-dueno", "en paralelo",
                      "solo la ruta del digest", "3, 7 y 9", "AskUserQuestion", "no_evaluado", "crudo/",
                      "red no local", "veredictos.jsonl", "schema_veredicto=2"):
            self.assertIn(clave, t, clave)
        fm = frontmatter(t)
        self.assertIn("Agent", fm.get("allowed-tools", ""))

    def test_auditar_modos(self):
        t = leer_skill("auditar")
        for modo in ("rapido", "estandar", "profundo"):
            self.assertIn(modo, t)
        self.assertRegex(t, r"(?i)rápido.{0,200}solo triage")

    def test_perfil_entrevista_y_flujograma(self):
        t = leer_skill("auditar-perfil")
        for clave in ("E0", "E5", "```mermaid", "flujograma", "confirm", "perfil.json", "AskUserQuestion",
                      "no se asume", "no_evaluado", "BORRADOR", "3, 7 y 9"):
            self.assertIn(clave, t, clave)
        for n in range(1, 17):
            self.assertRegex(t, rf"(?m)^\s*{n}\. ", f"pregunta {n}")

    def test_informe_regenera_desde_estado(self):
        t = leer_skill("auditar-informe")
        for clave in ('"$A" report', "estado.json", "crudo/", "resumen-dueno.md", "hoja-de-ruta.md"):
            self.assertIn(clave, t, clave)


if __name__ == "__main__":
    unittest.main()
