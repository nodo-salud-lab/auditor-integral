"""Tests de los JSON Schema (§3.5/§3.6) y del validador mínimo stdlib."""
import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))

import validar_schema as vs  # noqa: E402

SCHEMAS = RAIZ / "schemas"
EJEMPLOS = SCHEMAS / "ejemplos"


def cargar(ruta):
    return json.loads(Path(ruta).read_text(encoding="utf-8"))


class TestValidadorMinimo(unittest.TestCase):
    """El validador soporta el subconjunto usado por los schemas."""

    def test_type_basico(self):
        self.assertEqual(vs.validar("a", {"type": "string"}), [])
        self.assertTrue(vs.validar(1, {"type": "string"}))
        self.assertEqual(vs.validar(None, {"type": ["string", "null"]}), [])
        # bool no es integer en JSON Schema
        self.assertTrue(vs.validar(True, {"type": "integer"}))
        self.assertEqual(vs.validar(3, {"type": "number"}), [])

    def test_required_y_properties(self):
        s = {"type": "object", "required": ["a"], "properties": {"a": {"type": "integer"}}}
        self.assertEqual(vs.validar({"a": 1}, s), [])
        self.assertTrue(vs.validar({}, s))
        self.assertTrue(vs.validar({"a": "x"}, s))

    def test_additional_properties(self):
        s = {"type": "object", "properties": {"a": {}}, "additionalProperties": False}
        self.assertEqual(vs.validar({"a": 1}, s), [])
        self.assertTrue(vs.validar({"a": 1, "b": 2}, s))
        s2 = {"type": "object", "additionalProperties": {"type": "boolean"}}
        self.assertEqual(vs.validar({"x": True}, s2), [])
        self.assertTrue(vs.validar({"x": 1}, s2))

    def test_enum_items_maxlength_pattern(self):
        self.assertTrue(vs.validar("z", {"enum": ["a", "b"]}))
        self.assertEqual(vs.validar([1, 2], {"type": "array", "items": {"type": "integer"}}), [])
        self.assertTrue(vs.validar([1, "x"], {"type": "array", "items": {"type": "integer"}}))
        self.assertTrue(vs.validar("abcd", {"maxLength": 3}))
        self.assertEqual(vs.validar("H-abc123", {"pattern": "^H-[0-9a-f]{6,}$"}), [])
        self.assertTrue(vs.validar("X-1", {"pattern": "^H-"}))

    def test_ref_a_defs(self):
        s = {"$defs": {"n": {"type": "integer"}}, "type": "array", "items": {"$ref": "#/$defs/n"}}
        self.assertEqual(vs.validar([1], s), [])
        self.assertTrue(vs.validar(["x"], s))

    def test_errores_indican_ruta(self):
        s = {"type": "object", "properties": {"a": {"type": "object", "properties": {"b": {"type": "string"}}}}}
        errores = vs.validar({"a": {"b": 1}}, s)
        self.assertEqual(len(errores), 1)
        self.assertIn("/a/b", errores[0])


class TestSchemasBienFormados(unittest.TestCase):
    def test_cuatro_schemas_draft_2020_12(self):
        for nombre in ("hallazgo", "estado", "perfil", "veredicto"):
            s = cargar(SCHEMAS / f"{nombre}.schema.json")
            self.assertEqual(s["$schema"], "https://json-schema.org/draft/2020-12/schema", nombre)
            self.assertIn("$id", s)
            # solo palabras clave del subconjunto soportado
            self.assertEqual(vs.palabras_no_soportadas(s), set(), nombre)


class TestEjemplosValidos(unittest.TestCase):
    def test_todos_los_ejemplos_validan(self):
        ejemplos = sorted(EJEMPLOS.glob("*.json")) + sorted(EJEMPLOS.glob("*.jsonl"))
        self.assertGreaterEqual(len(ejemplos), 4)
        for ej in ejemplos:
            base = ej.name.split(".")[0]
            if base == "perfil_tecnico":
                schema = vs.subschema(cargar(SCHEMAS / "perfil.schema.json"), "perfil_tecnico")
            else:
                schema = cargar(SCHEMAS / f"{base.split('_')[0]}.schema.json")
            for i, inst in enumerate(vs.leer_instancias(ej)):
                self.assertEqual(vs.validar(inst, schema), [], f"{ej.name}#{i}")


class TestInvalidosRechazados(unittest.TestCase):
    def setUp(self):
        self.s = cargar(SCHEMAS / "hallazgo.schema.json")
        self.base = cargar(EJEMPLOS / "hallazgo.json")
        self.assertEqual(vs.validar(self.base, self.s), [])

    def mutar(self, **cambios):
        h = copy.deepcopy(self.base)
        for k, v in cambios.items():
            if v is vs.FALTA:
                h.pop(k)
            else:
                h[k] = v
        return h

    def test_hallazgo_invalidos(self):
        casos = {
            "severidad fuera de enum": self.mutar(severidad="grave"),
            "dominio fuera de enum": self.mutar(dominio="XYZ"),
            "gate N6": self.mutar(gate="N6"),
            "falta control": self.mutar(control=vs.FALTA),
            "evidencia > 300": self.mutar(evidencia="x" * 301),
            "propiedad extra": self.mutar(inventado=1),
            "fingerprint no sha256": self.mutar(fingerprint="abc"),
            "triage veredicto malo": self.mutar(triage={"veredicto": "quizas", "razon": "r", "modelo": "m"}),
            "fuente vacía de herramienta": self.mutar(fuente=[{"version": "1"}]),
            "estado_hallazgo malo": self.mutar(estado_hallazgo="cerrado"),
        }
        for nombre, h in casos.items():
            self.assertTrue(vs.validar(h, self.s), f"debió rechazar: {nombre}")

    def test_estado_invalido(self):
        s = cargar(SCHEMAS / "estado.schema.json")
        e = cargar(EJEMPLOS / "estado.json")
        e["controles"][0]["estado"] = "ok"
        self.assertTrue(vs.validar(e, s))

    def test_veredicto_invalido(self):
        s = cargar(SCHEMAS / "veredicto.schema.json")
        v = vs.leer_instancias(EJEMPLOS / "veredicto.jsonl")[0]
        v["veredicto"] = "tal_vez"
        self.assertTrue(vs.validar(v, s))
        v2 = vs.leer_instancias(EJEMPLOS / "veredicto.jsonl")[0]
        v2.pop("razon")
        self.assertTrue(vs.validar(v2, s))

    def test_perfil_invalido(self):
        s = cargar(SCHEMAS / "perfil.schema.json")
        p = cargar(EJEMPLOS / "perfil.json")
        p["banderas"]["baas"] = "mongodb-atlas"
        self.assertTrue(vs.validar(p, s))
        p = cargar(EJEMPLOS / "perfil.json")
        p["banderas"]["salud"] = "si"
        self.assertTrue(vs.validar(p, s))


class TestCLI(unittest.TestCase):
    def test_cli_ok_y_falla(self):
        script = RAIZ / "scripts" / "validar_schema.py"
        ok = subprocess.run([sys.executable, str(script), str(SCHEMAS / "hallazgo.schema.json"),
                             str(EJEMPLOS / "hallazgo.json")], capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        malo = subprocess.run([sys.executable, str(script), str(SCHEMAS / "estado.schema.json"),
                               str(EJEMPLOS / "hallazgo.json")], capture_output=True, text=True)
        self.assertEqual(malo.returncode, 1)
        self.assertTrue(malo.stdout or malo.stderr)

    def test_cli_def(self):
        script = RAIZ / "scripts" / "validar_schema.py"
        r = subprocess.run([sys.executable, str(script), "--def", "perfil_tecnico",
                            str(SCHEMAS / "perfil.schema.json"), str(EJEMPLOS / "perfil_tecnico.json")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
