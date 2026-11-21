"""F3-A: scripts/perfil.py + plantillas/entrevista_e0.md y entrevista_e5.md (PLAN_MAESTRO §3.6).

perfil_tecnico.json + respuestas.json del creador → perfil.json (valida contra schemas/perfil.schema.json).
Pregunta sin respuesta → sus controles quedan fuera de pass (no_evaluado); no se asume la respuesta. Se registran
la fecha, las declaraciones (p. ej. datos_personales = false) y las rutas sintéticas declaradas.
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
import catalogo  # noqa: E402
import estado as estado_mod  # noqa: E402
import perfil  # noqa: E402
import utiles  # noqa: E402
import validar_schema  # noqa: E402

SCHEMA = json.loads((RAIZ / "schemas" / "perfil.schema.json").read_text(encoding="utf-8"))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)
        self.corrida = ap.preparar_corrida(self.tmp, crudo=None)

    def tearDown(self):
        ap.limpiar(self.tmp)

    def respuestas(self, datos):
        ruta = self.corrida / "respuestas.json"
        ruta.write_text(json.dumps(datos), encoding="utf-8")
        return ruta

    def generar(self, datos=None):
        if datos is not None:
            self.respuestas(datos)
        perfil.generar(self.corrida)
        return json.loads((self.corrida / "perfil.json").read_text(encoding="utf-8"))


class TestPreguntas(unittest.TestCase):
    def test_16_preguntas_con_controles_del_catalogo(self):
        self.assertEqual(sorted(perfil.PREGUNTAS), list(range(1, 17)))
        ids = {c["id"] for c in catalogo.cargar_catalogo()}
        for n, p in perfil.PREGUNTAS.items():
            for c in p["controles"]:
                self.assertIn(c, ids, f"pregunta {n}")
            for b in p["banderas"]:
                self.assertIn(b, utiles.BANDERAS_ARCHIVOS + utiles.BANDERAS_ENTREVISTA, f"pregunta {n}")

    def test_modos(self):
        self.assertEqual(perfil.preguntas_del_modo("rapido"), [3, 7, 9])
        self.assertEqual(perfil.preguntas_del_modo("estandar"), list(range(1, 11)))
        self.assertEqual(perfil.preguntas_del_modo("profundo"), list(range(1, 17)))


class TestGenerar(Base):
    def test_sin_respuestas_todo_pendiente_y_valido(self):
        p = self.generar()
        self.assertEqual(validar_schema.validar(p, SCHEMA), [])
        for b in utiles.BANDERAS_ENTREVISTA:
            self.assertIsNone(p["banderas"][b], b)
            self.assertEqual(p["origen_banderas"][b], "sin_dato")
        self.assertEqual(p["banderas"]["baas"], "supabase")
        self.assertEqual(p["origen_banderas"]["baas"], "archivos")
        self.assertEqual(sorted(map(int, p["pendientes_entrevista"])), list(range(1, 17)))
        self.assertIn("DAT-BACKUP", p["pendientes_entrevista"]["11"]["controles"])

    def test_respuestas_y_declaraciones(self):
        p = self.generar({"fecha": "2026-11-10", "modo": "estandar",
                          "respuestas": {"1": "Agenda de kinesiología.", "3": "Sí, datos de salud de pacientes.",
                                         "7": "Vercel, sin staging", "9": "No"},
                          "declaraciones": {"datos_personales": True, "salud": True, "menores": False, "ue": False,
                                            "datos_reales_cargados": False, "pagos": False}})
        self.assertEqual(validar_schema.validar(p, SCHEMA), [])
        self.assertEqual(p["fecha"], "2026-11-10")
        self.assertIs(p["banderas"]["salud"], True)
        self.assertIs(p["banderas"]["datos_reales_cargados"], False)
        self.assertEqual(p["origen_banderas"]["salud"], "entrevista")
        self.assertEqual(p["declaraciones"]["salud"], {"valor": True, "fecha": "2026-11-10", "fuente": "entrevista",
                                                      "pregunta": 3})
        self.assertNotIn("3", p["pendientes_entrevista"])
        self.assertNotIn("7", p["pendientes_entrevista"])
        self.assertIn("2", p["pendientes_entrevista"])
        self.assertEqual(p["entrevista"]["respuestas"]["2"], None)
        self.assertEqual(p["entrevista"]["modo"], "estandar")

    def test_archivos_y_entrevista_se_combinan_sin_bajar(self):
        # perfil_tecnico dice pagos = true: si el creador declara false, gana la evidencia de archivos
        p = self.generar({"respuestas": {"4": "no"}, "declaraciones": {"pagos": False, "llm": True}})
        self.assertIs(p["banderas"]["pagos"], True)
        self.assertEqual(p["origen_banderas"]["pagos"], "ambos")
        self.assertIn("pagos", p["discrepancias"][0])
        self.assertIs(p["banderas"]["llm"], True)

    def test_respuesta_sin_declaracion_no_asume(self):
        p = self.generar({"respuestas": {"3": "creo que no"}})
        self.assertIsNone(p["banderas"]["datos_personales"])
        self.assertIn("3", p["pendientes_entrevista"])
        self.assertIn("datos_personales", p["pendientes_entrevista"]["3"]["banderas"])

    def test_declaracion_sin_datos_personales_registrada_con_fecha(self):
        p = self.generar({"fecha": "2026-11-12", "respuestas": {"3": "No guarda datos de personas."},
                          "declaraciones": {"datos_personales": False, "salud": False, "menores": False, "ue": False}})
        decl = estado_mod.declaracion_sin_datos(utiles.cargar_perfil(self.corrida), self.corrida, p)
        self.assertEqual(decl["fecha"], "2026-11-12")

    def test_rutas_sinteticas(self):
        p = self.generar({"rutas_sinteticas": ["pruebas/sinteticos", "../fuera", "/abs", "ok/datos"]})
        self.assertEqual(p["sinteticos"]["rutas"], ["ok/datos", "pruebas/sinteticos"])
        self.assertEqual(sorted(p["sinteticos"]["descartadas"]), ["../fuera", "/abs"])
        self.assertEqual(p["sinteticos"]["fuente"], "creador (entrevista)")

    def test_respuestas_invalidas_no_se_asumen(self):
        p = self.generar({"respuestas": {"3": 42, "99": "x"}, "declaraciones": {"salud": "sí", "usuarios_3m": -5}})
        self.assertEqual(validar_schema.validar(p, SCHEMA), [])
        self.assertIsNone(p["banderas"]["salud"])
        self.assertIsNone(p["banderas"]["usuarios_3m"])
        self.assertIn("3", p["pendientes_entrevista"])
        self.assertTrue(p["advertencias"])

    def test_respuestas_enmascaradas(self):
        p = self.generar({"respuestas": {"1": "contacto ana.perez@correo.cl, rut 12.345.678-5"}})
        texto = json.dumps(p, ensure_ascii=False)
        self.assertNotIn("ana.perez@correo.cl", texto)
        self.assertNotIn("12.345.678-5", texto)

    def test_pendiente_deja_control_fuera_de_pass(self):
        p = self.generar()
        controles = [{"control": "INF-PLATAFORMA", "estado": "pass", "motivo": None, "herramienta": "x"}]
        import veredictos
        veredictos.ajustar_pendientes(controles, p)
        self.assertEqual(controles[0]["estado"], "no_evaluado")
        self.assertIn("pregunta 7", controles[0]["motivo"])

    def test_cli(self):
        self.respuestas({"respuestas": {"9": "sí"}, "declaraciones": {"datos_reales_cargados": True}})
        self.assertEqual(perfil.main(["--corrida", str(self.corrida)]), 0)
        self.assertTrue((self.corrida / "perfil.json").is_file())
        self.assertEqual(perfil.main(["--corrida", str(self.tmp / "no-existe")]), 2)


class TestPlantillas(unittest.TestCase):
    def test_e0_y_e5(self):
        e0 = (RAIZ / "plantillas" / "entrevista_e0.md").read_text(encoding="utf-8")
        e5 = (RAIZ / "plantillas" / "entrevista_e5.md").read_text(encoding="utf-8")
        for n in range(1, 11):
            self.assertRegex(e0, rf"(?m)^{n}\. ", f"E0 pregunta {n}")
        for n in range(11, 17):
            self.assertRegex(e5, rf"(?m)^{n}\. ", f"E5 pregunta {n}")
        for t in (e0, e5):
            self.assertIn("respuestas.json", t)
            self.assertIn("no se asume", t)
            self.assertIn("no_evaluado", t)
        self.assertIn("3, 7 y 9", e0)
        self.assertIn("rutas_sinteticas", e0)
        for n, p in perfil.PREGUNTAS.items():
            texto = e0 if n <= 10 else e5
            for c in p["controles"]:
                self.assertIn(c, texto, f"pregunta {n}: {c}")
            for b in p["banderas"]:
                self.assertIn(b, texto, f"pregunta {n}: {b}")
        bloques = re.findall(r"```json\n(.*?)```", e0, re.S)
        self.assertTrue(bloques)
        json.loads(bloques[0])


if __name__ == "__main__":
    unittest.main()
