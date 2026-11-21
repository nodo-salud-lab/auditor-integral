"""A3 (investigacion/18): las respuestas de la entrevista del perfil no se pierden.

Antes, el skill auditar-perfil mandaba escribir perfil.json a mano y luego correr `bin/auditar perfil`, pero
perfil.py regenera perfil.json desde respuestas.json y, sin él, usaba {}: las respuestas se pisaban con un perfil
vacío. Arreglo mínimo: (1) el skill escribe respuestas.json (lo que perfil.py lee) y nunca perfil.json; (2) perfil.py,
sin respuestas.json ni --respuestas, NO sobrescribe un perfil.json que ya trae datos de la entrevista (código 1,
archivo intacto).
"""
import json
import shutil
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import perfil  # noqa: E402

SKILL = RAIZ / "skills" / "auditar-perfil" / "SKILL.md"


class TestPerfilNoPisaDatos(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.corrida = ap.preparar_corrida(self.tmp, crudo=None)

    def escribir(self, nombre, datos):
        (self.corrida / nombre).write_text(json.dumps(datos), encoding="utf-8")

    def leer(self, nombre="perfil.json"):
        return json.loads((self.corrida / nombre).read_text(encoding="utf-8"))

    def test_respuestas_json_llega_a_perfil_json(self):
        self.escribir("respuestas.json", {"fecha": "2026-11-18", "modo": "estandar",
                                          "respuestas": {"1": "Agenda de kinesiología para pacientes"},
                                          "declaraciones": {"datos_personales": True, "salud": True}})
        self.assertEqual(perfil.main(["--corrida", str(self.corrida)]), 0)
        p = self.leer()
        self.assertTrue(p["banderas"]["salud"])
        self.assertEqual(p["declaraciones"]["datos_personales"]["valor"], True)
        self.assertEqual(p["entrevista"]["respuestas"]["1"], "Agenda de kinesiología para pacientes")

    def test_perfil_escrito_a_mano_no_se_pisa_sin_respuestas(self):
        a_mano = {"version_esquema": "1", "banderas": {"salud": True, "datos_personales": True},
                  "entrevista": {"modo": "estandar", "respuestas": {"3": "sí, datos de salud"}}}
        self.escribir("perfil.json", a_mano)
        antes = (self.corrida / "perfil.json").read_bytes()
        self.assertEqual(perfil.main(["--corrida", str(self.corrida)]), 1)
        self.assertEqual((self.corrida / "perfil.json").read_bytes(), antes, "perfil.json debe quedar intacto")
        with self.assertRaises(perfil.PerfilConDatos):
            perfil.generar(self.corrida)

    def test_perfil_generado_con_datos_tampoco_se_pisa_si_se_borra_respuestas(self):
        self.escribir("respuestas.json", {"declaraciones": {"datos_reales_cargados": False}})
        self.assertEqual(perfil.main(["--corrida", str(self.corrida)]), 0)
        (self.corrida / "respuestas.json").unlink()
        antes = (self.corrida / "perfil.json").read_bytes()
        self.assertEqual(perfil.main(["--corrida", str(self.corrida)]), 1)
        self.assertEqual((self.corrida / "perfil.json").read_bytes(), antes)

    def test_perfil_vacio_si_se_regenera(self):
        """Un perfil.json sin datos de entrevista (p. ej. corrida no interactiva) sí se puede regenerar."""
        self.assertEqual(perfil.main(["--corrida", str(self.corrida)]), 0)
        self.assertEqual(perfil.main(["--corrida", str(self.corrida)]), 0)
        self.assertFalse(perfil.perfil_con_datos(self.leer()))

    def test_respuestas_explicitas_regeneran(self):
        self.escribir("perfil.json", {"version_esquema": "1", "banderas": {"salud": True},
                                      "declaraciones": {"salud": {"valor": True}}})
        otra = self.tmp / "resp.json"
        otra.write_text(json.dumps({"declaraciones": {"salud": False}}), encoding="utf-8")
        self.assertEqual(perfil.main(["--corrida", str(self.corrida), "--respuestas", str(otra)]), 0)
        self.assertIs(self.leer()["banderas"]["salud"], False)

    def _con_datos(self):
        self.escribir("respuestas.json", {"fecha": "2026-11-19", "respuestas": {"1": "Agenda"},
                                          "declaraciones": {"datos_personales": True, "salud": True}})
        self.assertEqual(perfil.main(["--corrida", str(self.corrida)]), 0)
        return (self.corrida / "perfil.json").read_bytes()

    def test_respuestas_con_coma_final_no_pisa_el_perfil(self):
        """Revisión adversarial 2026-11-20: JSON inválido → rc 1 y perfil.json idéntico byte a byte."""
        antes = self._con_datos()
        texto = json.dumps({"fecha": "2026-11-19", "respuestas": {"1": "Agenda"},
                            "declaraciones": {"datos_personales": True, "salud": True}})
        (self.corrida / "respuestas.json").write_text(texto[:-1] + ",}", encoding="utf-8")
        self.assertEqual(perfil.main(["--corrida", str(self.corrida)]), 1)
        self.assertEqual((self.corrida / "perfil.json").read_bytes(), antes)
        with self.assertRaisesRegex(ValueError, "JSON inválido"):
            perfil.generar(self.corrida)

    def test_respuestas_que_no_son_objeto_no_pisan_el_perfil(self):
        antes = self._con_datos()
        self.escribir("respuestas.json", ["no es objeto"])
        self.assertEqual(perfil.main(["--corrida", str(self.corrida)]), 1)
        self.assertEqual((self.corrida / "perfil.json").read_bytes(), antes)

    def test_respuestas_invalidas_explicitas_tambien_fallan(self):
        otra = self.tmp / "resp.json"
        otra.write_text("{", encoding="utf-8")
        self.assertEqual(perfil.main(["--corrida", str(self.corrida), "--respuestas", str(otra)]), 1)
        self.assertFalse((self.corrida / "perfil.json").exists())

    def test_claves_desconocidas_de_primer_nivel_se_advierten(self):
        self.escribir("respuestas.json", {"fecha": "2026-11-19", "respuesta": {"1": "texto"},
                                          "declaracion": {"salud": True}})
        self.assertEqual(perfil.main(["--corrida", str(self.corrida)]), 0)
        adv = " ".join(self.leer()["advertencias"])
        self.assertIn("respuesta", adv)
        self.assertIn("declaracion", adv)
        self.assertIsNone(self.leer()["banderas"]["salud"])     # fail-closed: no se asume

    def test_perfil_con_datos_detecta_cada_fuente(self):
        self.assertFalse(perfil.perfil_con_datos(None))
        self.assertFalse(perfil.perfil_con_datos({"banderas": {"salud": None}, "entrevista": {"respuestas": {"1": None}}}))
        for p in ({"declaraciones": {"salud": {"valor": True}}},
                  {"entrevista": {"respuestas": {"2": "login, agenda"}}},
                  {"flujograma": {"archivo": "flujograma.mmd", "estado": "borrador"}},
                  {"sinteticos": {"rutas": ["pruebas/sint"]}},
                  {"banderas": {"usuarios_3m": 0}}):
            with self.subTest(p=p):
                self.assertTrue(perfil.perfil_con_datos(p))


class TestSkillEscribeRespuestas(unittest.TestCase):
    def setUp(self):
        self.t = SKILL.read_text(encoding="utf-8")

    def test_skill_escribe_respuestas_json(self):
        self.assertIn('"$C/respuestas.json"', self.t)
        self.assertIn("## Escribir respuestas.json y generar perfil.json", self.t)
        self.assertIn('bin/auditar" perfil "$P" --salida "$C"', self.t)

    def test_skill_no_manda_escribir_perfil_json_a_mano(self):
        self.assertNotIn('Escribe `"$C/perfil.json"`', self.t)
        self.assertIn("No escribas ni edites `perfil.json` a mano", self.t)

    def test_formato_del_skill_coincide_con_perfil_py(self):
        """Las claves que el skill documenta son las que perfil.py lee."""
        for clave in ("respuestas", "declaraciones", "rutas_sinteticas", "flujograma", "fecha", "modo"):
            self.assertIn(f'"{clave}"', self.t, clave)
            self.assertIn(f'"{clave}"', Path(perfil.__file__).read_text(encoding="utf-8"), clave)

    def test_orquestador_apunta_a_respuestas(self):
        t = (RAIZ / "skills" / "auditar" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn('"$C/respuestas.json"', t)


if __name__ == "__main__":
    unittest.main()
