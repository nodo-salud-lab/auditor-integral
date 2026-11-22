"""«Cómo verificar» con el comando real según el canal (H-9 / O4 de investigacion/18).

- roadmap.comando da el par CLI / Claude Code con el prefijo del plugin (`/auditor-integral:…`).
- roadmap._verificacion depende de la causa: entrevista → perfil, juicio LLM → auditar (Claude Code),
  fuera del modo → modo superior, herramienta → doctor + corrida nueva; fail → corrida nueva.
- La plantilla de la hoja de ruta trae los dos caminos y el comando de comparar corridas.
- Refuerzo: con el prefijo, «/auditar-doctor» deja de aparecer como subcadena, así que las aserciones de
  test_f3c_fp_critico_informe (assertNotIn "/auditar-doctor") se volverían triviales. Aquí se re-ejecuta esa clase
  exigiendo que el bloque de un posible falso positivo grave no mande a doctor por ningún canal.
"""
import string
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import roadmap  # noqa: E402
import test_f3c_fp_critico_informe as fp_critico  # noqa: E402


class TestComando(unittest.TestCase):
    def test_pares_cli_y_plugin(self):
        a = roadmap.comando("auditar", "rapido")
        self.assertIn('`bin/auditar all "<carpeta del proyecto>" --modo rapido`', a)
        self.assertIn("`/auditor-integral:auditar --modo rapido`", a)
        self.assertIn("/auditor-integral:auditar-doctor", roadmap.comando("doctor"))
        self.assertIn("doctor_tabla.py", roadmap.comando("doctor"))
        self.assertIn("/auditor-integral:auditar-perfil", roadmap.comando("perfil"))
        self.assertIn("--respuestas", roadmap.comando("perfil"))
        self.assertIn("/auditor-integral:auditar-informe", roadmap.comando("informe"))
        self.assertIn("la CLI no lanza los jueces", roadmap.comando("juicio"))

    def test_sin_comandos_sin_prefijo(self):
        for acc in ("auditar", "doctor", "perfil", "informe", "juicio"):
            t = roadmap.comando(acc, "estandar")
            self.assertNotRegex(t, r"`/auditar", acc)


class TestVerificacionPorCausa(unittest.TestCase):
    C = {"id": "X-1"}

    def v(self, estado, motivo=None, modo="estandar"):
        return roadmap._verificacion(self.C, {"estado": estado, "motivo": motivo}, modo)

    def test_entrevista_va_a_perfil(self):
        t = self.v("no_evaluado", "requiere respuesta en la entrevista (perfil.json)")
        self.assertIn("auditar-perfil", t)
        self.assertNotIn("auditar-doctor", t)

    def test_juicio_va_a_auditar_en_claude_code(self):
        t = self.v("no_evaluado", "juicio LLM no ejecutado en F1 (revisor-ux)")
        self.assertIn("/auditor-integral:auditar --modo estandar", t)
        self.assertNotIn("auditar-doctor", t)
        self.assertIn("--modo estandar", self.v("no_evaluado", "juicio LLM no ejecutado", modo="rapido"))

    def test_fuera_del_modo_sube_el_modo(self):
        t = self.v("no_evaluado", "fuera del alcance del modo rapido (N3 > N2)", modo="rapido")
        self.assertIn("--modo estandar", t)
        self.assertNotIn("auditar-doctor", t)

    def test_herramienta_va_a_doctor(self):
        t = self.v("no_evaluado", "trivy: herramienta ausente")
        self.assertTrue(t.startswith("Habilitar lo que falta (trivy: herramienta ausente"))
        self.assertIn("auditar-doctor", t)
        self.assertIn('bin/auditar all "<carpeta del proyecto>"', t)

    def test_fail_y_manual(self):
        self.assertIn("el control X-1 debe quedar en pass", self.v("fail"))
        self.assertIn("auditar-informe", self.v("manual_pendiente"))

    def test_fp_ia_no_cambia(self):
        motivo = (roadmap.MOTIVOS_FP_IA[0] if isinstance(roadmap.MOTIVOS_FP_IA, tuple) else roadmap.MOTIVOS_FP_IA) + " x"
        self.assertTrue(roadmap.es_motivo_fp_ia(motivo))
        t = self.v("no_evaluado", motivo)
        self.assertTrue(t.startswith("Verificación humana"))
        self.assertNotIn("doctor", t)


class TestPlantilla(unittest.TestCase):
    def test_hoja_de_ruta_dos_caminos(self):
        tmpl = (RAIZ / "plantillas" / "hoja-de-ruta.md.tmpl").read_text(encoding="utf-8")
        ultima = tmpl.strip().splitlines()[-1]
        self.assertIn('`bin/auditar all "<carpeta del proyecto>" --modo $modo`', ultima)
        self.assertIn("`/auditor-integral:auditar --modo $modo`", ultima)
        self.assertIn("comparar_corridas.py", ultima)
        # se rellena con substitute estricto: no puede quedar ningún marcador sin valor
        claves = {m.group("named") or m.group("braced") for m in string.Template.pattern.finditer(tmpl)
                  if m.group("named") or m.group("braced")}
        # R10: la línea de nivel/hito pasó a la cabecera de 2 líneas de la portada (variante hoja)
        self.assertEqual(claves, {"proyecto", "cabecera_portada", "que_hacer_ahora", "grupos", "descartes_humanos",
                                  "modo"})


class TestFpGraveNoMandaADoctor(fp_critico.TestOtrasSuperficies):
    """Re-ejecuta las superficies del FP crítico con una aserción más estricta (sin depender de la barra)."""

    def assert_verificacion_humana(self, bloque):
        super().assert_verificacion_humana(bloque)
        self.assertNotIn("auditar-doctor", bloque)
        self.assertNotIn("doctor_tabla", bloque)


if __name__ == "__main__":
    unittest.main()
