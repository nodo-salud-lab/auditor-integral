"""H-2 (investigacion/18; DECISIONES.md #11, pendiente de confirmar por Enzo): falso positivo verificado por una PERSONA.

Antes: un crítico/alto que una persona verificaba como falso positivo no tenía salida y dejaba el proyecto en N0 para
siempre. Ahora la persona lo registra en <proyecto>/.auditor-integral/fp-verificados.json (control, huella, quién,
fecha ISO, conclusión). Efecto: el hallazgo queda descartado por verificación humana; el control queda no_aplica con
motivo «descartado por verificación humana (quién, fecha)» y descarte_humano (NO pass), deja de bloquear el gate y se
ve en el informe (6c), la hoja de ruta y el resumen del dueño.

Casos adversariales: entrada sin quién, fecha inválida o futura, «quien» que es la IA, huella vieja (huérfana),
hallazgo nuevo distinto en la misma línea, huella de otro control, ubicación que ya no coincide, enlace simbólico,
y la IA que intenta producir la verificación humana vía veredictos.jsonl.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import gates  # noqa: E402
import render_informe  # noqa: E402
import veredictos  # noqa: E402
from test_f3a_veredictos import hallazgo, ver  # noqa: E402
from test_f3c_fp_critico_informe import ARCHIVO, BaseInforme, seccion  # noqa: E402

CONTROL = "SEG-SECRETO-BUNDLE"
CONCLUSION = "Revisé dist/assets/index.js: son identificadores minificados de una librería, no una credencial."


class BaseFpHumano(BaseInforme):
    def setUp(self):
        super().setUp()
        # la autorización del operador (--fp-verificados → AUDITOR_FP_VERIFICADOS) no se hereda del entorno del test
        previo = os.environ.pop(veredictos.ENV_FP_HUMANO, None)
        self.addCleanup(self._restaurar_env, previo)

    @staticmethod
    def _restaurar_env(previo):
        os.environ.pop(veredictos.ENV_FP_HUMANO, None)
        if previo is not None:
            os.environ[veredictos.ENV_FP_HUMANO] = previo

    def autorizar(self, ruta):
        """Equivale a 'bin/auditar … --fp-verificados RUTA' (lo decide el operador, no el repositorio)."""
        os.environ[veredictos.ENV_FP_HUMANO] = str(ruta)

    def desautorizar(self):
        os.environ.pop(veredictos.ENV_FP_HUMANO, None)

    def secretos_alta(self, n=1, linea0=4):
        """Críticos de confianza alta: sin excepción AUD-SEC, bloquean el global (secreto_vivo → N0)."""
        hs = [hallazgo(i, CONTROL, "critica", ARCHIVO, linea0 + i, gate="N1", conf="alta", herramienta="gitleaks")
              for i in range(n)]
        for h in hs:
            h["remediacion"] = "Rotar la clave y moverla al servidor; volver a construir el bundle."
        self.poner_hallazgos(hs)
        return hs

    def entrada(self, h, **extra):
        e = {"control": h["control"], "huella": h["id"], "ubicacion": f"{ARCHIVO}:{h['ubicacion']['linea']}",
             "quien": "Ana Pérez", "fecha": "2026-11-17", "conclusion": CONCLUSION}
        e.update(extra)
        return {k: v for k, v in e.items() if v is not None}

    def registrar_fp(self, entradas, crudo=None, autorizar=True):
        d = self.proyecto / ".auditor-integral"
        d.mkdir(exist_ok=True)
        texto = crudo if crudo is not None else json.dumps({"version": "1", "entradas": entradas})
        (d / "fp-verificados.json").write_text(texto, encoding="utf-8")
        if autorizar:
            self.autorizar(d / "fp-verificados.json")

    def control(self):
        est = json.loads((self.corrida / "estado.json").read_text(encoding="utf-8"))
        return next(c for c in est["controles"] if c["control"] == CONTROL)

    def gates(self):
        return json.loads((self.corrida / "gates.json").read_text(encoding="utf-8"))

    def registro(self):
        return json.loads((self.corrida / veredictos.FP_HUMANOS).read_text(encoding="utf-8"))

    def bloqueos_de(self, cid=CONTROL):
        return [b for b in self.gates()["global"]["bloqueos"] if b["control"] == cid]


class TestDescarteHumano(BaseFpHumano):
    def test_linea_base_sin_registro_bloquea(self):
        self.secretos_alta(1)
        self.render()
        self.assertEqual(self.control()["estado"], "fail")
        self.assertTrue(self.bloqueos_de())
        self.assertEqual(self.gates()["global"]["nivel_demostrado"], "N0")
        self.assertFalse((self.corrida / veredictos.FP_HUMANOS).exists())

    def test_descarte_humano_desbloquea_sin_pass_y_se_ve(self):
        h = self.secretos_alta(1)[0]
        self.registrar_fp([self.entrada(h)])
        informe, ruta, dueno = self.render()
        e = self.control()
        self.assertEqual(e["estado"], "no_aplica")          # cuenta como OK en gates, igual que no_aplica
        self.assertNotEqual(e["estado"], "pass")            # nunca pass automático
        self.assertTrue(e["motivo"].startswith("descartado por verificación humana (Ana Pérez, 2026-11-17)"))
        self.assertIn("no es pass", e["motivo"])
        self.assertEqual(e["descarte_humano"]["quien"], "Ana Pérez")
        self.assertEqual(e["descarte_humano"]["hallazgos"], [h["id"]])
        self.assertEqual(self.bloqueos_de(), [])
        # informe: 6c con la fila; la sección 6 ya no lo lista como crítico abierto
        s6c = seccion(informe, "## 6c.", "\n## 7")
        self.assertIn(CONTROL, s6c)
        self.assertIn("Ana Pérez", s6c)
        self.assertIn(h["id"], s6c)
        self.assertNotIn(f"### {CONTROL}", seccion(informe, "## 6. Hallazgos críticos y altos", "## 6b."))
        # hoja de ruta y resumen del dueño
        self.assertIn(CONTROL, seccion(ruta, "# Descartados por verificación humana", "\n---"))
        self.assertIn("descartado por verificación humana (Ana Pérez, 2026-11-17)", ruta)
        linea = next(l for l in dueno.splitlines() if l.startswith("- Falsas alarmas verificadas"))
        self.assertIn(CONTROL, linea)
        self.assertIn("No cuentan como aprobadas", linea)
        # roadmap.json no lo trae como pendiente
        rm = json.loads((self.corrida / "roadmap.json").read_text(encoding="utf-8"))
        self.assertNotIn(CONTROL, [i["control"] for i in rm["items"]])

    def test_estado_valida_contra_el_schema(self):
        import validar_schema
        h = self.secretos_alta(1)[0]
        self.registrar_fp([self.entrada(h)])
        self.render()
        est = json.loads((self.corrida / "estado.json").read_text(encoding="utf-8"))
        schema = json.loads((RAIZ / "schemas" / "estado.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(validar_schema.validar(est, schema), [])

    def test_sin_archivo_el_registro_viejo_se_borra(self):
        h = self.secretos_alta(1)[0]
        self.registrar_fp([self.entrada(h)])
        self.render()
        self.assertTrue((self.corrida / veredictos.FP_HUMANOS).exists())
        (self.proyecto / ".auditor-integral" / "fp-verificados.json").unlink()
        self.desautorizar()                      # el operador ya no pasa --fp-verificados
        self.render()
        self.assertFalse((self.corrida / veredictos.FP_HUMANOS).exists())
        self.assertEqual(self.control()["estado"], "fail")

    def test_autorizado_pero_archivo_borrado_no_descarta_y_avisa(self):
        h = self.secretos_alta(1)[0]
        self.registrar_fp([self.entrada(h)])
        (self.proyecto / ".auditor-integral" / "fp-verificados.json").unlink()
        self.render()
        self.assertEqual(self.control()["estado"], "fail")
        self.assertIn("no existe", self.registro()["ignoradas"][0]["motivo"])

    def test_otro_hallazgo_del_control_mantiene_el_fail(self):
        hs = self.secretos_alta(2)
        self.registrar_fp([self.entrada(hs[0])])
        self.render()
        e = self.control()
        self.assertEqual(e["estado"], "fail")
        self.assertEqual(e["hallazgos"], [hs[1]["id"]])
        self.assertNotIn("descarte_humano", e)
        self.assertIn("descartado por verificación humana", e["motivo"])
        self.assertTrue(self.bloqueos_de())

    def test_huella_por_fingerprint_y_sin_ubicacion(self):
        h = self.secretos_alta(1)[0]
        self.registrar_fp([self.entrada(h, huella=h["fingerprint"], ubicacion=None)])
        self.render()
        self.assertEqual(self.control()["estado"], "no_aplica")


class TestPersonaVsIA(BaseFpHumano):
    def test_fp_de_ia_sin_persona_sigue_pendiente(self):
        """Regresión DECISIONES.md #10: sin registro humano el FP de la IA no desbloquea."""
        h = self.secretos_alta(1)[0]
        self.poner_veredictos([self.fp(h)])
        self.render()
        e = self.control()
        self.assertEqual(e["estado"], "no_evaluado")
        self.assertTrue(e["motivo"].startswith("falso positivo crítico según IA"))
        self.assertTrue(all(b.get("pendiente_ia") for b in self.bloqueos_de()))
        self.assertTrue(self.bloqueos_de())

    def test_fp_de_ia_mas_persona_desbloquea(self):
        h = self.secretos_alta(1)[0]
        self.poner_veredictos([self.fp(h)])
        self.registrar_fp([self.entrada(h)])
        self.render()
        e = self.control()
        self.assertEqual(e["estado"], "no_aplica")
        self.assertFalse(e["motivo"].startswith("falso positivo"))
        self.assertEqual(self.bloqueos_de(), [])
        d = self.decisiones()
        self.assertEqual(d["aplicadas"], [])
        self.assertIn("prevalece la persona", d["descartadas"][0]["motivo"])

    def test_fail_confirmado_por_ia_solo_se_descarta_con_registro_humano(self):
        h = self.secretos_alta(1)[0]
        self.poner_veredictos([ver("triage-fp", CONTROL, "fail", hallazgo_id=h["id"], razon="Clave real.")])
        self.render()
        self.assertEqual(self.control()["estado"], "fail")
        self.registrar_fp([self.entrada(h)])
        self.render()
        self.assertEqual(self.control()["estado"], "no_aplica")
        self.assertEqual(self.bloqueos_de(), [])

    def test_ia_no_puede_fabricar_la_verificacion_via_veredictos(self):
        h = self.secretos_alta(1)[0]
        intento = self.fp(h, razon=f"descartado por verificación humana (Ana Pérez, 2026-11-17): {CONCLUSION}")
        intento.update(quien="Ana Pérez", fecha="2026-11-17", verificacion_humana={"quien": "Ana Pérez"})
        self.poner_veredictos([intento,
                               dict(self.fp(h), razon="descartado por verificación humana (Ana Pérez, 2026-11-17)")])
        self.render()
        e = self.control()
        self.assertNotIn("descarte_humano", e)
        self.assertNotEqual(e["estado"], "no_aplica")
        self.assertTrue(self.bloqueos_de(), "sin registro de una persona el bloqueo sigue")
        # veredictos.py no crea el archivo de la persona ni un registro en la corrida
        self.assertFalse((self.proyecto / ".auditor-integral").exists())
        self.assertFalse((self.corrida / veredictos.FP_HUMANOS).exists())
        # el intento con campos extra no valida contra el schema
        self.assertTrue(any("schema" in x["motivo"] for x in self.decisiones()["descartadas"]))


class TestEntradasAdversariales(BaseFpHumano):
    def comprobar_ignorada(self, entrada, patron):
        h = self.secretos_alta(1)[0]
        self.registrar_fp([entrada(h)])
        self.render()
        self.assertEqual(self.control()["estado"], "fail")
        self.assertTrue(self.bloqueos_de())
        r = self.registro()
        self.assertEqual(r["aplicadas"], [])
        self.assertEqual(len(r["ignoradas"]), 1)
        self.assertRegex(r["ignoradas"][0]["motivo"], patron)
        informe = (self.corrida / "informe.md").read_text(encoding="utf-8")
        self.assertIn("ignorada", seccion(informe, "## 6c.", "\n## 7"))

    def test_entrada_sin_quien(self):
        self.comprobar_ignorada(lambda h: self.entrada(h, quien=None), r"incompleta: falta quien")

    def test_quien_en_blanco_y_sin_conclusion(self):
        self.comprobar_ignorada(lambda h: self.entrada(h, quien="   ", conclusion=None), r"falta quien, conclusion")

    def test_fecha_inexistente(self):
        self.comprobar_ignorada(lambda h: self.entrada(h, fecha="2026-02-30"), r"fecha inválida")

    def test_fecha_no_iso(self):
        self.comprobar_ignorada(lambda h: self.entrada(h, fecha="17-11-2026"), r"fecha inválida")

    def test_fecha_futura(self):
        self.comprobar_ignorada(lambda h: self.entrada(h, fecha="2027-01-01"), r"posterior a la corrida")

    def test_quien_es_la_ia(self):
        for quien in ("triage-fp", "Claude", "IA del auditor", "revisor-autorizacion"):
            with self.subTest(quien=quien):
                self.comprobar_ignorada(lambda h: self.entrada(h, quien=quien), r"IA o a un agente")

    def test_quien_no_es_un_nombre(self):
        for quien in ("<img src=x onerror=alert(1)>", "ana@ejemplo.cl", "X"):
            with self.subTest(quien=quien):
                self.comprobar_ignorada(lambda h: self.entrada(h, quien=quien), r"nombre de persona")

    def test_huella_vieja_es_huerfana(self):
        self.secretos_alta(1)
        vieja = hallazgo(9, CONTROL, "critica", ARCHIVO, 30, gate="N1", conf="alta", herramienta="gitleaks")
        self.registrar_fp([self.entrada(vieja, ubicacion=None)])
        self.render()
        self.assertEqual(self.control()["estado"], "fail")
        r = self.registro()
        self.assertEqual(r["aplicadas"], [])
        self.assertEqual(len(r["huerfanas"]), 1)
        self.assertIn("ya no coincide", r["huerfanas"][0]["motivo"])
        informe = (self.corrida / "informe.md").read_text(encoding="utf-8")
        self.assertIn("huérfana", seccion(informe, "## 6c.", "\n## 7"))

    def test_hallazgo_nuevo_distinto_en_la_misma_linea_no_se_descarta(self):
        viejo = hallazgo(0, CONTROL, "critica", ARCHIVO, 4, gate="N1", conf="alta", herramienta="gitleaks")
        nuevo = hallazgo(7, CONTROL, "critica", ARCHIVO, 4, gate="N1", conf="alta", herramienta="gitleaks")
        self.assertNotEqual(viejo["fingerprint"], nuevo["fingerprint"])
        self.poner_hallazgos([nuevo])
        self.registrar_fp([self.entrada(viejo)])
        self.render()
        e = self.control()
        self.assertEqual(e["estado"], "fail")
        self.assertEqual(e["hallazgos"], [nuevo["id"]])
        r = self.registro()
        self.assertEqual(r["aplicadas"], [])
        self.assertIn("hallazgo distinto", r["huerfanas"][0]["motivo"])
        self.assertTrue(self.bloqueos_de())

    def test_ubicacion_que_ya_no_coincide(self):
        h = self.secretos_alta(1)[0]
        self.registrar_fp([self.entrada(h, ubicacion=f"{ARCHIVO}:15")])
        self.render()
        self.assertEqual(self.control()["estado"], "fail")
        self.assertIn("ubicación registrada", self.registro()["huerfanas"][0]["motivo"])

    def test_huella_de_otro_control(self):
        h = self.secretos_alta(1)[0]
        self.registrar_fp([self.entrada(h, control="SEG-SECRETO-REPO")])
        self.render()
        self.assertEqual(self.control()["estado"], "fail")
        self.assertIn("otro control", self.registro()["huerfanas"][0]["motivo"])

    def test_json_ilegible_no_descarta_nada(self):
        self.secretos_alta(1)
        self.registrar_fp(None, crudo="{ esto no es json")
        self.render()
        self.assertEqual(self.control()["estado"], "fail")
        self.assertIn("no es JSON", self.registro()["ignoradas"][0]["motivo"])

    def test_enlace_simbolico_se_ignora(self):
        h = self.secretos_alta(1)[0]
        afuera = self.tmp / "afuera.json"
        afuera.write_text(json.dumps({"version": "1", "entradas": [self.entrada(h)]}), encoding="utf-8")
        (self.proyecto / ".auditor-integral").mkdir()
        (self.proyecto / ".auditor-integral" / "fp-verificados.json").symlink_to(afuera)
        self.autorizar(self.proyecto / ".auditor-integral" / "fp-verificados.json")
        self.render()
        self.assertEqual(self.control()["estado"], "fail")
        self.assertIn("enlace simbólico", self.registro()["ignoradas"][0]["motivo"])

    def test_duplicada_vale_la_primera(self):
        h = self.secretos_alta(1)[0]
        self.registrar_fp([self.entrada(h), self.entrada(h, quien="Otra Persona")])
        self.render()
        r = self.registro()
        self.assertEqual(len(r["aplicadas"]), 1)
        self.assertEqual(r["aplicadas"][0]["quien"], "Ana Pérez")
        self.assertIn("duplicada", r["ignoradas"][0]["motivo"])

    def test_texto_de_la_persona_como_literal_markdown(self):
        h = self.secretos_alta(1)[0]
        self.registrar_fp([self.entrada(h, conclusion="<img src=x onerror=alert(1)> | celda [x](http://e.example)")])
        informe, ruta, dueno = self.render()
        for doc in (informe, ruta):
            self.assertNotIn("<img", doc)
            self.assertNotIn("[x](http", doc)


class TestAutorizacionYFalsificacion(BaseFpHumano):
    """Revisión adversarial 2026-11-20: el registro del repo auditado y un fp_humanos.json escrito a mano en la
    corrida no pueden descartar críticos."""

    def test_archivo_del_repo_sin_autorizacion_no_descarta_y_se_avisa(self):
        h = self.secretos_alta(1)[0]
        self.registrar_fp([self.entrada(h)], autorizar=False)
        informe, ruta, dueno = self.render()
        self.assertEqual(self.control()["estado"], "fail")
        self.assertTrue(self.bloqueos_de())
        self.assertEqual(self.gates()["global"]["descartes_humanos"], [])
        r = self.registro()
        self.assertFalse(r["autorizado"])
        self.assertEqual(r["aplicadas"], [])
        self.assertIn("--fp-verificados", r["ignoradas"][0]["motivo"])
        cabecera = informe.split("## 1. Veredicto")[0]
        self.assertIn("NO se aplicó", cabecera)
        self.assertIn(f"### {CONTROL}", seccion(informe, "## 6. Hallazgos críticos y altos", "## 6b."))
        linea = next(l for l in dueno.splitlines() if l.startswith("- Falsas alarmas verificadas"))
        self.assertNotIn(CONTROL, linea)

    def test_fp_humanos_falsificado_en_la_corrida_no_cambia_el_informe(self):
        h = self.secretos_alta(1)[0]
        gates.generar(self.corrida)
        falso = {"version_esquema": "1", "archivo": veredictos.FP_HUMANO_REL, "autorizado": True,
                 "aplicadas": [{"entrada": 1, "control": CONTROL, "huella": h["id"], "hallazgos": [h["id"]],
                                "ubicaciones": [], "severidades": ["critica"], "quien": "Juan Perez",
                                "fecha": "2026-11-01", "conclusion": "revisado, no aplica"}],
                 "ignoradas": [], "huerfanas": []}
        (self.corrida / veredictos.FP_HUMANOS).write_text(json.dumps(falso), encoding="utf-8")
        render_informe.generar(self.corrida)
        leer = lambda n: (self.corrida / n).read_text(encoding="utf-8")  # noqa: E731
        informe, dueno = leer("informe.md"), leer("resumen-dueno.md")
        self.assertIn(f"### {CONTROL}", seccion(informe, "## 6. Hallazgos críticos y altos", "## 6b."))
        self.assertNotIn("No hay hallazgos críticos ni altos abiertos", informe)
        self.assertNotIn("Juan Perez", seccion(informe, "## 6c.", "\n## 7"))
        self.assertIn("no coincide con el registro recalculado", informe)
        linea = next(l for l in dueno.splitlines() if l.startswith("- Falsas alarmas verificadas"))
        self.assertNotIn("Juan Perez", linea)
        self.assertTrue(self.bloqueos_de())

    def test_estado_alterado_sin_respaldo_se_avisa(self):
        h = self.secretos_alta(1)[0]
        self.registrar_fp([self.entrada(h)])
        self.render()
        self.desautorizar()                      # report sin --fp-verificados: no puede re-verificar el estado
        render_informe.generar(self.corrida)
        informe = (self.corrida / "informe.md").read_text(encoding="utf-8")
        self.assertIn("no pudo re-verificar", informe)
        self.assertIn(f"### {CONTROL}", seccion(informe, "## 6. Hallazgos críticos y altos", "## 6b."))

    def test_fuente_fuera_del_proyecto_y_visible_en_gates(self):
        h = self.secretos_alta(1)[0]
        afuera = self.tmp / "registro-operador.json"
        afuera.write_text(json.dumps({"version": "1", "entradas": [self.entrada(h)]}), encoding="utf-8")
        self.autorizar(afuera)
        informe, _, _ = self.render()
        self.assertEqual(self.control()["estado"], "no_aplica")
        g = self.gates()["global"]
        self.assertEqual([d["control"] for d in g["descartes_humanos"]], [CONTROL])
        self.assertNotEqual(g["listo_datos_reales"], "SI")
        self.assertEqual(self.registro()["archivo"], "(fuera del proyecto) registro-operador.json")
        self.assertIn("Descartes humanos aplicados: 1", informe.split("## 1. Veredicto")[0])

    def test_listo_nunca_si_con_descartes(self):
        estados = [{"control": CONTROL, "estado": "no_aplica",
                    "descarte_humano": {"quien": "Ana Pérez", "fecha": "2026-11-17", "conclusion": "x",
                                        "hallazgos": ["H-1"]}}]
        g = gates.calcular(estados, {}, [], {}, set())
        self.assertNotEqual(g["global"]["listo_datos_reales"], "SI")
        self.assertEqual(g["global"]["descartes_humanos"][0]["control"], CONTROL)


class TestCliFpVerificados(unittest.TestCase):
    AUDITAR = RAIZ / "bin" / "auditar"

    def correr(self, *args):
        env = {k: v for k, v in os.environ.items() if k != veredictos.ENV_FP_HUMANO}
        return subprocess.run(["bash", str(self.AUDITAR), *args], capture_output=True, text=True, env=env,
                              timeout=60)

    def test_flag_solo_con_subcomandos_que_lo_usan(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "fp.json"
            f.write_text("{}", encoding="utf-8")
            r = self.correr("stack", d, "--fp-verificados", str(f))
            self.assertEqual(r.returncode, 2)
            self.assertIn("--fp-verificados solo vale", r.stderr)
            r = self.correr("gates", d, "--fp-verificados", str(Path(d) / "no-existe.json"))
            self.assertEqual(r.returncode, 2)
            self.assertIn("no es un archivo regular", r.stderr)

    def test_salida_que_es_un_archivo(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "archivo"
            f.write_text("x", encoding="utf-8")
            (Path(d) / "proy").mkdir()
            r = self.correr("gates", str(Path(d) / "proy"), "--salida", str(f))
            self.assertEqual(r.returncode, 4)
            self.assertIn("no es una carpeta", r.stderr)
            self.assertNotIn("no existe", r.stderr)
            self.assertEqual(r.stdout, "")


class TestFuncionesPuras(unittest.TestCase):
    def test_cargar_sin_proyecto_o_sin_carpeta(self):
        self.assertEqual(veredictos.cargar_fp_humanos(None), ([], [], False))
        self.assertEqual(veredictos.cargar_fp_humanos(Path("/nonexistent-auditor-h2")), ([], [], False))

    def test_regla_dura_en_los_skills(self):
        t = (RAIZ / "skills" / "auditar" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn(".auditor-integral/fp-verificados.json", t)
        self.assertRegex(t, r"Nunca escribas.{0,80}fp-verificados")
        p = (RAIZ / "skills" / "auditar-perfil" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("fp-verificados.json", p)

    def test_decision_11_registrada(self):
        t = (RAIZ / "DECISIONES.md").read_text(encoding="utf-8")
        self.assertRegex(t, r"\| 11 \|")
        self.assertRegex(t, r"(?i)pendiente de confirmar por Enzo")


if __name__ == "__main__":
    unittest.main()
