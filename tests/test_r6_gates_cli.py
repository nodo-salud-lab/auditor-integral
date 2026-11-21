"""Ronda 6, grupo gates-cli: correcciones de la verificación real (nivel N0 en todas las corridas).

1. gates.json: un bloqueo por control (tope más estricto + todos los motivos); el conteo es de controles únicos.
2. Remediación de secretos: «rotar + git filter-repo» solo si el secreto está versionado o en el historial.
3. bin/auditar: «all» exige RUTA; Python < 3.11 → rc 2 con mensaje (sin traceback).
4. Informe/resumen: herramientas en «parcial» cuentan como que corrieron; línea fija «no evaluado = no revisado»;
   códigos de bloqueo con su nombre legible en resumen-dueno.
5. Aplicabilidad por perfil_tecnico.tipo_proyecto (fail-closed: sin tipo no cambia nada).
Cada corrección tiene casos positivos y negativos (los negativos comprueban que no se abre un pase falso).
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import gates  # noqa: E402
import render_informe as ri  # noqa: E402
import roadmap  # noqa: E402
from tmp_tests import TMP_BASE  # noqa: E402

AUDITAR = RAIZ / "bin" / "auditar"


def control(id_, gate="N1", sev="media", bloquea=False, titulo=None):
    return {"id": id_, "titulo": titulo or f"Título de {id_}", "dominio": id_.split("-")[0], "gate": gate,
            "severidad_base": sev, "bloquea_global": bloquea, "metodo": "determinista", "esfuerzo": "S"}


INDICE = {
    "SEG-SECRETO-REPO": control("SEG-SECRETO-REPO", sev="critica", bloquea=True,
                                titulo="Sin secretos en el working tree ni en el historial git"),
    "DAT-PII-REPO": control("DAT-PII-REPO", sev="critica", bloquea=True, titulo="Datos personales versionados"),
    "DAT-RLS-PERMISIVA": control("DAT-RLS-PERMISIVA", gate="N2", sev="media", titulo="Sin políticas permisivas"),
    "COD-X": control("COD-X"),
}


def h(hid, ctrl, sev="critica", **extra):
    return {"id": hid, "control": ctrl, "severidad": sev, "confianza": "alta", "estado_hallazgo": "abierto", **extra}


# --------------------------------------------------------------------------------------------- 1. deduplicación
class TestBloqueoUnicoPorControl(unittest.TestCase):
    def calc(self, estados, hallazgos, banderas=None, exposicion=()):
        return gates.calcular(estados, INDICE, hallazgos, banderas or {}, set(exposicion))

    def test_secreto_con_bloquea_global_es_una_sola_entrada(self):
        g = self.calc([{"control": "SEG-SECRETO-REPO", "estado": "fail", "hallazgos": ["H-1"]},
                       {"control": "COD-X", "estado": "pass", "hallazgos": []}], [h("H-1", "SEG-SECRETO-REPO")])
        bl = g["global"]["bloqueos"]
        self.assertEqual(len(bl), 1)
        b = bl[0]
        self.assertEqual((b["control"], b["tipo"], b["tope"]), ("SEG-SECRETO-REPO", "secreto_vivo", "N0"))
        self.assertEqual(b["tipos"], ["secreto_vivo", "bloquea_global"])
        self.assertEqual(b["motivos"], [{"tipo": "secreto_vivo", "tope": "N0"}, {"tipo": "bloquea_global", "tope": "N1"}])
        self.assertEqual(b["hallazgos"], ["H-1"])
        # negativo: deduplicar no abre un pase; el tope más estricto (N0) sigue mandando
        self.assertEqual(g["global"]["nivel_demostrado"], "N0")
        self.assertEqual(g["global"]["listo_datos_reales"], "NO")

    def test_tres_motivos_con_datos_reales_expuestos(self):
        g = self.calc([{"control": "SEG-SECRETO-REPO", "estado": "fail", "hallazgos": ["H-1"]}],
                      [h("H-1", "SEG-SECRETO-REPO")], banderas={"datos_reales_cargados": True},
                      exposicion={"SEG-SECRETO-REPO"})
        bl = g["global"]["bloqueos"]
        self.assertEqual(len(bl), 1)
        self.assertEqual(bl[0]["tope"], "N0")
        self.assertEqual(bl[0]["tipos"], ["datos_reales_expuestos", "secreto_vivo", "bloquea_global"])

    def test_controles_distintos_siguen_separados_y_ordenados(self):
        g = self.calc([{"control": "SEG-SECRETO-REPO", "estado": "fail", "hallazgos": ["H-1"]},
                       {"control": "DAT-PII-REPO", "estado": "fail", "hallazgos": ["H-2"]},
                       {"control": "DAT-RLS-PERMISIVA", "estado": "fail", "hallazgos": ["H-3"]}],
                      [h("H-1", "SEG-SECRETO-REPO"), h("H-2", "DAT-PII-REPO"), h("H-3", "DAT-RLS-PERMISIVA")])
        bl = g["global"]["bloqueos"]
        self.assertEqual([b["control"] for b in bl], ["SEG-SECRETO-REPO", "DAT-PII-REPO", "DAT-RLS-PERMISIVA"])
        self.assertEqual([b["tipo"] for b in bl], ["secreto_vivo", "bloquea_global", "critico_seg_dat"])
        self.assertEqual(len({b["control"] for b in bl}), len(bl))

    def test_sin_fail_no_hay_bloqueo(self):
        g = self.calc([{"control": "SEG-SECRETO-REPO", "estado": "pass", "hallazgos": []}], [])
        self.assertEqual(g["global"]["bloqueos"], [])

    def test_resumen_dueno_cuenta_controles_y_muestra_nombre(self):
        g = self.calc([{"control": "SEG-SECRETO-REPO", "estado": "fail", "hallazgos": ["H-1"]},
                       {"control": "DAT-PII-REPO", "estado": "fail", "hallazgos": ["H-2"]}],
                      [h("H-1", "SEG-SECRETO-REPO"), h("H-2", "DAT-PII-REPO")])
        texto = ri._bloqueos_dueno(g, INDICE)
        self.assertTrue(texto.startswith("2: "), texto)
        self.assertIn("SEG-SECRETO-REPO «Sin secretos en el working tree ni en el historial git» → N0", texto)
        self.assertIn("DAT-PII-REPO «Datos personales versionados» → N1", texto)
        self.assertEqual(ri._bloqueos_dueno({"global": {"bloqueos": []}}, INDICE), "ninguno")

    def test_seccion_bloqueos_del_informe_lista_todos_los_motivos(self):
        g = self.calc([{"control": "SEG-SECRETO-REPO", "estado": "fail", "hallazgos": ["H-1"]}],
                      [h("H-1", "SEG-SECRETO-REPO")])
        texto = ri._seccion_bloqueos(g, INDICE)
        self.assertEqual(texto.count("- SEG-SECRETO-REPO"), 1)
        self.assertIn(ri.TEXTOS_BLOQUEO["secreto_vivo"], texto)
        self.assertIn(ri.TEXTOS_BLOQUEO["bloquea_global"], texto)

    def test_roadmap_junta_los_tipos_de_un_bloqueo_pendiente_ia(self):
        gates_json = {"global": {"bloqueos": [{"control": "SEG-SECRETO-REPO", "tipo": "secreto_vivo", "tope": "N0",
                                               "tipos": ["secreto_vivo", "bloquea_global"], "pendiente_ia": True,
                                               "nota": "x", "hallazgos": ["H-1"]}], "cuello_de_botella": []},
                      "dominios": {"SEG": {"activo": True, "nivel_demostrado": "N0"}}}
        items = roadmap.calcular([{"control": "SEG-SECRETO-REPO", "estado": "no_evaluado", "hallazgos": [],
                                   "motivo": "falso positivo crítico según IA (H-1)"}], INDICE, gates_json, [])
        self.assertEqual(items[0]["bloqueo"]["tipos"], ["secreto_vivo", "bloquea_global"])


# --------------------------------------------------------------------------------------------- 2. secretos
BASE = "Rotar la credencial ... limpiar el historial (git filter-repo) después de rotar."


class TestRemediacionSecreto(unittest.TestCase):
    def test_clases(self):
        self.assertEqual(roadmap.clase_secreto(h("H", "SEG-SECRETO-REPO")), "versionado")  # sin marcas: fail-closed
        self.assertEqual(roadmap.clase_secreto(h("H", "SEG-SECRETO-REPO", secreto={"versionado": False})),
                         "no_versionado")
        self.assertEqual(roadmap.clase_secreto(h("H", "SEG-SECRETO-REPO", no_versionado=True)), "no_versionado")
        self.assertEqual(roadmap.clase_secreto(h("H", "SEG-SECRETO-REPO", secreto={"jwt_rol": "anon"})), "publica")
        self.assertEqual(roadmap.clase_secreto(h("H", "SEG-SECRETO-REPO", jwt_rol="ANON")), "publica")
        self.assertEqual(roadmap.clase_secreto(h("H", "SEG-SECRETO-REPO", secreto={"jwt_rol": "service_role"})),
                         "versionado")
        # del historial (commit) siempre es versionado, aunque traiga la marca de no versionado
        self.assertEqual(roadmap.clase_secreto(h("H", "SEG-SECRETO-REPO", secreto={"versionado": False},
                                                 ubicacion={"archivo": "a", "commit": "abcdef1"})), "versionado")

    def test_no_versionado_sin_filter_repo(self):
        t = roadmap.remediacion_secreto("SEG-SECRETO-REPO",
                                        [h("H-1", "SEG-SECRETO-REPO", secreto={"versionado": False})], BASE)
        self.assertNotEqual(t, BASE)
        self.assertIn("no versiona", t)
        self.assertIn("no hace falta limpiar el historial", t)

    def test_clave_publica(self):
        t = roadmap.remediacion_secreto("SEG-SECRETO-BUNDLE",
                                        [h("H-1", "SEG-SECRETO-BUNDLE", secreto={"jwt_rol": "anon"})], BASE)
        self.assertIn("anon", t)
        self.assertIn("RLS", t)
        self.assertNotIn("filter-repo después", t)

    def test_mezcla_publica_y_no_versionado(self):
        t = roadmap.remediacion_secreto("SEG-SECRETO-REPO",
                                        [h("H-1", "SEG-SECRETO-REPO", secreto={"jwt_rol": "anon"}),
                                         h("H-2", "SEG-SECRETO-REPO", secreto={"versionado": False})], BASE)
        self.assertIn("anon", t)
        self.assertIn("no versiona", t)

    def test_una_instancia_versionada_mantiene_rotar_y_filter_repo(self):
        hs = [h("H-1", "SEG-SECRETO-REPO", secreto={"versionado": False}), h("H-2", "SEG-SECRETO-REPO")]
        self.assertEqual(roadmap.remediacion_secreto("SEG-SECRETO-REPO", hs, BASE), BASE)

    def test_otro_control_o_sin_hallazgos_no_cambia(self):
        self.assertEqual(roadmap.remediacion_secreto("DAT-PII-REPO",
                                                     [h("H", "DAT-PII-REPO", secreto={"versionado": False})], BASE), BASE)
        self.assertEqual(roadmap.remediacion_secreto("SEG-SECRETO-REPO", [], BASE), BASE)

    def test_roadmap_decide_con_todas_las_instancias(self):
        """hallazgos.jsonl puede traer solo una instancia (no versionada); si en hallazgos_todos hay una versionada,
        la hoja de ruta mantiene rotar + filter-repo."""
        gates_json = {"global": {"bloqueos": [], "cuello_de_botella": []},
                      "dominios": {"SEG": {"activo": True, "nivel_demostrado": "N0"}}}
        uno = h("H-1", "SEG-SECRETO-REPO", secreto={"versionado": False}, remediacion=BASE)
        est = [{"control": "SEG-SECRETO-REPO", "estado": "fail", "hallazgos": ["H-1"]}]
        items = roadmap.calcular(est, INDICE, gates_json, [uno])
        self.assertIn("no versiona", items[0]["que_hacer"])
        items = roadmap.calcular(est, INDICE, gates_json, [uno], todos=[uno, h("H-2", "SEG-SECRETO-REPO")])
        self.assertEqual(items[0]["que_hacer"], BASE)

    def test_textos_en_la_plantilla(self):
        t = roadmap.textos_remediacion_secreto()
        self.assertEqual(set(t), {"no_versionado", "clave_publica", "no_versionado_y_publica"})
        for v in t.values():
            self.assertLessEqual(len(v), 600)


# --------------------------------------------------------------------------------------------- 3. bin/auditar
class TestBinAuditar(unittest.TestCase):
    def setUp(self):
        TMP_BASE.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="r6-gates-cli-", dir=TMP_BASE))
        self.env = dict(os.environ, TMPDIR=str(self.tmp))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def correr(self, *args, env=None, cwd=None):
        return subprocess.run([str(AUDITAR), *args], capture_output=True, text=True, env=env or self.env,
                              cwd=cwd or self.tmp, timeout=120)

    def test_all_sin_ruta_rc2_y_no_crea_nada(self):
        (self.tmp / "package.json").write_text("{}")
        r = self.correr("all", "--sin-red")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("requiere la RUTA", r.stderr)
        self.assertIn("auditar-aqui", r.stderr)
        self.assertFalse((self.tmp / ".auditoria").exists())
        self.assertEqual(r.stdout, "")

    def test_all_con_ruta_inexistente_sigue_siendo_rc2(self):
        r = self.correr("all", str(self.tmp / "no-existe"), "--sin-red")
        self.assertEqual(r.returncode, 2)
        self.assertIn("no es una carpeta", r.stderr)

    def falso_python(self, version, rc):
        p = self.tmp / "python-falso"
        p.write_text(f"#!/bin/sh\necho {version}\nexit {rc}\n")
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
        return p

    def test_python_viejo_rc2_con_mensaje(self):
        env = dict(self.env, AUDITOR_PYTHON=str(self.falso_python("3.9.6", 1)))
        for args in (("all", str(self.tmp), "--sin-red"), ("--version",), ("gates", str(self.tmp))):
            r = self.correr(*args, env=env)
            self.assertEqual(r.returncode, 2, args)
            self.assertIn("requiere Python ≥ 3.11; encontrado 3.9.6", r.stderr)
            self.assertIn("instale Python 3.11", r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_python_inexistente_rc2(self):
        env = dict(self.env, AUDITOR_PYTHON=str(self.tmp / "no-hay-python"))
        r = self.correr("--version", env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("requiere Python ≥ 3.11", r.stderr)

    def test_ayuda_no_exige_python(self):
        env = dict(self.env, AUDITOR_PYTHON=str(self.falso_python("3.9.6", 1)))
        self.assertEqual(self.correr("--help", env=env).returncode, 0)

    def test_python_actual_pasa(self):
        r = self.correr("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("auditor-integral", r.stdout)

    @unittest.skipUnless(Path("/usr/bin/python3").exists(), "sin /usr/bin/python3")
    def test_python_del_sistema_si_es_viejo(self):
        v = subprocess.run(["/usr/bin/python3", "-c", "import sys; print(sys.version_info >= (3, 11))"],
                           capture_output=True, text=True, timeout=60)
        if v.returncode != 0 or v.stdout.strip() != "False":
            self.skipTest("/usr/bin/python3 no es < 3.11")
        r = self.correr("--version", env=dict(self.env, AUDITOR_PYTHON="/usr/bin/python3"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("requiere Python ≥ 3.11; encontrado 3.", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


# --------------------------------------------------------------------------------------------- 4. informe
class TestInforme(unittest.TestCase):
    RESUMEN = {"herramientas": {"semgrep": {"estado": "parcial", "version": "1.181.0"},
                                "gitleaks": {"estado": "ok", "version": "8.30.1"},
                                "osv-scanner": {"estado": "no_evaluado", "version": None},
                                "trivy": {"estado": "error", "version": None},
                                "iac": {"estado": "no_aplica", "version": None}}}

    def test_parcial_cuenta_como_que_corrio(self):
        motivos = {"semgrep": "sin red (AUDITOR_SIN_RED): solo reglas locales"}
        t = ri.seccion_que_hizo(self.RESUMEN, [], {}, [], None, "estandar", motivos=motivos)
        corrieron = next(l for l in t.splitlines() if "Herramientas que corrieron" in l)
        no_corrieron = next(l for l in t.splitlines() if "No corrieron" in l)
        self.assertIn("(2)", corrieron)
        self.assertIn("semgrep 1.181.0 (parcial: sin red (AUDITOR_SIN_RED): solo reglas locales)", corrieron)
        self.assertIn("gitleaks 8.30.1", corrieron)
        self.assertNotIn("semgrep", no_corrieron)
        # negativo: lo que no corrió sigue fuera de la lista
        self.assertIn("osv-scanner", no_corrieron)
        self.assertIn("trivy", no_corrieron)
        self.assertNotIn("osv-scanner", corrieron)

    def test_parcial_sin_motivo_registrado(self):
        t = ri.seccion_que_hizo({"herramientas": {"semgrep": {"estado": "parcial"}}}, [], {}, [], None, "estandar")
        self.assertIn(f"semgrep s/v (parcial: {ri.MOTIVO_NO_REGISTRADO})", t)

    def test_nota_no_evaluado(self):
        indice = {"SEG-A": {"herramientas": ["semgrep"]}, "SEG-B": {"herramientas": ["revisor-autorizacion"]},
                  "SEG-C": {"herramientas": ["gitleaks"]}, "SEG-D": {}}
        est = [{"control": "SEG-A", "estado": "no_evaluado",
                "motivo": "semgrep: ejecución parcial: sin red (AUDITOR_SIN_RED): solo reglas locales"},
               {"control": "SEG-B", "estado": "no_evaluado", "motivo": "juicio LLM no ejecutado en F1"},
               {"control": "SEG-C", "estado": "pass", "motivo": None},
               {"control": "SEG-D", "estado": "manual_pendiente", "motivo": "requiere verificación manual"}]
        t = ri.nota_no_evaluado(est, indice)
        self.assertIn("«No evaluado» significa «no revisado», no «está bien»", t)
        self.assertIn("quedaron 3 control(es) sin revisar", t)
        self.assertIn("1 por falta de red y 1 a la espera del juicio de la IA", t)
        t0 = ri.nota_no_evaluado([{"control": "SEG-C", "estado": "pass"}], indice)
        self.assertIn("quedaron 0 control(es) sin revisar; de ellos, 0 por falta de red y 0", t0)

    def test_plantillas_llevan_la_nota(self):
        for nombre in ("informe.md.tmpl", "resumen-dueno.md.tmpl"):
            self.assertIn("$nota_no_evaluado", (RAIZ / "plantillas" / nombre).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------------- 5. tipo_proyecto
class TestTipoProyecto(unittest.TestCase):
    def estados(self):
        return [{"control": "OPS-HEALTH", "estado": "no_evaluado", "hallazgos": [], "motivo": "x", "herramienta": "a"},
                {"control": "SEG-HEADERS", "estado": "no_evaluado", "hallazgos": [], "motivo": "x"},
                {"control": "SEG-CORS", "estado": "fail", "hallazgos": ["H-1"], "motivo": None},
                {"control": "SEG-RATELIMIT", "estado": "pass", "hallazgos": [], "motivo": None},
                {"control": "UX-LANG", "estado": "manual_pendiente", "hallazgos": [], "motivo": "x"},
                {"control": "SEG-SECRETO-REPO", "estado": "no_evaluado", "hallazgos": [], "motivo": "x"}]

    def test_lectura_del_tipo(self):
        self.assertEqual(gates.tipo_proyecto({"tipo_proyecto": "cli_libreria"}), "cli_libreria")
        self.assertEqual(gates.tipo_proyecto({"tipo_proyecto": {"valor": "movil"}}), "movil")
        for t in ({}, None, {"tipo_proyecto": "desconocido"}, {"tipo_proyecto": "otra_cosa"},
                  {"tipo_proyecto": None}, {"tipo_proyecto": 3}):
            self.assertIsNone(gates.tipo_proyecto(t), t)

    def test_cli_libreria(self):
        est = self.estados()
        ajustados = gates.ajustar_tipo_proyecto(est, "cli_libreria")
        por = {e["control"]: e for e in est}
        self.assertEqual(sorted(ajustados), ["OPS-HEALTH", "SEG-HEADERS", "UX-LANG"])
        self.assertEqual(por["OPS-HEALTH"]["estado"], "no_aplica")
        self.assertIn("cli_libreria", por["OPS-HEALTH"]["motivo"])
        self.assertIsNone(por["OPS-HEALTH"]["herramienta"])
        # negativos: fail con hallazgos y pass no se tocan; controles fuera de la lista tampoco
        self.assertEqual(por["SEG-CORS"]["estado"], "fail")
        self.assertEqual(por["SEG-RATELIMIT"]["estado"], "pass")
        self.assertEqual(por["SEG-SECRETO-REPO"]["estado"], "no_evaluado")

    def test_movil_no_toca_servidor(self):
        est = self.estados()
        est[3]["estado"] = "no_evaluado"   # SEG-RATELIMIT: en movil el backend puede necesitarlo
        gates.ajustar_tipo_proyecto(est, "movil")
        por = {e["control"]: e["estado"] for e in est}
        self.assertEqual(por["SEG-HEADERS"], "no_aplica")
        self.assertEqual(por["UX-LANG"], "no_aplica")
        self.assertEqual(por["OPS-HEALTH"], "no_evaluado")
        self.assertEqual(por["SEG-RATELIMIT"], "no_evaluado")

    def test_sin_tipo_o_tipo_sin_regla_no_cambia_nada(self):
        for tipo in (None, "web", "api", "spa"):
            est = self.estados()
            self.assertEqual(gates.ajustar_tipo_proyecto(est, tipo), [])
            self.assertEqual(est, self.estados())

    def test_fp_ia_pendiente_no_se_toca(self):
        est = [{"control": "SEG-HEADERS", "estado": "no_evaluado", "hallazgos": [],
                "motivo": roadmap.MOTIVO_FP_ALTO + " (H-1): requiere verificación humana"}]
        self.assertEqual(gates.ajustar_tipo_proyecto(est, "cli_libreria"), [])
        self.assertEqual(est[0]["estado"], "no_evaluado")

    def test_controles_de_la_tabla_existen_en_el_catalogo(self):
        import catalogo
        ids = {c["id"] for c in catalogo.cargar_catalogo()}
        reglas = gates.reglas_tipo_proyecto()
        self.assertEqual(set(reglas), {"cli_libreria", "movil"})
        for tipo, (motivo, controles) in reglas.items():
            self.assertTrue(controles <= ids, controles - ids)
            self.assertLessEqual(len(motivo), 300)
            # ningún control que bloquee el nivel global ni de nivel N1 se vuelve no_aplica por tipo
            for cid in controles:
                c = next(x for x in catalogo.cargar_catalogo() if x["id"] == cid)
                self.assertFalse(c.get("bloquea_global"), cid)
                self.assertNotEqual(c["gate"], "N1", cid)

    def test_tabla_ausente_no_cambia_nada(self):
        est = self.estados()
        self.assertEqual(gates.ajustar_tipo_proyecto(est, "cli_libreria", reglas={}), [])
        self.assertEqual(est, self.estados())


if __name__ == "__main__":
    unittest.main()
