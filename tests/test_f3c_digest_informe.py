"""F3-C: correcciones de digest e informe tras la comparación de brazos (investigacion/17-comparacion-calidad-tokens.md).

1. El digest de triage reserva una cuota (config/presupuesto_tokens.toml [triage] cuota_fp) para candidatos a falso
   positivo: confianza baja/media, reglas o controles con historial de FP, rutas de tests/minificados/ejemplos. Los
   críticos/altos que no entran siguen en incierto_por_tope (cuentan como verdaderos). Nunca se supera el tope.
2. indice.json marca omitir_juez/motivo_omision por digest cuando no hay nada que juzgar o falta la entrada esencial,
   lista los controles de cada digest y qué jueces lanzar según el modo ([jueces], ESTIMACIÓN).
3. render_informe: «No corrieron» muestra el motivo real del .meta.json / salida del check (fallback honesto).
4. rutas_inventario: una SPA sin backend registra «sin backend detectado (SPA)»; sigue no_evaluado.
"""
import json
import math
import sys
import tomllib
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import digest  # noqa: E402
import render_informe  # noqa: E402
import rutas_inventario as ri  # noqa: E402
from test_f3a_digest import Base, escribir, hallazgo  # noqa: E402


def con_regla(h, herramienta, regla):
    h = dict(h)
    h["fuente"] = [{"herramienta": herramienta, "version": "1", "regla": regla}]
    return h


class TestCuotaFalsosPositivos(Base):
    def test_candidatos_fp_entran_aunque_los_graves_llenen_el_tope(self):
        graves = [hallazgo(i, "SEG-SECRETO-REPO", "critica", "src/api.js", 10, evidencia="g" * 280) for i in range(40)]
        conf_baja = hallazgo(100, "UX-ESTADOS", "media", "src/api.js", 12, conf="baja")
        en_tests = hallazgo(101, "COD-DUPLICACION", "media", "tests/util.test.js", 3)
        generica = con_regla(hallazgo(102, "SEG-SECRETO-BUNDLE", "baja", "src/api.js", 10), "gitleaks", "generic-api-key")
        sin_indicio = hallazgo(103, "UX-ESTADOS", "media", "src/api.js", 15)
        self.hallazgos(graves + [conf_baja, en_tests, generica, sin_indicio])
        d = digest.generar(self.corrida)
        ids = {x["id"] for x in d["hallazgos"]}
        for h in (conf_baja, en_tests, generica):
            self.assertIn(h["id"], ids)
        self.assertNotIn(sin_indicio["id"], ids)
        marcados = {x["id"]: x for x in d["hallazgos"] if x.get("indicios_fp")}
        self.assertIn("confianza baja", marcados[conf_baja["id"]]["indicios_fp"])
        self.assertTrue(any("test" in i for i in marcados[en_tests["id"]]["indicios_fp"]))
        self.assertTrue(any("generic-api-key" in i for i in marcados[generica["id"]]["indicios_fp"]))
        # los graves que no entran siguen 'incierto' (cuentan como verdaderos)
        graves_dentro = {h["id"] for h in graves} & ids
        self.assertEqual(sorted(d["incierto_por_tope"]), sorted({h["id"] for h in graves} - graves_dentro))
        self.assertGreater(len(graves_dentro), 0)
        tope, cpt = digest.cargar_presupuesto()
        self.assertLessEqual(math.ceil(len(self.texto("triage")) / cpt), tope)
        self.assertFalse(self.indice()["digests"]["triage"]["completo"])

    def test_cuota_no_supera_su_porcentaje(self):
        graves = [hallazgo(i, "SEG-SECRETO-REPO", "alta", "src/api.js", 10, evidencia="g" * 200) for i in range(30)]
        candidatos = [hallazgo(200 + i, "UX-ESTADOS", "media", "src/api.js", 12, conf="baja", evidencia="c" * 200)
                      for i in range(60)]
        self.hallazgos(graves + candidatos)
        digest.generar(self.corrida, tope_tokens=4000, caracteres_por_token=4)
        d = self.leer("triage")
        cuota = digest.cargar_triage()["cuota_fp"]
        fp_items = [x for x in d["hallazgos"] if x["id"] in {h["id"] for h in candidatos}]
        tokens_fp = sum(math.ceil(len(json.dumps(x, ensure_ascii=False, separators=(",", ":"))) / 4) + 1
                        for x in fp_items)
        self.assertGreater(len(fp_items), 0)
        self.assertLessEqual(tokens_fp, math.floor(4000 * cuota) + 5)
        self.assertGreater(sum(1 for x in d["hallazgos"] if x["severidad"] == "alta"), 0)
        ind = self.indice()["digests"]["triage"]
        self.assertGreater(ind["candidatos_fp"]["fuera"], 0)
        self.assertEqual(ind["candidatos_fp"]["incluidos"], len(fp_items))
        self.assertLessEqual(ind["tokens_estimados"], 4000)

    def test_graves_de_baja_confianza_entran_por_la_cuota(self):
        hs = [hallazgo(i, "SEG-SECRETO-REPO", "critica", "src/api.js", 10, conf="alta" if i < 25 else "baja")
              for i in range(30)]
        self.hallazgos(hs)
        d = digest.generar(self.corrida, tope_tokens=100000)
        ids = {x["id"] for x in d["hallazgos"]}
        self.assertTrue({h["id"] for h in hs[25:]} <= ids)  # los 5 de confianza baja se juzgan
        self.assertEqual(len(d["hallazgos"]), 25)  # anti-desborde: ≤ 25 críticos/altos en el digest
        self.assertEqual(len(d["incierto_por_tope"]), 5)
        self.assertTrue(set(d["incierto_por_tope"]) <= {h["id"] for h in hs[:25]})

    def test_orden_por_fuerza_de_indicios_antes_que_severidad(self):
        cfg = digest.cargar_triage()
        critico_media = hallazgo(1, "SEG-AUTH-CLIENTE", "critica", "src/api.js", 10, conf="media")
        historial = hallazgo(2, "SEG-ERRORES", "media", "src/api.js", 12)
        pares = [(h, digest.indicios_fp(h, cfg)) for h in (critico_media, historial)]
        orden = [h["id"] for h, _ in sorted(pares, key=digest._orden_candidato)]
        self.assertEqual(orden, [historial["id"], critico_media["id"]])

    def test_sin_candidatos_los_graves_usan_todo(self):
        hs = [hallazgo(i, "SEG-SECRETO-REPO", "alta", "src/api.js", 10) for i in range(10)]
        self.hallazgos(hs)
        d = digest.generar(self.corrida)
        self.assertEqual(len(d["hallazgos"]), 10)
        self.assertEqual(d["incierto_por_tope"], [])
        self.assertTrue(self.indice()["digests"]["triage"]["completo"])

    def test_config_triage_y_valores_por_defecto(self):
        t = digest.cargar_triage()
        self.assertGreater(t["cuota_fp"], 0)
        self.assertLess(t["cuota_fp"], 1)
        self.assertIn("gitleaks:generic-api-key", t["reglas_historial_fp"])
        vacio = self.tmp / "v.toml"
        vacio.write_text("", encoding="utf-8")
        self.assertEqual(digest.cargar_triage(vacio)["cuota_fp"], digest.CUOTA_FP_DEFECTO)
        malo = self.tmp / "m.toml"
        malo.write_text("[triage]\ncuota_fp = 3\n", encoding="utf-8")
        self.assertEqual(digest.cargar_triage(malo)["cuota_fp"], digest.CUOTA_FP_DEFECTO)


class TestOmitirJuez(Base):
    def inventario(self, filas, estado="ok", motivo=None):
        datos = {"check": "rutas_inventario", "estado": estado, "motivo": motivo, "hallazgos": [], "checks_pass": [],
                 "inventario": filas, "alcance": {"rutas": len(filas), "codigo_confidencial": 0, "omitidos_tamano": 0,
                                                  "omitidos_tope": 0}, "resumen": {"incompleto": []}}
        (self.corrida / "crudo" / "check_rutas_inventario.json").write_text(json.dumps(datos), encoding="utf-8")

    def test_todo_vacio_omite_todos_los_jueces(self):
        self.hallazgos([])
        self.inventario([], estado="no_evaluado", motivo="sin backend detectado (SPA)")
        digest.generar(self.corrida)
        ind = self.indice()["digests"]
        for j in ("autorizacion", "arquitectura", "triage", "ux"):
            self.assertTrue(ind[j]["omitir_juez"], j)
            self.assertTrue(ind[j]["motivo_omision"], j)
            self.assertFalse(ind[j]["lanzar"], j)
        self.assertIn("inventario de rutas", ind["autorizacion"]["motivo_omision"])
        self.assertIn("sin backend detectado (SPA)", ind["autorizacion"]["motivo_omision"])
        self.assertIn("flujograma", ind["arquitectura"]["motivo_omision"])
        self.assertIn("0 hallazgos", ind["triage"]["motivo_omision"])
        # una omisión nunca vuelve 'completo' un digest vacío por falta de entrada
        self.assertFalse(ind["autorizacion"]["completo"])

    def test_controles_listados_en_indice_y_digest(self):
        self.hallazgos([])
        digest.generar(self.corrida)
        ind = self.indice()["digests"]
        for j in ("autorizacion", "arquitectura", "ux"):
            self.assertEqual(ind[j]["controles"], [c["id"] for c in self.leer(j)["controles"]], j)
        # triage: el digest no lleva la lista (tokens); el índice sí (integración F3-C, regla f de veredictos.py)
        self.assertEqual(self.leer("triage")["controles"], [])
        self.assertIn("SEG-SAST-TRIAGE", ind["triage"]["controles"])
        self.assertIn("SEG-IDOR", ind["autorizacion"]["controles"])

    def test_con_material_no_se_omite(self):
        self.hallazgos([hallazgo(1, "SEG-SECRETO-REPO", "critica", "src/api.js", 10)])
        self.inventario([{"framework": "express", "ruta": "/api/a/:id", "metodo": "GET", "archivo": "src/api.js",
                          "linea": 10, "auth": False, "filtra_por_usuario": False, "service_role": False,
                          "consultas": [], "sospechosa": True, "motivos": ["id_sin_pertenencia"]}])
        digest.generar(self.corrida)
        ind = self.indice()["digests"]
        for j in ("autorizacion", "triage"):
            self.assertFalse(ind[j]["omitir_juez"], j)
            self.assertIsNone(ind[j]["motivo_omision"], j)

    def test_arquitectura_con_flujograma_confirmado_no_se_omite(self):
        self.hallazgos([])
        (self.corrida / "perfil.json").write_text(json.dumps({
            "banderas": {}, "flujograma": {"archivo": "flujograma.mmd", "estado": "confirmado"}}), encoding="utf-8")
        digest.generar(self.corrida)
        ind = self.indice()["digests"]["arquitectura"]
        self.assertFalse(ind["omitir_juez"])
        self.assertEqual(self.leer("arquitectura")["contexto"]["flujograma"]["estado"], "confirmado")

    def test_arquitectura_con_flujograma_borrador_y_sin_hallazgos_se_omite(self):
        self.hallazgos([])
        (self.corrida / "perfil.json").write_text(json.dumps({
            "banderas": {}, "flujograma": {"archivo": "flujograma.mmd", "estado": "borrador"}}), encoding="utf-8")
        digest.generar(self.corrida)
        self.assertTrue(self.indice()["digests"]["arquitectura"]["omitir_juez"])

    def test_jueces_por_modo(self):
        self.hallazgos([hallazgo(1, "SEG-SECRETO-REPO", "critica", "src/api.js", 10),
                        hallazgo(2, "SEG-AUTH-CLIENTE", "alta", "src/api.js", 12)])
        for modo, esperado in (("rapido", {"triage"}), ("estandar", {"triage", "autorizacion"})):
            run = json.loads((self.corrida / "run.json").read_text(encoding="utf-8"))
            run["modo"] = modo
            (self.corrida / "run.json").write_text(json.dumps(run), encoding="utf-8")
            digest.generar(self.corrida)
            ind = self.indice()
            lanzar = {j for j, m in ind["digests"].items() if m["lanzar"]}
            self.assertEqual(lanzar, esperado, modo)
            self.assertEqual(ind["jueces_modo"]["modo"], modo)
            self.assertIn("ESTIMACIÓN", ind["jueces_modo"]["nota"])

    def test_config_jueces(self):
        t = tomllib.loads((RAIZ / "config" / "presupuesto_tokens.toml").read_text(encoding="utf-8"))
        self.assertEqual(t["jueces"]["rapido"]["lanzar"], ["triage"])
        self.assertEqual(sorted(t["jueces"]["estandar"]["lanzar"]), ["autorizacion", "triage"])
        self.assertEqual(t["jueces"]["estandar"]["condicionales"], ["arquitectura"])
        self.assertIn("arquitectura", t["jueces"]["profundo"]["lanzar"])
        self.assertEqual(t["jueces"]["origen"], "ESTIMACIÓN")


class TestSkill(unittest.TestCase):
    def test_skill_respeta_omitir_juez_y_modo(self):
        t = (RAIZ / "skills" / "auditar" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("omitir_juez", t)
        self.assertIn("lanzar", t)
        self.assertIn("[jueces]", t)
        self.assertRegex(t, r"(?s)jueces.{0,400}ESTIMACIÓN")
        self.assertLessEqual(len(t.splitlines()), 150)


class TestMotivosNoCorrieron(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)
        self.crudo = self.tmp / "crudo"
        self.crudo.mkdir()

    def tearDown(self):
        ap.limpiar(self.tmp)

    def meta(self, nombre, error):
        (self.crudo / f"{nombre}.meta.json").write_text(json.dumps({"estado": "no_evaluado", "error": error}),
                                                         encoding="utf-8")

    def test_motivo_real_desde_meta_y_salida(self):
        self.meta("check_rls_estatico", "no hay supabase/migrations/*.sql")
        (self.crudo / "check_tipos.json").write_text(json.dumps({"estado": "no_evaluado", "motivo":
                                                                 "no se ejecuta el tsc del repositorio auditado"}),
                                                     encoding="utf-8")
        self.meta("gitleaks", "sin red simulada")
        m = render_informe.motivos_herramientas(self.tmp)
        self.assertEqual(m["rls_estatico"], "no hay supabase/migrations/*.sql")
        self.assertEqual(m["tipos"], "no se ejecuta el tsc del repositorio auditado")
        self.assertEqual(m["gitleaks"], "sin red simulada")

    def test_seccion_que_hizo_usa_el_motivo_real(self):
        resumen = {"herramientas": {"rls_estatico": {"estado": "no_evaluado"}, "tipos": {"estado": "no_evaluado"},
                                    "semgrep": {"estado": "ok", "version": "1"}}}
        texto = render_informe.seccion_que_hizo(resumen, [], {}, [], None, "estandar",
                                                motivos={"rls_estatico": "no hay supabase/migrations"})
        self.assertIn("rls_estatico (no evaluado: no hay supabase/migrations)", texto)
        self.assertIn("tipos (no evaluado: motivo no registrado)", texto)
        self.assertNotIn("p. ej. sin red", texto)

    def test_motivo_se_enmascara_y_recorta(self):
        largo = "x" * 1000
        texto = render_informe.seccion_que_hizo({"herramientas": {"tipos": {"estado": "error"}}}, [], {}, [], None,
                                                "estandar", motivos={"tipos": largo})
        self.assertNotIn(largo, texto)
        self.assertIn("la herramienta terminó con error", texto)


class TestRutasSPA(unittest.TestCase):
    def setUp(self):
        self.dir = ap.tmp_dir(self)

    def tearDown(self):
        ap.limpiar(self.dir)

    def test_spa_sin_backend(self):
        escribir(self.dir, "package.json", json.dumps({"dependencies": {"react": "18.3.1", "vite": "5.0.0"}}))
        escribir(self.dir, "src/App.jsx", "export default function App() { return null; }\n")
        res = ri.analizar(self.dir)
        self.assertEqual(res["estado"], "no_evaluado")
        self.assertIn("sin backend detectado (SPA)", res["motivo"])
        self.assertNotIn("framework no reconocido", res["motivo"])
        self.assertEqual(res["checks_pass"], [])

    def test_backend_no_reconocido(self):
        escribir(self.dir, "package.json", json.dumps({"dependencies": {"koa": "2.15.0"}}))
        escribir(self.dir, "src/server.js", "const Koa = require('koa'); const app = new Koa();\n")
        res = ri.analizar(self.dir)
        self.assertEqual(res["estado"], "no_evaluado")
        self.assertIn("framework no reconocido", res["motivo"])
        self.assertIn("koa", res["motivo"])

    def test_carpeta_server_no_es_spa(self):
        escribir(self.dir, "package.json", json.dumps({"dependencies": {"react": "18.3.1"}}))
        escribir(self.dir, "server/index.js", "module.exports = 1;\n")
        res = ri.analizar(self.dir)
        self.assertEqual(res["estado"], "no_evaluado")
        self.assertNotIn("SPA", res["motivo"])
        self.assertIn("server/", res["motivo"])

    def test_python_backend_en_requirements_no_es_spa(self):
        escribir(self.dir, "requirements.txt", "django==5.0\n")
        escribir(self.dir, "app/views.py", "x = 1\n")
        res = ri.analizar(self.dir)
        self.assertNotIn("SPA", res["motivo"])


if __name__ == "__main__":
    unittest.main()
