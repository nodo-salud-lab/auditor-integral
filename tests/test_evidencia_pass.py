"""Sin «pases vacíos» (regla general sobre TODO el catálogo).

Un control solo queda `pass` con evidencia positiva de que se evaluó:
  evidencia_pass = "ausencia_suficiente"     la herramienta cubre el control completo y su ausencia de hallazgos
                                             vale como evidencia, SIEMPRE que haya analizado ≥ 1 objeto relevante
                                             (alcance_requerido = ["herramienta.clave"], registrado en su meta).
                                             Alcance 0 → `sin_alcance` (no_aplica | no_evaluado) con su motivo.
  evidencia_pass = "checks_pass"             requiere un pase explícito en checks_pass (default si falta: fail-closed).
  evidencia_pass = "no_demostrable_estatico" no puede pasar en análisis estático: no_evaluado con motivo
                                             «requiere juicio LLM / sonda dinámica / entrevista».
Los hallazgos siguen dando fail en las tres categorías.
"""
import json
import os
import re
import subprocess
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "scripts" / "adaptadores"))

import alcance  # noqa: E402
import archivos_clave  # noqa: E402
import catalogo  # noqa: E402
import detectar_stack as ds  # noqa: E402
import estado  # noqa: E402
import render_informe  # noqa: E402
import utiles  # noqa: E402

CATEGORIAS = {"ausencia_suficiente", "checks_pass", "no_demostrable_estatico"}
FECHA = "2026-11-18"
# Los 19 «pases vacíos» conocidos: los 8 citados en la tarea (SEG-SECRETO-BUNDLE, DAT-PAGINACION, SEG-CSRF,
# SEG-COOKIES, SEG-JWT, SEG-SSRF, SEG-CORS, SEG-VALIDACION), los 9 de la re-auditoría de kine (AUD-INF y
# exige_checks_pass, REAUDITORIA.md §3.3) y los dos semgrep-only restantes de N3 (SEG-MASIVA, SEG-ERRORES).
DIECINUEVE = ("SEG-SECRETO-BUNDLE", "DAT-PAGINACION", "SEG-CSRF", "SEG-COOKIES", "SEG-JWT", "SEG-SSRF", "SEG-CORS",
              "SEG-VALIDACION", "SEG-MASIVA", "SEG-ERRORES", "SEG-RATELIMIT", "DAT-N+1", "INF-TIMEOUTS-SALIDA",
              "OPS-LOGS-ESTRUCTURADOS", "INF-REGION", "INF-IAC-REPRO", "OPS-HEALTH", "OPS-OTEL-RED",
              "OPS-REAUDITORIA")


def cat():
    return {c["id"]: c for c in catalogo.cargar_catalogo()}


def deterministas(c):
    return [h for h in c.get("herramientas", []) if not estado.es_agente_llm(h)
            and h not in estado.COMPONENTES_ENTREVISTA and h not in estado.COMPONENTES_MANUALES]


def literal(patron):
    """Una regla concreta que cumple el patrón fnmatch (para simular un pase explícito)."""
    return patron.replace("*", "x").replace("?", "x")


def aplicable(c):
    d = dict(c)
    d["aplicabilidad"] = "aplica"
    return d


def calc(c, herr=None, checks=(), alcance_=None, hallazgos=()):
    herr = herr if herr is not None else {utiles.canon_herramienta(h): "ok" for h in deterministas(c)}
    return estado.calcular({c["id"]: aplicable(c)}, list(hallazgos), herr, set(checks), "profundo", FECHA,
                           alcance=alcance_)[0]


def alcance_lleno(c, valor=5):
    res = {}
    # Ronda 1: también las claves de alcance_condicional (p. ej. gitleaks.historial / gitleaks.commits): «lleno» es
    # todo el alcance que el control puede exigir.
    reqs = list(c.get("alcance_requerido", []))
    for cond in c.get("alcance_condicional", []):
        reqs += [cond["requiere"], cond["si"]]
    for req in reqs:
        h, clave = req.split(".", 1)
        res.setdefault(utiles.canon_herramienta(h), {})[clave] = valor
    # Ronda 3: las claves de alcance_excluyente se registran siempre (en 0 = todo cubierto); una ausente bloquea el pass.
    for ex in c.get("alcance_excluyente", []):
        h, clave = ex["clave"].split(".", 1)
        res.setdefault(utiles.canon_herramienta(h), {})[clave] = 0
    return res


# ------------------------------------------------------------------------------------------- catálogo
class TestCatalogoEvidencia(unittest.TestCase):
    def setUp(self):
        self.cat = cat()

    def test_todos_declaran_evidencia_pass(self):
        sin = [cid for cid, c in self.cat.items() if c.get("evidencia_pass") not in CATEGORIAS]
        self.assertEqual(sin, [])

    def test_cada_control_justifica_su_eleccion_con_un_comentario(self):
        texto = (RAIZ / "catalogo" / "controles.toml").read_text(encoding="utf-8")
        bloques = texto.split("[[control]]")[1:]
        self.assertEqual(len(bloques), len(self.cat))
        for b in bloques:
            cid = re.search(r'^id = "([^"]+)"', b, re.M).group(1)
            with self.subTest(control=cid):
                m = re.search(r"^# evidencia_pass: (.{20,})$", b, re.M)
                self.assertIsNotNone(m, "falta el comentario «# evidencia_pass: <justificación>»")

    def test_ausencia_suficiente_exige_precondicion_de_alcance(self):
        for cid, c in self.cat.items():
            if c["evidencia_pass"] != "ausencia_suficiente":
                continue
            with self.subTest(control=cid):
                req = c.get("alcance_requerido")
                self.assertTrue(req, "ausencia_suficiente sin alcance_requerido")
                completas = set(deterministas(c)) - set(c.get("herramientas_parciales", []))
                for r in req:
                    h, _, clave = r.partition(".")
                    self.assertIn(h, completas, f"{r}: la herramienta debe ser completa (no parcial) del control")
                    self.assertTrue(clave)
                self.assertIn(c.get("sin_alcance"), ("no_aplica", "no_evaluado"))
                self.assertTrue(c.get("motivo_sin_alcance"))

    def test_campos_de_alcance_solo_en_ausencia_suficiente(self):
        for cid, c in self.cat.items():
            if c["evidencia_pass"] != "ausencia_suficiente":
                with self.subTest(control=cid):
                    for k in ("alcance_requerido", "sin_alcance", "motivo_sin_alcance"):
                        self.assertNotIn(k, c)

    def test_juicio_entrevista_manual_y_legal_son_no_demostrables(self):
        for cid, c in self.cat.items():
            herrs = c.get("herramientas", [])
            if (c["metodo"] in ("llm", "manual") or c.get("aviso_legal")
                    or any(estado.es_agente_llm(h) or h in estado.COMPONENTES_ENTREVISTA
                           or h in estado.COMPONENTES_MANUALES for h in herrs)):
                with self.subTest(control=cid):
                    self.assertEqual(c["evidencia_pass"], "no_demostrable_estatico")

    def test_exige_checks_pass_coherente(self):
        for cid, c in self.cat.items():
            if c.get("exige_checks_pass"):
                with self.subTest(control=cid):
                    self.assertNotEqual(c["evidencia_pass"], "ausencia_suficiente")

    def test_los_19_conocidos_no_son_ausencia_suficiente_salvo_bundle(self):
        for cid in DIECINUEVE:
            with self.subTest(control=cid):
                c = self.cat[cid]
                if cid == "SEG-SECRETO-BUNDLE":  # gitleaks cubre el bundle: vale la ausencia, con ≥ 1 bundle
                    self.assertEqual(c["evidencia_pass"], "ausencia_suficiente")
                    self.assertEqual(c["alcance_requerido"], ["gitleaks.bundles"])
                    self.assertEqual(c["sin_alcance"], "no_aplica")
                    self.assertEqual(c["motivo_sin_alcance"], "sin bundle")
                else:
                    self.assertNotEqual(c["evidencia_pass"], "ausencia_suficiente")

    def test_semgrep_solo_no_es_ausencia_salvo_sast_declarado(self):
        # Regla 3: si el único soporte determinista son reglas semgrep, el control no puede pasar por ausencia,
        # salvo los SAST de patrones (SEG-SAST-INY, DAT-SQL-CONCATENADO), con alcance ≥ 1 archivo fuente.
        excepciones = {"SEG-SAST-INY", "DAT-SQL-CONCATENADO"}
        for cid, c in self.cat.items():
            completas = set(deterministas(c)) - set(c.get("herramientas_parciales", []))
            if completas == {"semgrep"} and cid not in excepciones:
                with self.subTest(control=cid):
                    self.assertNotEqual(c["evidencia_pass"], "ausencia_suficiente")
        # Ronda 1: DAT-SQL-CONCATENADO exige archivos con consultas SQL (semgrep.consultas_sql, subconjunto de fuentes).
        self.assertEqual(self.cat["SEG-SAST-INY"]["alcance_requerido"], ["semgrep.fuentes"])
        self.assertEqual(self.cat["DAT-SQL-CONCATENADO"]["alcance_requerido"], ["semgrep.consultas_sql"])


# --------------------------------------------------------------------- (a) recorrido parametrizado del catálogo
class TestNingunPaseSinEvidencia(unittest.TestCase):
    """(a) Recorre TODO el catálogo: con todas sus herramientas deterministas ok, sin hallazgos, sin checks_pass y
    con alcance lleno, solo un control `ausencia_suficiente` puede quedar en pass."""

    def test_sin_checks_pass_solo_pasa_ausencia_suficiente(self):
        for cid, c in cat().items():
            with self.subTest(control=cid):
                r = calc(c, alcance_=alcance_lleno(c))
                if c["evidencia_pass"] != "ausencia_suficiente":
                    self.assertNotEqual(r["estado"], "pass", r)

    def test_ausencia_suficiente_pasa_con_alcance_y_no_sin_el(self):
        for cid, c in cat().items():
            if c["evidencia_pass"] != "ausencia_suficiente" or c.get("aviso_legal"):
                continue
            with self.subTest(control=cid):
                self.assertEqual(calc(c, alcance_=alcance_lleno(c))["estado"], "pass")
                r0 = calc(c, alcance_=alcance_lleno(c, 0))
                self.assertEqual(r0["estado"], c["sin_alcance"], r0)
                self.assertIn(c["motivo_sin_alcance"], r0["motivo"])
                rn = calc(c, alcance_={})  # la herramienta no registró su alcance: fail-closed
                self.assertEqual(rn["estado"], "no_evaluado", rn)
                self.assertIn("alcance", rn["motivo"])

    def test_checks_pass_pasa_solo_con_pase_explicito(self):
        for cid, c in cat().items():
            if c["evidencia_pass"] != "checks_pass" or not c["mapea_reglas"] or c.get("aviso_legal"):
                continue
            with self.subTest(control=cid):
                self.assertNotEqual(calc(c)["estado"], "pass")
                r = calc(c, checks={literal(p) for p in c["mapea_reglas"]})
                self.assertEqual(r["estado"], "pass", r)

    def test_no_demostrable_nunca_pasa_ni_con_pase_explicito(self):
        for cid, c in cat().items():
            if c["evidencia_pass"] != "no_demostrable_estatico":
                continue
            with self.subTest(control=cid):
                r = calc(c, checks={literal(p) for p in c["mapea_reglas"]}, alcance_={})
                self.assertNotEqual(r["estado"], "pass", r)
                if r["estado"] == "no_evaluado" and c["metodo"] in ("determinista", "mixto") and deterministas(c) \
                        and not any(estado.es_agente_llm(h) or h in estado.COMPONENTES_ENTREVISTA
                                    for h in c["herramientas"]):
                    self.assertIn("no demostrable en análisis estático", r["motivo"])
                    # Ronda 9: un control puede declarar su propio motivo_no_demostrable (DAT-PII-REPO).
                    self.assertIn(c.get("motivo_no_demostrable") or "juicio LLM / sonda dinámica / entrevista",
                                  r["motivo"])

    def test_hallazgo_sigue_dando_fail_en_las_tres_categorias(self):
        for cid, c in cat().items():
            if c["metodo"] == "manual" and not c["herramientas"]:
                continue
            with self.subTest(control=cid):
                h = {"id": "H-abcdef", "control": cid, "severidad": "alta", "gate": c["gate"]}
                self.assertEqual(calc(c, hallazgos=[h])["estado"], "fail")

    def test_falta_el_campo_es_checks_pass(self):
        c = {"id": "SEG-X", "titulo": "x", "dominio": "SEG", "gate": "N2", "metodo": "determinista",
             "herramientas": ["semgrep"], "condicion": "siempre", "mapea_reglas": ["semgrep:x"]}
        self.assertEqual(calc(c)["estado"], "no_evaluado")
        self.assertEqual(calc(c, checks={"semgrep:x"})["estado"], "pass")


# ------------------------------------------------------------------------------ (b) proyecto sin bundle
class Tmp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def escribir(self, rel, contenido=""):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contenido, encoding="utf-8")
        return p


class TestSinBundle(Tmp):
    def test_calcular_sin_bundle_es_no_aplica(self):
        c = cat()["SEG-SECRETO-BUNDLE"]
        r = calc(c, herr={"gitleaks": "ok", "semgrep": "ok"},
                 alcance_={"gitleaks": {"arbol": 12, "historial": 1, "bundles": 0}})
        self.assertEqual(r["estado"], "no_aplica")
        self.assertIn("sin bundle", r["motivo"])

    def test_con_bundle_escaneado_pasa(self):
        c = cat()["SEG-SECRETO-BUNDLE"]
        r = calc(c, herr={"gitleaks": "ok", "semgrep": "ok"}, alcance_={"gitleaks": {"bundles": 1}})
        self.assertEqual(r["estado"], "pass")
        self.assertEqual(r["herramienta"], "gitleaks")

    def test_generar_lee_el_alcance_del_meta(self):
        corrida = self.dir / "corrida"
        crudo = corrida / "crudo"
        crudo.mkdir(parents=True)
        (corrida / "run.json").write_text(json.dumps({"id": "x", "modo": "estandar", "fases": {}}), encoding="utf-8")
        (corrida / "normalizacion.json").write_text(json.dumps({"checks_pass": []}), encoding="utf-8")
        (corrida / "hallazgos.jsonl").write_text("", encoding="utf-8")
        (crudo / "gitleaks.json").write_text("[]", encoding="utf-8")
        (crudo / "gitleaks.meta.json").write_text(json.dumps(
            {"herramienta": "gitleaks", "estado": "ok",
             "alcance": {"arbol": 3, "historial": 1, "bundles": 0, "codigo_confidencial": 0}}),
            encoding="utf-8")
        self.assertEqual(estado.alcance_herramientas(corrida)["gitleaks"]["bundles"], 0)
        datos = estado.generar(corrida)
        r = {x["control"]: x for x in datos["controles"]}
        self.assertEqual(r["SEG-SECRETO-BUNDLE"]["estado"], "no_aplica")
        self.assertEqual(r["SEG-SECRETO-REPO"]["estado"], "pass")

    @unittest.skipUnless(shutil.which("gitleaks"), "gitleaks no instalado")
    def test_adaptador_gitleaks_registra_el_alcance(self):
        self.escribir("src/app.js", "console.log(1)\n")
        crudo = self.dir.parent / (self.dir.name + "-crudo")
        try:
            subprocess.run(["bash", str(RAIZ / "scripts" / "adaptadores" / "gitleaks.sh"), str(self.dir), str(crudo)],
                           check=True, capture_output=True, timeout=120)
            meta = json.loads((crudo / "gitleaks.meta.json").read_text(encoding="utf-8"))
            self.assertEqual(meta["alcance"]["bundles"], 0)
            self.assertGreaterEqual(meta["alcance"]["arbol"], 1)
            self.escribir("dist/index.js", "var a=1\n")
            subprocess.run(["bash", str(RAIZ / "scripts" / "adaptadores" / "gitleaks.sh"), str(self.dir), str(crudo)],
                           check=True, capture_output=True, timeout=120)
            meta = json.loads((crudo / "gitleaks.meta.json").read_text(encoding="utf-8"))
            self.assertEqual(meta["alcance"]["bundles"], 1)
        finally:
            shutil.rmtree(crudo, ignore_errors=True)


# ------------------------------------------------------------------------------------ alcance.py
class TestAlcance(Tmp):
    def test_cuenta_fuentes_lockfiles_y_workflows_sin_dependencias(self):
        self.escribir("src/a.ts", "x")
        self.escribir("src/b.jsx", "x")
        self.escribir("README.md", "x")
        self.escribir("node_modules/z/index.js", "x")
        self.escribir("package-lock.json", "{}")
        self.escribir("node_modules/z/package-lock.json", "{}")
        self.escribir(".github/workflows/ci.yml", "on: push")
        self.escribir("dist/x.js", "x")
        a = alcance.calcular(self.dir)
        self.assertEqual(a["fuentes"], 2)
        self.assertEqual(a["lockfiles"], 1)
        self.assertEqual(a["workflows"], 1)
        self.assertEqual(a["arbol"], 5)  # a.ts, b.jsx, README, package-lock, ci.yml (sin node_modules ni dist)

    def test_no_recorre_carpetas_confidenciales(self):
        conf = self.dir / "conf.toml"
        conf.write_text('carpetas = ["privado"]\narchivos = []\n', encoding="utf-8")
        self.escribir("privado/secreto.py", "x")
        self.escribir("datos-reales/otro.py", "x")  # default confidencial: tampoco se recorre
        self.escribir("src/a.py", "x")
        self.assertEqual(alcance.calcular(self.dir, confidencial=conf)["fuentes"], 1)

    def test_cli_imprime_json(self):
        self.escribir("src/a.py", "x")
        out = subprocess.run([sys.executable, str(RAIZ / "scripts" / "adaptadores" / "alcance.py"), str(self.dir)],
                             check=True, capture_output=True, text=True).stdout
        self.assertEqual(json.loads(out)["fuentes"], 1)


# ------------------------------------------------------------------------------ (c) fixture express + pg
class TestExpressPg(Tmp):
    """(c) Un backend express+pg sin bundle, con un endpoint que devuelve todas las filas: con todas las herramientas
    deterministas ok y sin hallazgos, ninguno de los 19 controles pasa."""

    def setUp(self):
        super().setUp()
        self.escribir("package.json", json.dumps({"name": "api", "dependencies": {"express": "4.21.2", "pg": "8.11.0"}}))
        self.escribir("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {}}))
        self.escribir("server/index.js",
                      "import express from 'express'\nimport pg from 'pg'\nconst pool = new pg.Pool()\n"
                      "const app = express()\napp.use(express.json())\n"
                      "app.get('/api/pacientes', async (req, res) => {\n"
                      "  const r = await pool.query('SELECT * FROM pacientes')\n  res.json(r.rows)\n})\n"
                      "app.listen(3000)\n")
        self.escribir("README.md", "# api\n")

    def test_ninguno_de_los_19_pasa(self):
        tec = ds.detectar(self.dir)
        perfil = {"banderas": {k: tec.get(k) for k in utiles.BANDERAS_ARCHIVOS}, "origen": "perfil_tecnico"}
        self.assertTrue(perfil["banderas"].get("servidor"))
        indice = utiles.indice_controles(perfil)
        herr = {}
        for c in indice.values():
            for h in deterministas(c):
                herr[utiles.canon_herramienta(h)] = "ok"
        a = alcance.calcular(self.dir)
        al = {"gitleaks": {"arbol": a["arbol"], "historial": 0, "bundles": 0},
              "osv-scanner": {"lockfiles": a["lockfiles"]}, "semgrep": {"fuentes": a["fuentes"]},
              "zizmor": {"workflows": a["workflows"]}}
        pases = {p["regla"] for p in archivos_clave.analizar(self.dir)["checks_pass"]}
        r = {x["control"]: x for x in estado.calcular(indice, [], herr, pases, "profundo", FECHA, alcance=al)}
        for cid in DIECINUEVE:
            with self.subTest(control=cid):
                self.assertNotEqual(r[cid]["estado"], "pass", r[cid])
        self.assertEqual(r["SEG-SECRETO-BUNDLE"]["estado"], "no_aplica")
        self.assertEqual(r["DAT-PAGINACION"]["estado"], "no_evaluado")
        self.assertIn("no demostrable en análisis estático", r["DAT-PAGINACION"]["motivo"])


# ------------------------------------------------------------------------------ (d) conteo de cambios
class TestConteo(unittest.TestCase):
    def test_conteo_por_categoria_y_cambios(self):
        r = catalogo.conteo_evidencia_pass()
        self.assertEqual(sum(r["por_categoria"].values()), len(cat()))
        self.assertEqual(set(r["por_categoria"]), CATEGORIAS)
        # Antes, todo control sin exige_checks_pass podía pasar por la mera ejecución (equivale a
        # ausencia_suficiente sin precondición); cambia de categoría todo el que ya no es ausencia_suficiente.
        antes = {cid for cid, c in cat().items() if not c.get("exige_checks_pass")}
        cambiaron = sorted(cid for cid in antes if cat()[cid]["evidencia_pass"] != "ausencia_suficiente")
        self.assertEqual(r["cambiaron"], cambiaron)
        print(f"\n[conteo evidencia_pass] {r['por_categoria']} · cambiaron de categoría: {len(cambiaron)}",
              file=sys.stderr)


# ------------------------------------------------------------------------------ informe
class TestInforme(unittest.TestCase):
    def test_seccion_no_demostrable(self):
        indice = cat()
        estados = [{"control": "DAT-PAGINACION", "estado": "no_evaluado", "motivo": "no demostrable…"},
                   {"control": "SEG-IDOR", "estado": "no_evaluado", "motivo": "juicio LLM no ejecutado en F1"},
                   {"control": "OPS-RPO-RTO", "estado": "no_evaluado", "motivo": "entrevista"},
                   {"control": "SEG-SECRETO-REPO", "estado": "pass", "motivo": None},
                   {"control": "SEG-PENTEST", "estado": "manual_pendiente", "motivo": None}]
        texto = render_informe._seccion_no_demostrable(estados, indice)
        self.assertIn("3 controles", texto)
        self.assertIn("no demostrable en estático", texto)
        for clave in ("F3", "F4", "entrevista"):
            self.assertIn(clave, texto)
        self.assertIn("DAT-PAGINACION", texto)

    def test_plantilla_lo_incluye_en_cobertura(self):
        t = (RAIZ / "plantillas" / "informe.md.tmpl").read_text(encoding="utf-8")
        i_cob = t.index("### Cobertura por nivel")
        i_iua = t.index("### Índice de Usabilidad")
        self.assertTrue(i_cob < t.index("$no_demostrable") < i_iua)


if __name__ == "__main__":
    unittest.main()
