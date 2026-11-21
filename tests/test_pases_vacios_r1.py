"""Ronda 1 de pases vacíos (fail-closed): ningún control queda `pass` sin evidencia positiva de que se evaluó algo
relevante. Cada clase reproduce un pase vacío detectado tras la re-auditoría 2 (REAUDITORIA.md §R2.7).

  A  SEG-SAST-INY / DAT-SQL-CONCATENADO: el alcance sale de paths.scanned de semgrep (no de un recorrido propio que
     ignora sus exclusiones) y el código en tests/ SÍ se escanea (decisión de seguridad: una carpeta `test/` puede
     ser código desplegado, p. ej. app/api/test/route.ts), pero no cuenta como alcance de código de producción.
  B  solo cuentan archivos de lenguajes que cubren los rulesets (no .sh, .yaml, .json).
  C  DAT-SQL-CONCATENADO sin consultas SQL en el código → no_aplica.
  D  INF-INVENTARIO con inventario vacío no pasa.
  E  SEG-ENV-PUBLICAS sin .env* ni código que lea variables de entorno → no_aplica.
  F  DAT-PII-REPO sin repositorio git → no_aplica; sin candidatos, pass solo con ≥ 1 archivo versionado evaluado.
  G  COD-CI-BASICO: el pase exige que el CI ejecute lint/typecheck/tests (comprobación semántica que corre siempre,
     también con actionlint instalado).
  H  SEG-SECRETO-REPO: en un repo git con commits exige historial > 0.
  I  COD-TESTS-HUMO, DAT-ESQUEMA-VERSIONADO, SEG-AGENTES-IA, SEG-CORS/COOKIES/CSRF: sin pases imposibles.
  J  el tope de 5 por (control, archivo) nunca descarta críticos de N1; metricas.py advierte si recibe el archivo
     con tope.
  K  osv.meta.json registra la fecha de consulta de la base OSV.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "scripts" / "adaptadores"))
sys.path.insert(0, str(RAIZ / "validacion"))

import alcance  # noqa: E402
import archivos_clave  # noqa: E402
import catalogo  # noqa: E402
import config_agentes  # noqa: E402
import datos_confidenciales as dc  # noqa: E402
import env_publicas  # noqa: E402
import estado  # noqa: E402
import metricas  # noqa: E402
import utiles  # noqa: E402
import workflows  # noqa: E402
from normalizar import comun as ncomun  # noqa: E402

ADAPT = RAIZ / "scripts" / "adaptadores"
FECHA = "2026-11-18"


def cat():
    return {c["id"]: c for c in catalogo.cargar_catalogo()}


def calc(cid, herr, checks=(), alcance_=None, hallazgos=(), motivos=None):
    c = dict(cat()[cid], aplicabilidad="aplica")
    kw = {"motivos": motivos} if motivos is not None else {}
    return estado.calcular({cid: c}, list(hallazgos), herr, set(checks), "profundo", FECHA, alcance=alcance_, **kw)[0]


def git(proy, *args):
    ident = ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
    return subprocess.run(["git", *ident, "-C", str(proy), *args], capture_output=True, text=True, check=True)


class Tmp(unittest.TestCase):
    """Carpeta temporal FUERA del repositorio del auditor (para que «sin git» sea de verdad sin git)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name).resolve()
        self.addCleanup(self._tmp.cleanup)

    def escribir(self, rel, contenido=""):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contenido, encoding="utf-8")
        return p


# ------------------------------------------------------------------------------------------- A, B, C
class TestAlcanceDesdeSemgrep(Tmp):
    def json_semgrep(self, escaneados):
        return {"version": "1.181.0", "results": [], "errors": [], "paths": {"scanned": escaneados}}

    def test_solo_tests_no_es_alcance_de_produccion(self):
        self.escribir("tests/a.js", "eval(x)\n")
        a = alcance.desde_semgrep(self.json_semgrep(["tests/a.js"]), self.dir)
        self.assertEqual(a["fuentes"], 0)
        self.assertEqual(a["fuentes_test"], 1)

    def test_archivos_de_test_por_nombre(self):
        for rel in ("src/a.test.ts", "src/b.spec.jsx", "pkg/x_test.go", "app/test_util.py", "src/__tests__/c.js"):
            self.escribir(rel, "x\n")
        a = alcance.desde_semgrep(self.json_semgrep(
            ["src/a.test.ts", "src/b.spec.jsx", "pkg/x_test.go", "app/test_util.py", "src/__tests__/c.js"]), self.dir)
        self.assertEqual(a["fuentes"], 0)
        self.assertEqual(a["fuentes_test"], 5)

    def test_shell_yaml_json_no_cuentan(self):
        for rel in ("s.sh", "c.yaml", "d.json", "i.html", "Dockerfile", "m.tf"):
            self.escribir(rel, "x\n")
        a = alcance.desde_semgrep(self.json_semgrep(["s.sh", "c.yaml", "d.json", "i.html", "Dockerfile", "m.tf"]),
                                  self.dir)
        self.assertEqual(a["fuentes"], 0)

    def test_lenguajes_cubiertos_cuentan(self):
        rels = ["src/a.ts", "src/b.tsx", "api/c.py", "cmd/d.go", "e.java", "f.php", "g.rb", "h.mjs"]
        for rel in rels:
            # ronda 2: Python cuenta solo con un framework que el ruleset cubre (Flask/Django/Pyramid/Lambda)
            self.escribir(rel, "from flask import Flask\n" if rel.endswith(".py") else "x\n")
        self.assertEqual(alcance.desde_semgrep(self.json_semgrep(rels), self.dir)["fuentes"], len(rels))

    def test_consultas_sql(self):
        self.escribir("server/db.js", "const q = 'SELECT * FROM citas WHERE id = ' + req.params.id\n")
        self.escribir("server/b.js", "await pool.query(sql)\n")
        self.escribir("src/c.jsx", "const x = 1; // select the first item from list\n")
        self.escribir("tests/d.js", "db.query('DELETE FROM t')\n")
        a = alcance.desde_semgrep(self.json_semgrep(["server/db.js", "server/b.js", "src/c.jsx", "tests/d.js"]),
                                  self.dir)
        self.assertEqual(a["fuentes"], 3)
        self.assertEqual(a["consultas_sql"], 2)

    def test_sin_consultas_sql(self):
        self.escribir("src/a.ts", "export const sumar = (a: number, b: number) => a + b\nuseQuery(['x'])\n")
        self.assertEqual(alcance.desde_semgrep(self.json_semgrep(["src/a.ts"]), self.dir)["consultas_sql"], 0)

    def test_sin_paths_es_none_fail_closed(self):
        self.assertIsNone(alcance.desde_semgrep({"results": []}, self.dir))
        self.assertIsNone(alcance.desde_semgrep({"paths": {}}, self.dir))
        self.assertIsNone(alcance.desde_semgrep([], self.dir))

    def test_no_lee_fuera_del_proyecto(self):
        a = alcance.desde_semgrep(self.json_semgrep(["../../etc/passwd.js", "/etc/x.js"]), self.dir)
        self.assertEqual(a["fuentes"], 0)
        self.assertEqual(a["consultas_sql"], 0)

    def test_cli_semgrep_json(self):
        self.escribir("src/a.js", "db.query('SELECT 1')\n")
        js = self.dir / "s.json"
        js.write_text(json.dumps(self.json_semgrep(["src/a.js"])), encoding="utf-8")
        out = subprocess.run([sys.executable, str(ADAPT / "alcance.py"), str(self.dir), "--semgrep-json", str(js)],
                             check=True, capture_output=True, text=True).stdout
        # Ronda 3: las claves sin_reglas se registran siempre (también en 0); una ausente bloquea el pass (fail-closed).
        # Ronda 4: también fuentes_no_escaneadas (= fuentes_grandes + fuentes_confidenciales), siempre registrada.
        self.assertEqual(json.loads(out), {"fuentes": 1, "fuentes_test": 0, "consultas_sql": 1,
                                           "fuentes_sin_reglas": 0, "consultas_sql_sin_reglas": 0,
                                           "fuentes_grandes": 0, "fuentes_confidenciales": 0,
                                           "fuentes_no_escaneadas": 0})


class TestEstadoSast(unittest.TestCase):
    def test_sast_sin_fuentes_es_no_aplica(self):
        r = calc("SEG-SAST-INY", {"semgrep": "ok"}, alcance_={"semgrep": {"fuentes": 0, "fuentes_test": 3}})
        self.assertEqual(r["estado"], "no_aplica")

    def test_sql_sin_consultas_es_no_aplica(self):
        r = calc("DAT-SQL-CONCATENADO", {"semgrep": "ok"},
                 alcance_={"semgrep": {"fuentes": 40, "consultas_sql": 0}})
        self.assertEqual(r["estado"], "no_aplica", r)
        self.assertIn("sin consultas SQL", r["motivo"])

    def test_sql_con_consultas_pasa(self):
        # Ronda 3: alcance completo, con la clave excluyente registrada (en 0); sin ella → no_evaluado (r3).
        r = calc("DAT-SQL-CONCATENADO", {"semgrep": "ok"},
                 alcance_={"semgrep": {"fuentes": 40, "consultas_sql": 2, "consultas_sql_sin_reglas": 0,
                                       "fuentes_no_escaneadas": 0}})
        self.assertEqual(r["estado"], "pass")

    def test_sql_alcance_antiguo_sin_consultas_es_no_evaluado(self):
        r = calc("DAT-SQL-CONCATENADO", {"semgrep": "ok"}, alcance_={"semgrep": {"fuentes": 40}})
        self.assertEqual(r["estado"], "no_evaluado")

    def test_hallazgo_sql_da_fail_aunque_no_haya_consultas(self):
        h = {"id": "H-1", "control": "DAT-SQL-CONCATENADO", "severidad": "critica", "gate": "N1"}
        r = calc("DAT-SQL-CONCATENADO", {"semgrep": "ok"}, alcance_={"semgrep": {"fuentes": 1, "consultas_sql": 0}},
                 hallazgos=[h])
        self.assertEqual(r["estado"], "fail")


@unittest.skipUnless(shutil.which("semgrep"), "semgrep no instalado")
class TestAdaptadorSemgrep(Tmp):
    def correr(self):
        crudo = self.dir.parent / (self.dir.name + "-crudo")
        self.addCleanup(shutil.rmtree, crudo, ignore_errors=True)
        env = dict(os.environ, AUDITOR_SEMGREP_REGISTRO="")
        subprocess.run(["bash", str(ADAPT / "semgrep.sh"), str(self.dir / "p"), str(crudo)], check=True,
                       capture_output=True, timeout=300, env=env)
        meta = json.loads((crudo / "semgrep.meta.json").read_text(encoding="utf-8"))
        sarif = json.loads((crudo / "semgrep.sarif").read_text(encoding="utf-8"))
        return meta, sarif

    def test_solo_tests_escanea_pero_alcance_cero(self):
        self.escribir("p/tests/a.js", "router.post('/x', (req, res) => { res.json(eval(req.body.f)) })\n")
        meta, sarif = self.correr()
        self.assertEqual(meta["estado"], "ok", meta)
        self.assertEqual(meta["alcance"]["fuentes"], 0)
        self.assertEqual(meta["alcance"]["fuentes_test"], 1)
        # decisión de seguridad: tests/ NO se excluye; el hallazgo se reporta
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)

    def test_solo_shell_alcance_cero(self):
        self.escribir("p/deploy.sh", "echo hola\n")
        meta, _ = self.correr()
        self.assertEqual(meta["alcance"]["fuentes"], 0)

    def test_codigo_de_produccion_cuenta(self):
        self.escribir("p/server/db.js", "pool.query('SELECT * FROM t WHERE id = ' + req.params.id)\n")
        meta, _ = self.correr()
        self.assertEqual(meta["alcance"]["fuentes"], 1)
        self.assertEqual(meta["alcance"]["consultas_sql"], 1)
        self.assertNotIn("tests", meta.get("exclusiones", []))


# --------------------------------------------------------------------------------------------- D
class TestInventario(Tmp):
    def corrida(self, tecnico):
        c = self.dir / "corrida"
        (c / "crudo").mkdir(parents=True)
        (c / "run.json").write_text(json.dumps({"id": "x", "modo": "estandar", "fases": {}}), encoding="utf-8")
        (c / "normalizacion.json").write_text(json.dumps({"checks_pass": []}), encoding="utf-8")
        (c / "hallazgos.jsonl").write_text("", encoding="utf-8")
        (c / "perfil_tecnico.json").write_text(json.dumps(tecnico), encoding="utf-8")
        return {x["control"]: x for x in estado.generar(c)["controles"]}

    def test_inventario_vacio_no_pasa(self):
        r = self.corrida({"lenguajes": [], "frameworks": [], "bd": False})
        self.assertNotEqual(r["INF-INVENTARIO"]["estado"], "pass")
        self.assertEqual(r["INF-INVENTARIO"]["estado"], "no_evaluado")

    def test_inventario_con_lenguajes_pasa(self):
        # Ronda 3 (PV-R2-08): el título pide también la plataforma de despliegue; sin ella ver test_pases_vacios_r3.
        r = self.corrida({"lenguajes": ["javascript"], "frameworks": [], "bd": False,
                          "plataformas_despliegue": ["vercel"]})
        self.assertEqual(r["INF-INVENTARIO"]["estado"], "pass")

    def test_inventario_con_frameworks_pasa(self):
        r = self.corrida({"lenguajes": [], "frameworks": ["react"], "bd": False, "plataformas_despliegue": ["netlify"]})
        self.assertEqual(r["INF-INVENTARIO"]["estado"], "pass")


# --------------------------------------------------------------------------------------------- E
class TestEnvPublicas(Tmp):
    def test_proyecto_vacio_es_no_aplica(self):
        r = env_publicas.analizar(self.dir)
        self.assertEqual(r["estado"], "no_aplica")
        self.assertEqual(r["checks_pass"], [])
        self.assertTrue(r["motivo"])

    def test_codigo_sin_variables_de_entorno_es_no_aplica(self):
        self.escribir("src/a.js", "console.log(1)\n")
        r = env_publicas.analizar(self.dir)
        self.assertEqual(r["estado"], "no_aplica")
        self.assertEqual(r["checks_pass"], [])

    def test_codigo_con_variables_publicas_pasa(self):
        self.escribir("src/a.js", "const u = import.meta.env.VITE_SUPABASE_URL\n")
        r = env_publicas.analizar(self.dir)
        self.assertEqual(r["estado"], "ok")
        self.assertEqual([p["regla"] for p in r["checks_pass"]], ["check:env_publicas.nombre_sensible"])

    def test_estado_no_aplica_con_motivo_del_check(self):
        r = calc("SEG-ENV-PUBLICAS", {"env_publicas": "no_aplica"},
                 motivos={"env_publicas": "sin archivos .env* ni código que lea variables de entorno"})
        self.assertEqual(r["estado"], "no_aplica")
        self.assertIn("sin archivos .env*", r["motivo"])


# --------------------------------------------------------------------------------------------- F
@unittest.skipUnless(shutil.which("git"), "git no instalado")
class TestPiiRepo(Tmp):
    def test_sin_git_es_no_aplica(self):
        self.escribir("src/app.js", "console.log(1)\n")
        r = dc.analizar(self.dir)
        self.assertEqual(r["estado"], "no_aplica", r)
        self.assertIn("sin repositorio git", r["motivo"])
        self.assertEqual(r["checks_pass"], [])

    def test_sin_git_con_candidatos_tambien_no_aplica_y_conserva_inventario(self):
        self.escribir("datos-reales/p.csv", "x\n")
        r = dc.analizar(self.dir)
        self.assertEqual(r["estado"], "no_aplica")
        self.assertEqual([i["ruta"] for i in r["inventario"]], ["datos-reales"])

    def test_repo_sin_candidatos_con_versionados_pasa(self):
        self.escribir("src/app.js", "console.log(1)\n")
        self.escribir("README.md", "x\n")
        git(self.dir, "init", "-q")
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", "x")
        r = dc.analizar(self.dir)
        self.assertEqual(r["estado"], "ok")
        pases = [p for p in r["checks_pass"] if p["regla"] == "check:datos_confidenciales.no_trackeado"]
        self.assertEqual(len(pases), 1)
        self.assertIn("2 archivos versionados", pases[0]["mensaje"])

    def test_repo_sin_versionados_ni_candidatos_no_aplica(self):
        self.escribir("src/app.js", "console.log(1)\n")
        git(self.dir, "init", "-q")
        r = dc.analizar(self.dir)
        self.assertEqual(r["estado"], "no_aplica", r)
        self.assertEqual(r["checks_pass"], [])

    def test_repo_con_candidatos_ignorados_pasa(self):
        self.escribir("datos-reales/p.csv", "x\n")
        self.escribir(".gitignore", "datos-reales/\n")
        git(self.dir, "init", "-q")
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", "x")
        r = dc.analizar(self.dir)
        self.assertIn("check:datos_confidenciales.no_trackeado", [p["regla"] for p in r["checks_pass"]])

    def test_estado_dat_pii_repo_no_aplica(self):
        r = calc("DAT-PII-REPO", {"datos_confidenciales": "no_aplica"},
                 motivos={"datos_confidenciales": "sin repositorio git: nada está versionado"})
        self.assertEqual(r["estado"], "no_aplica")
        self.assertIn("sin repositorio git", r["motivo"])


# --------------------------------------------------------------------------------------------- G
class TestCiBasico(Tmp):
    SIN_CALIDAD = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm run build\n"
    CON_CALIDAD = "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n      - run: npm test\n"

    def pases(self):
        return {p["regla"] for p in archivos_clave.analizar(self.dir)["checks_pass"]}

    def test_ci_que_no_ejecuta_calidad_no_da_pase(self):
        self.escribir(".github/workflows/ci.yml", self.SIN_CALIDAD)
        self.assertNotIn("check:archivos_clave.ci", self.pases())

    def test_ci_vacio_no_da_pase(self):
        self.escribir(".github/workflows/ci.yml", "on: push\njobs: {}\n")
        self.assertNotIn("check:archivos_clave.ci", self.pases())

    def test_ci_que_ejecuta_tests_da_pase(self):
        self.escribir(".github/workflows/ci.yml", self.CON_CALIDAD)
        self.assertIn("check:archivos_clave.ci", self.pases())

    def test_ci_no_github_sin_verificacion_semantica_no_da_pase(self):
        self.escribir(".gitlab-ci.yml", "test:\n  script:\n    - npm test\n")
        self.assertNotIn("check:archivos_clave.ci", self.pases())

    def correr_workflows(self, actionlint):
        crudo = self.dir / "corrida" / "crudo"
        crudo.mkdir(parents=True, exist_ok=True)
        (crudo.parent / "herramientas.json").write_text(json.dumps(
            {"herramientas": {"actionlint": {"disponible": actionlint}}}), encoding="utf-8")
        p = subprocess.run([sys.executable, str(RAIZ / "scripts" / "checks" / "workflows.py"), str(self.dir / "p"),
                            str(crudo)], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads((crudo / "check_workflows.json").read_text(encoding="utf-8"))

    def test_con_actionlint_la_comprobacion_semantica_corre_igual(self):
        self.escribir("p/.github/workflows/ci.yml", self.SIN_CALIDAD + "  roto:\n    steps:\n      - run: x\n")
        datos = self.correr_workflows(actionlint=True)
        reglas = [h["regla"] for h in datos["hallazgos"]]
        self.assertEqual(datos["estado"], "ok", datos)
        self.assertIn("check:workflows.ci_sin_calidad", reglas)
        # la sintaxis la valida actionlint: el fallback no la duplica
        self.assertNotIn("check:workflows.job_sin_runs_on", reglas)

    def test_con_actionlint_y_calidad_no_hay_hallazgo(self):
        self.escribir("p/.github/workflows/ci.yml", self.CON_CALIDAD)
        datos = self.correr_workflows(actionlint=True)
        self.assertEqual(datos["hallazgos"], [])
        self.assertIn("check:workflows.ok_ci_calidad", [p["regla"] for p in datos["checks_pass"]])

    def test_sin_actionlint_sigue_el_fallback_completo(self):
        self.escribir("p/.github/workflows/ci.yml", self.SIN_CALIDAD + "  roto:\n    steps:\n      - run: x\n")
        reglas = [h["regla"] for h in self.correr_workflows(actionlint=False)["hallazgos"]]
        self.assertIn("check:workflows.ci_sin_calidad", reglas)
        self.assertIn("check:workflows.job_sin_runs_on", reglas)

    def test_calidad_ci_funcion_compartida(self):
        self.escribir(".github/workflows/a.yml", self.SIN_CALIDAD)
        self.assertEqual(workflows.calidad_ci(self.dir), (False, [".github/workflows/a.yml"]))
        self.escribir(".github/workflows/b.yml", self.CON_CALIDAD)
        self.assertEqual(workflows.calidad_ci(self.dir)[0], True)


# --------------------------------------------------------------------------------------------- H
class TestSecretoRepoHistorial(unittest.TestCase):
    def test_repo_con_commits_sin_historial_no_pasa(self):
        r = calc("SEG-SECRETO-REPO", {"gitleaks": "ok"},
                 alcance_={"gitleaks": {"arbol": 1, "historial": 0, "bundles": 0, "commits": 12,
                                         "codigo_confidencial": 0}})
        self.assertEqual(r["estado"], "no_evaluado", r)
        self.assertIn("historial", r["motivo"])
        self.assertIn("12 commits", r["motivo"])

    def test_repo_con_commits_e_historial_pasa(self):
        r = calc("SEG-SECRETO-REPO", {"gitleaks": "ok"},
                 alcance_={"gitleaks": {"arbol": 1, "historial": 1, "bundles": 0, "commits": 12,
                                         "codigo_confidencial": 0}})
        self.assertEqual(r["estado"], "pass")

    def test_sin_repo_basta_el_arbol(self):
        r = calc("SEG-SECRETO-REPO", {"gitleaks": "ok"},
                 alcance_={"gitleaks": {"arbol": 1, "historial": 0, "bundles": 0, "commits": 0,
                                         "codigo_confidencial": 0}})
        self.assertEqual(r["estado"], "pass")

    def test_sin_registro_de_commits_e_historial_cero_es_fail_closed(self):
        r = calc("SEG-SECRETO-REPO", {"gitleaks": "ok"}, alcance_={"gitleaks": {"arbol": 1, "historial": 0}})
        self.assertEqual(r["estado"], "no_evaluado", r)


@unittest.skipUnless(shutil.which("gitleaks") and shutil.which("git"), "gitleaks o git no instalados")
class TestAdaptadorGitleaksCommits(Tmp):
    def correr(self):
        crudo = self.dir.parent / (self.dir.name + "-crudo")
        self.addCleanup(shutil.rmtree, crudo, ignore_errors=True)
        subprocess.run(["bash", str(ADAPT / "gitleaks.sh"), str(self.dir), str(crudo)], check=True,
                       capture_output=True, timeout=120)
        return json.loads((crudo / "gitleaks.meta.json").read_text(encoding="utf-8"))

    def test_repo_con_commits_registra_commits(self):
        self.escribir("src/a.js", "console.log(1)\n")
        git(self.dir, "init", "-q")
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", "x")
        m = self.correr()
        self.assertEqual(m["alcance"]["commits"], 1)
        self.assertEqual(m["alcance"]["historial"], 1)

    def test_sin_repo_commits_cero(self):
        self.escribir("src/a.js", "console.log(1)\n")
        m = self.correr()
        self.assertEqual(m["alcance"]["commits"], 0)
        self.assertEqual(m["alcance"]["historial"], 0)
        self.assertEqual(m["estado"], "ok")

    def test_git_ilegible_es_parcial_sin_commits(self):
        self.escribir("src/a.js", "console.log(1)\n")
        self.escribir(".git", "gitdir: /ruta/que/no/existe\n")
        m = self.correr()
        self.assertEqual(m["estado"], "parcial", m)
        self.assertNotIn("commits", m["alcance"])


# --------------------------------------------------------------------------------------------- I
class TestPasesImposibles(Tmp):
    def test_tests_de_humo_no_demostrable(self):
        c = cat()["COD-TESTS-HUMO"]
        self.assertEqual(c["evidencia_pass"], "no_demostrable_estatico")
        r = calc("COD-TESTS-HUMO", {"archivos_clave": "ok"}, checks={"check:archivos_clave.tests"})
        self.assertEqual(r["estado"], "no_evaluado")
        self.assertIn("no demostrable", r["motivo"])
        h = {"id": "H-1", "control": "COD-TESTS-HUMO", "severidad": "media", "gate": "N2"}
        self.assertEqual(calc("COD-TESTS-HUMO", {"archivos_clave": "ok"}, hallazgos=[h])["estado"], "fail")

    def test_esquema_versionado_solo_con_bd(self):
        self.assertEqual(cat()["DAT-ESQUEMA-VERSIONADO"]["condicion"], "bd == true")
        sin_bd = utiles.indice_controles({"banderas": {"bd": False}})["DAT-ESQUEMA-VERSIONADO"]
        self.assertEqual(sin_bd["aplicabilidad"], "no_aplica")
        con_bd = utiles.indice_controles({"banderas": {"bd": True}})["DAT-ESQUEMA-VERSIONADO"]
        self.assertEqual(con_bd["aplicabilidad"], "aplica")
        r = calc("DAT-ESQUEMA-VERSIONADO", {"archivos_clave": "ok"}, checks={"check:archivos_clave.migraciones"})
        self.assertEqual(r["estado"], "pass")

    def test_agentes_sin_configuracion_es_no_aplica(self):
        self.escribir("CLAUDE.md", "# x\n")
        r = config_agentes.analizar(self.dir)
        self.assertEqual(r["estado"], "no_aplica")
        self.assertIn("sin configuración de agentes", r["motivo"])
        e = calc("SEG-AGENTES-IA", {"config_agentes": "no_aplica"}, motivos={"config_agentes": r["motivo"]})
        self.assertEqual(e["estado"], "no_aplica")

    def test_agentes_con_configuracion_limpia_pasa(self):
        self.escribir(".claude/settings.json", json.dumps({"permissions": {"allow": ["Bash(npm test)"]}}))
        r = config_agentes.analizar(self.dir)
        self.assertEqual(r["estado"], "ok")
        self.assertEqual([p["regla"] for p in r["checks_pass"]], ["check:config_agentes.configuracion"])

    def test_cors_cookies_csrf_no_demostrables_estaticamente(self):
        for cid in ("SEG-CORS", "SEG-COOKIES", "SEG-CSRF"):
            with self.subTest(control=cid):
                self.assertEqual(cat()[cid]["evidencia_pass"], "no_demostrable_estatico")
                r = calc(cid, {"semgrep": "ok"})
                self.assertEqual(r["estado"], "no_evaluado")
                self.assertIn("sonda dinámica", r["motivo"])


# --------------------------------------------------------------------------------------------- J
def hallazgo(i, severidad, gate, control="SEG-SECRETO-REPO", archivo=".env"):
    return {"id": f"H-{i}", "control": control, "severidad": severidad, "gate": gate,
            "ubicacion": {"archivo": archivo, "linea": i}, "fingerprint": f"{i:04d}"}


class TestTope(unittest.TestCase):
    def test_no_descarta_criticos_n1(self):
        hs = [hallazgo(i, "critica", "N1") for i in range(1, 9)]
        lim = ncomun.limitar(hs, 5)
        self.assertEqual(len(lim), 8)
        self.assertEqual(sum(h.get("instancias_extra", 0) for h in lim), 0)

    def test_criticos_n1_primero_y_resto_hasta_el_tope(self):
        hs = [hallazgo(i, "alta", "N2") for i in range(1, 6)] + [hallazgo(i, "critica", "N1") for i in range(6, 9)]
        lim = ncomun.limitar(hs, 5)
        lineas = [h["ubicacion"]["linea"] for h in lim]
        self.assertEqual(lineas, [1, 2, 6, 7, 8])
        self.assertEqual(sum(h.get("instancias_extra", 0) for h in lim), 3)

    def test_critico_no_n1_si_se_puede_topar(self):
        hs = [hallazgo(i, "critica", "N2") for i in range(1, 9)]
        self.assertEqual(len(ncomun.limitar(hs, 5)), 5)


class TestMetricasAdvierteTope(Tmp):
    def correr(self, nombre, hallazgos, hermano=True):
        ruta = self.dir / nombre
        ruta.write_text("".join(json.dumps(h) + "\n" for h in hallazgos), encoding="utf-8")
        if hermano:
            (self.dir / "hallazgos_todos.jsonl").write_text("", encoding="utf-8")
        verdad = self.dir / "v.toml"
        verdad.write_text("", encoding="utf-8")
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err):
            metricas.main(["--hallazgos", str(ruta), "--verdad", str(verdad)], salida=out)
        return err.getvalue()

    def test_advierte_si_recibe_hallazgos_con_tope(self):
        self.assertIn("hallazgos_todos.jsonl", self.correr("hallazgos.jsonl", []))

    def test_advierte_si_hay_instancias_extra(self):
        h = dict(hallazgo(1, "alta", "N2"), instancias_extra=2)
        self.assertIn("tope", self.correr("otro.jsonl", [h], hermano=False))

    def test_no_advierte_con_hallazgos_todos(self):
        self.assertEqual(self.correr("hallazgos_todos.jsonl", [], hermano=False), "")


# --------------------------------------------------------------------------------------------- K
class TestOsvFechaBase(Tmp):
    def test_meta_registra_fecha_de_consulta(self):
        falsos = self.dir / "bin"
        falsos.mkdir()
        f = falsos / "osv-scanner"
        f.write_text('#!/usr/bin/env bash\nif [ "$1" = "--version" ]; then echo "osv-scanner version: 2.7.0"; exit 0; fi\n'
                     'o=""; while [ $# -gt 0 ]; do [ "$1" = --output-file ] && o="$2"; shift; done\n'
                     '[ -n "$o" ] && printf \'{"results": []}\' > "$o"; exit 0\n', encoding="utf-8")
        f.chmod(0o755)
        proy = self.dir / "p"
        proy.mkdir()
        (proy / "package-lock.json").write_text("{}", encoding="utf-8")
        crudo = self.dir / "crudo"
        env = dict(os.environ, AUDITOR_BIN_OSV=str(f))
        subprocess.run(["bash", str(ADAPT / "osv.sh"), str(proy), str(crudo)], check=True, capture_output=True,
                       env=env, timeout=60)
        m = json.loads((crudo / "osv.meta.json").read_text(encoding="utf-8"))
        base = m["base_osv"]
        self.assertRegex(base["consultada_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertIn("api.osv.dev", base["fuente"])
        self.assertIn("instantánea", base["nota"])


if __name__ == "__main__":
    unittest.main()
