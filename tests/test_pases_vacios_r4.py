"""Ronda 4 de pases vacíos (fail-closed): pases vacíos residuales PV-R3-01…15 de la re-verificación de la ronda 3, más
SEG-DEPS-EXISTEN (manifiestos Python no leídos) y COD-TIPOS (tsc del proyecto auditado). investigacion/16.

  A  PV-R3-01 rutas confidenciales por segmento: el código en src/patients/ no se escanea → no puede haber pass.
  B  PV-R3-02 COD-TIPOS: no se ejecuta un tsc del repo auditado sin confianza explícita; el pase exige ≥ 1 archivo tipado.
  C  PV-R3-03 gitleaks: carpetas build/dist/out a cualquier profundidad se escanean como bundle.
  D  PV-R3-04 archivos > 2 MB que semgrep omite impiden el pass.
  E  PV-R3-05/06 SEG-ENV-EJEMPLO: .env de subcarpetas; .env.example vacío o incompleto no da pase.
  F  PV-R3-07/08/09 COD-CI-BASICO: 'test' dentro de un nombre de archivo, `make test` sin calidad, script test no-op.
  G  PV-R3-10/11/12 DAT-PII-REPO: .sql/.yaml/.xml/.txt sospechosos, JSON grande con raíz objeto, historial.
  H  PV-R3-13/14/15 DAT-ESQUEMA-VERSIONADO (SQL solo con comentarios), OPS-HEALTH (axios.get), OPS-ERROR-TRACKING.
  I  SEG-DEPS-EXISTEN: -r de requirements, [dependency-groups], grupos de Poetry, setup.py/setup.cfg/environment.yml.
"""
import json
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
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "scripts" / "adaptadores"))

import alcance  # noqa: E402
import archivos_clave  # noqa: E402
import catalogo  # noqa: E402
import datos_confidenciales  # noqa: E402
import estado  # noqa: E402
import registro_deps  # noqa: E402
import tipos  # noqa: E402
import workflows  # noqa: E402

FECHA = "2026-11-18"
EXPRESS = ("const express = require('express');\nconst app = express();\n"
           "app.get('/u', (req, res) => res.json({}));\napp.listen(3000);\n")


def cat():
    return {c["id"]: c for c in catalogo.cargar_catalogo()}


def calc(cid, herr, checks=(), alcance_=None, hallazgos=()):
    c = dict(cat()[cid], aplicabilidad="aplica")
    return estado.calcular({cid: c}, list(hallazgos), herr, set(checks), "profundo", FECHA, alcance=alcance_)[0]


def git(proy, *args):
    ident = ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
    return subprocess.run(["git", *ident, "-C", str(proy), *args], capture_output=True, text=True, check=True)


class Tmp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name).resolve()
        self.addCleanup(self._tmp.cleanup)

    def escribir(self, rel, contenido=""):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contenido, bytes):
            p.write_bytes(contenido)
        else:
            p.write_text(contenido, encoding="utf-8")
        return p

    @staticmethod
    def reglas(res):
        return {h["regla"] for h in res["hallazgos"]}

    @staticmethod
    def pases(res):
        return {p["regla"] for p in res["checks_pass"]}


# --------------------------------------------------------------------------------------------- A
class TestCodigoConfidencial(Tmp):
    """PV-R3-01: las carpetas confidenciales se comparan por segmento; el código de src/datos-reales/ no se escanea.
    DECISIONES #12 (ronda 6, verificación ciega node-next): antes el caso era src/patients/; «patients» y «pacientes»
    son ahora carpetas AMBIGUAS cuyo código sí se escanea (ver test_r6_datos), así que el mecanismo se prueba con una
    carpeta inequívoca."""

    def test_calcular_cuenta_codigo_en_rutas_confidenciales(self):
        self.escribir("src/index.js", EXPRESS)
        self.escribir("src/datos-reales/routes.js", "module.exports = 1;\n")
        self.escribir("datos-reales/a.csv", "x\n")          # datos, no código
        self.escribir("datos-reales/imagen.dcm", b"\0\0")
        a = alcance.calcular(self.dir)
        self.assertEqual(a["codigo_confidencial"], 1, a)
        self.assertEqual(a["arbol"], 1)  # el código confidencial no se escanea ni cuenta como alcance

    def test_calcular_cuenta_lockfiles_confidenciales(self):
        self.escribir("package-lock.json", "{}")
        self.escribir("src/datos_reales/package-lock.json", "{}")
        a = alcance.calcular(self.dir)
        self.assertEqual(a["lockfiles"], 1)
        self.assertEqual(a["lockfiles_confidenciales"], 1)

    def test_semgrep_registra_fuentes_no_escaneadas(self):
        self.escribir("src/index.js", EXPRESS)
        self.escribir("src/datos-reales/routes.js", "module.exports = 1;\n")
        r = alcance.desde_semgrep({"paths": {"scanned": ["src/index.js"]}}, self.dir, ["vibe-coding.eval-dinamico"])
        self.assertEqual(r["fuentes"], 1)
        self.assertEqual(r["fuentes_confidenciales"], 1)
        self.assertEqual(r["fuentes_no_escaneadas"], 1)

    def test_sin_codigo_confidencial_las_claves_valen_cero(self):
        self.escribir("src/index.js", EXPRESS)
        r = alcance.desde_semgrep({"paths": {"scanned": ["src/index.js"]}}, self.dir, ["vibe-coding.x"])
        self.assertEqual((r["fuentes_no_escaneadas"], r["fuentes_confidenciales"], r["fuentes_grandes"]), (0, 0, 0))
        self.assertEqual(alcance.calcular(self.dir)["codigo_confidencial"], 0)

    def test_estado_secreto_repo_no_pasa_con_codigo_confidencial(self):
        base = {"arbol": 2, "historial": 1, "bundles": 0, "commits": 1}
        r = calc("SEG-SECRETO-REPO", {"gitleaks": "ok"}, alcance_={"gitleaks": dict(base, codigo_confidencial=1)})
        self.assertEqual(r["estado"], "no_evaluado", r)
        self.assertIn("codigo_confidencial", r["motivo"])
        r = calc("SEG-SECRETO-REPO", {"gitleaks": "ok"}, alcance_={"gitleaks": base})  # clave sin registrar
        self.assertEqual(r["estado"], "no_evaluado", r)
        r = calc("SEG-SECRETO-REPO", {"gitleaks": "ok"}, alcance_={"gitleaks": dict(base, codigo_confidencial=0)})
        self.assertEqual(r["estado"], "pass", r)

    def test_estado_sast_y_sql_no_pasan_con_fuentes_no_escaneadas(self):
        base = {"fuentes": 1, "fuentes_sin_reglas": 0, "consultas_sql": 1, "consultas_sql_sin_reglas": 0}
        for cid in ("SEG-SAST-INY", "DAT-SQL-CONCATENADO"):
            with self.subTest(control=cid):
                r = calc(cid, {"semgrep": "ok"}, alcance_={"semgrep": dict(base, fuentes_no_escaneadas=1)})
                self.assertEqual(r["estado"], "no_evaluado", r)
                self.assertIn("fuentes_no_escaneadas", r["motivo"])
                r = calc(cid, {"semgrep": "ok"}, alcance_={"semgrep": base})
                self.assertEqual(r["estado"], "no_evaluado", r)
                r = calc(cid, {"semgrep": "ok"}, alcance_={"semgrep": dict(base, fuentes_no_escaneadas=0)})
                self.assertEqual(r["estado"], "pass", r)

    def test_sql_sin_consultas_con_codigo_no_escaneado_no_es_no_aplica(self):
        base = {"fuentes": 1, "fuentes_sin_reglas": 0, "consultas_sql": 0, "consultas_sql_sin_reglas": 0,
                "fuentes_no_escaneadas": 2}
        r = calc("DAT-SQL-CONCATENADO", {"semgrep": "ok"}, alcance_={"semgrep": base})
        self.assertEqual(r["estado"], "no_evaluado", r)

    def test_estado_deps_cve_no_pasa_con_lockfile_confidencial(self):
        for cid in ("SEG-DEPS-CVE-CRIT", "SEG-DEPS-CVE-ALTO", "SEG-DEPS-CVE-MEDIO"):
            with self.subTest(control=cid):
                al = {"osv-scanner": {"lockfiles": 1, "lockfiles_confidenciales": 1}}
                self.assertEqual(calc(cid, {"osv-scanner": "ok"}, alcance_=al)["estado"], "no_evaluado")
                al = {"osv-scanner": {"lockfiles": 1, "lockfiles_confidenciales": 0}}
                self.assertEqual(calc(cid, {"osv-scanner": "ok"}, alcance_=al)["estado"], "pass")

    @unittest.skipUnless(shutil.which("gitleaks"), "gitleaks no instalado")
    def test_adaptador_gitleaks_registra_codigo_confidencial(self):
        self.escribir("src/index.js", EXPRESS)
        self.escribir("src/datos-reales/routes.js", "module.exports = 1;\n")
        crudo = self.dir.parent / (self.dir.name + "-crudo")
        self.addCleanup(shutil.rmtree, crudo, True)
        subprocess.run(["bash", str(RAIZ / "scripts" / "adaptadores" / "gitleaks.sh"), str(self.dir), str(crudo)],
                       check=True, capture_output=True, timeout=120)
        meta = json.loads((crudo / "gitleaks.meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["alcance"]["codigo_confidencial"], 1, meta)


# --------------------------------------------------------------------------------------------- B
class TestTiposNoConfiable(Tmp):
    """PV-R3-02: COD-TIPOS ejecutaba node_modules/.bin/tsc del repo auditado y daba pase sin tipar nada."""

    def setUp(self):
        super().setUp()
        self.proy = self.dir / "proy"
        self.escribir("proy/tsconfig.json", json.dumps({"compilerOptions": {"strict": True}, "include": ["src"]}))
        self.escribir("proy/src/a.ts", "const n: number = 1;\nexport default n;\n")
        self.marca = self.dir / "ejecutado"

    def ejecutable(self, ruta, cuerpo):
        ruta.parent.mkdir(parents=True, exist_ok=True)
        ruta.write_text(cuerpo, encoding="utf-8")
        ruta.chmod(ruta.stat().st_mode | stat.S_IEXEC)
        return ruta

    def tsc_espia(self, ruta, salida="", codigo=0):
        return self.ejecutable(ruta, f"#!/bin/sh\ntouch '{self.marca}'\nprintf '%b' '{salida}'\nexit {codigo}\n")

    def test_tsc_del_repo_que_no_es_typescript_no_se_ejecuta(self):
        self.tsc_espia(self.proy / "node_modules" / ".bin" / "tsc")
        res = tipos.analizar(self.proy, tsc="", confiar_proyecto=True)
        self.assertEqual(res["estado"], "no_evaluado", res)
        self.assertFalse(self.marca.exists(), "se ejecutó un binario del repo auditado")
        self.assertEqual(res["checks_pass"], [])

    def test_symlink_fuera_del_proyecto_no_se_ejecuta(self):
        externo = self.tsc_espia(self.dir / "fuera" / "tsc")
        enlace = self.proy / "node_modules" / ".bin" / "tsc"
        enlace.parent.mkdir(parents=True)
        enlace.symlink_to(externo)
        res = tipos.analizar(self.proy, tsc="", confiar_proyecto=True)
        self.assertEqual(res["estado"], "no_evaluado", res)
        self.assertIn("fuera", res["motivo"])
        self.assertFalse(self.marca.exists())

    def typescript_local(self, salida="", codigo=0):
        real = self.tsc_espia(self.proy / "node_modules" / "typescript" / "bin" / "tsc", salida, codigo)
        (self.proy / "node_modules" / "typescript" / "package.json").write_text('{"name": "typescript"}')
        enlace = self.proy / "node_modules" / ".bin" / "tsc"
        enlace.parent.mkdir(parents=True)
        enlace.symlink_to(Path("..") / "typescript" / "bin" / "tsc")
        return real

    def test_proyecto_no_confiable_no_se_ejecuta_aunque_el_layout_sea_estandar(self):
        self.typescript_local()
        res = tipos.analizar(self.proy, tsc="", confiar_proyecto=False)
        self.assertEqual(res["estado"], "no_evaluado", res)
        self.assertIn("AUDITOR_CONFIAR_TSC_PROYECTO", res["motivo"])
        self.assertFalse(self.marca.exists())

    def test_proyecto_confiable_ejecuta_pero_exige_archivos_tipados(self):
        self.typescript_local(salida="")
        res = tipos.analizar(self.proy, tsc="", confiar_proyecto=True)
        self.assertTrue(self.marca.exists())
        self.assertEqual(res["estado"], "no_evaluado", res)
        self.assertIn("ningún archivo", res["motivo"])

    def test_tsc_confiable_externo_con_archivos_tipados_pasa(self):
        tsc = self.tsc_espia(self.dir / "herr" / "tsc", salida=f"{self.proy / 'src' / 'a.ts'}\\n")
        res = tipos.analizar(self.proy, tsc=str(tsc))
        self.assertEqual(res["estado"], "ok", res)
        self.assertEqual(self.pases(res), {"check:tipos.sin_errores"})
        self.assertIn("1 archivo", res["checks_pass"][0]["mensaje"])

    def test_tsc_externo_sin_salida_no_da_pase(self):
        tsc = self.tsc_espia(self.dir / "herr" / "tsc", salida="")
        res = tipos.analizar(self.proy, tsc=str(tsc))
        self.assertEqual(res["estado"], "no_evaluado", res)
        self.assertEqual(res["checks_pass"], [])

    def test_tsc_externo_no_cuenta_dependencias_ni_libs(self):
        salida = (f"{self.dir / 'herr' / 'lib.es2020.d.ts'}\\n"
                  f"{self.proy / 'node_modules' / 'x' / 'index.d.ts'}\\n")
        tsc = self.tsc_espia(self.dir / "herr" / "tsc", salida=salida)
        res = tipos.analizar(self.proy, tsc=str(tsc))
        self.assertEqual(res["estado"], "no_evaluado", res)

    def test_tsc_en_el_path_dentro_del_proyecto_no_es_confiable(self):
        self.tsc_espia(self.proy / "node_modules" / ".bin" / "tsc")
        viejo = os.environ.get("PATH", "")
        os.environ["PATH"] = str(self.proy / "node_modules" / ".bin") + os.pathsep + viejo
        os.environ.pop("AUDITOR_BIN_TSC", None)
        self.addCleanup(os.environ.__setitem__, "PATH", viejo)
        res = tipos.analizar(self.proy, confiar_proyecto=False)
        self.assertEqual(res["estado"], "no_evaluado", res)
        self.assertFalse(self.marca.exists())


# --------------------------------------------------------------------------------------------- C
@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks no instalado")
class TestBundleProfundo(Tmp):
    """PV-R3-03: build/ a profundidad ≥ 5 quedaba fuera del árbol y de los bundles."""

    def test_build_profundo_se_escanea_como_bundle(self):
        self.escribir("package.json", "{}")
        self.escribir("apps/web/src/index.js", EXPRESS)
        self.escribir("apps/web/packages/ui/build/config.js",
                      'module.exports = { gh: "ghp_A1b2C3d4E5f6G7h8' 'I9j0K1l2M3n4O5p6Q7r8" };\n')
        crudo = self.dir.parent / (self.dir.name + "-crudo")
        self.addCleanup(shutil.rmtree, crudo, True)
        subprocess.run(["bash", str(RAIZ / "scripts" / "adaptadores" / "gitleaks.sh"), str(self.dir), str(crudo)],
                       check=True, capture_output=True, timeout=120)
        meta = json.loads((crudo / "gitleaks.meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["alcance"]["bundles"], 1, meta)
        self.assertIn("apps/web/packages/ui/build", meta.get("carpetas_bundle", []))
        hallazgos = json.loads((crudo / "gitleaks-bundle.json").read_text(encoding="utf-8"))
        self.assertTrue(hallazgos, "el secreto del bundle profundo no se encontró")


# --------------------------------------------------------------------------------------------- D
class TestArchivoGrande(Tmp):
    """PV-R3-04: un archivo de código > 2 MB que semgrep omite no puede dar pass."""

    def test_archivo_grande_cuenta_como_no_escaneado(self):
        self.escribir("src/index.js", EXPRESS)
        self.escribir("src/handlers.js", "//" + "x" * (alcance.MAX_BYTES_SQL + 10) + "\neval(req.query.code);\n")
        r = alcance.desde_semgrep({"paths": {"scanned": ["src/index.js"]}}, self.dir, ["vibe-coding.x"])
        self.assertEqual(r["fuentes_grandes"], 1, r)
        self.assertEqual(r["fuentes_no_escaneadas"], 1, r)

    def test_min_js_grande_sigue_excluido(self):
        self.escribir("src/index.js", EXPRESS)
        self.escribir("src/vendor.min.js", "x" * (alcance.MAX_BYTES_SQL + 10))
        r = alcance.desde_semgrep({"paths": {"scanned": ["src/index.js"]}}, self.dir, ["vibe-coding.x"])
        self.assertEqual(r["fuentes_no_escaneadas"], 0, r)


# --------------------------------------------------------------------------------------------- E
class TestEnvSubcarpetas(Tmp):
    """PV-R3-05: .env de subcarpetas versionados o sin ignorar; PV-R3-06: .env.example vacío."""

    def test_env_versionado_en_subcarpeta_es_hallazgo(self):
        git(self.dir, "init", "-q")
        self.escribir("package.json", "{}")
        self.escribir(".env.example", "DB_PASSWORD=\n")
        self.escribir(".gitignore", "node_modules\n")
        self.escribir("packages/api/.env", "DB_PASSWORD=Sup3rS3creta!2026\n")
        git(self.dir, "add", "-A")
        r = archivos_clave.analizar(self.dir)
        hs = [h for h in r["hallazgos"] if h["regla"] == "check:archivos_clave.env_comiteado"]
        self.assertEqual([h["archivo"] for h in hs], ["packages/api/.env"], r["hallazgos"])
        self.assertNotIn("check:archivos_clave.env_ignorado", self.pases(r))

    def test_env_en_subcarpeta_no_ignorado(self):
        git(self.dir, "init", "-q")
        self.escribir(".env.example", "DB_PASSWORD=\n")
        self.escribir(".gitignore", "/.env\n")
        self.escribir("backend/.env", "DB_PASSWORD=Sup3rS3creta!2026\n")
        r = archivos_clave.analizar(self.dir)
        self.assertIn("check:archivos_clave.env_no_ignorado", self.reglas(r))
        self.assertIn("backend/.env", {h["archivo"] for h in r["hallazgos"]})

    def test_env_en_subcarpeta_ignorado_da_pase(self):
        git(self.dir, "init", "-q")
        self.escribir(".env.example", "DB_PASSWORD=\n")
        self.escribir(".gitignore", ".env\n")
        self.escribir("backend/.env", "DB_PASSWORD=x\n")
        r = archivos_clave.analizar(self.dir)
        self.assertIn("check:archivos_clave.env_ignorado", self.pases(r))

    def test_env_en_node_modules_no_cuenta(self):
        git(self.dir, "init", "-q")
        self.escribir(".gitignore", "node_modules\n")
        self.escribir("node_modules/x/.env", "A=1\n")
        r = archivos_clave.analizar(self.dir)
        self.assertNotIn("check:archivos_clave.env_no_ignorado", self.reglas(r))

    def test_env_ejemplo_vacio_no_da_pase(self):
        self.escribir(".env.example", "")
        self.escribir("src/pay.js", "const k = process.env.STRIPE_SECRET_KEY;\n")
        r = archivos_clave.analizar(self.dir)
        self.assertNotIn("check:archivos_clave.env_ejemplo", self.pases(r))

    def test_env_ejemplo_sin_las_variables_del_codigo_no_da_pase(self):
        self.escribir(".env.example", "OTRA=\n")
        self.escribir("src/pay.js", "const k = process.env.STRIPE_SECRET_KEY;\nconst u = process.env.DATABASE_URL;\n")
        r = archivos_clave.analizar(self.dir)
        self.assertNotIn("check:archivos_clave.env_ejemplo", self.pases(r))

    def test_env_ejemplo_completo_da_pase(self):
        self.escribir(".env.example", "# claves\nSTRIPE_SECRET_KEY=\nDATABASE_URL=postgres://localhost/x\n")
        self.escribir("src/pay.js", "const k = process.env.STRIPE_SECRET_KEY;\nconst u = process.env.DATABASE_URL;\n"
                      "if (process.env.NODE_ENV === 'production') {}\n")
        r = archivos_clave.analizar(self.dir)
        self.assertIn("check:archivos_clave.env_ejemplo", self.pases(r))


# --------------------------------------------------------------------------------------------- F
def wfci(*runs):
    return ("name: CI\non: [push, pull_request]\njobs:\n  ci:\n    runs-on: ubuntu-latest\n    steps:\n"
            + "".join(f"      - run: {r}\n" for r in runs))


class TestCiR4(Tmp):
    def calidad(self, *runs):
        self.escribir(".github/workflows/ci.yml", wfci(*runs))
        return workflows.calidad_ci(self.dir)[0]

    def test_test_dentro_de_un_nombre_de_archivo_no_cuenta(self):
        self.escribir("scripts/generate-test-fixtures.js", "console.log(1)\n")
        for run in ("node scripts/generate-test-fixtures.js", "python -c \"print('tests ok')\"",
                    "make deploy-test"):
            with self.subTest(run=run):
                self.assertIs(self.calidad(run), False, run)

    def test_lanzadores_legitimos_siguen_contando(self):
        self.escribir("Makefile", "test:\n\tpytest -q\nlint:\n\t@ruff check .\n")
        for run in ("python -m pytest", "go test ./...", "cargo test", "npx eslint .", "npx tsc --noEmit",
                    "python manage.py test", "uv run pytest", "node --test", "make test", "make lint",
                    "dotnet test", "node scripts/test.js"):
            with self.subTest(run=run):
                self.assertIs(self.calidad(run), True, run)

    def test_make_target_que_no_hace_calidad_no_cuenta(self):
        self.escribir("Makefile", "test:\n\t@echo ok\nbuild:\n\tnpm run build\n")
        self.assertIs(self.calidad("make test"), False)
        self.assertIs(self.calidad("make build"), False)

    def test_make_sin_makefile_o_sin_target_no_cuenta(self):
        self.assertIs(self.calidad("make test"), False)
        self.escribir("Makefile", "lint:\n\teslint .\n")
        self.assertIs(self.calidad("make test"), False)

    def test_make_target_que_llama_a_otro_con_calidad(self):
        self.escribir("Makefile", "ci: test\n\t@echo listo\ntest:\n\tpytest\n")
        self.assertIs(self.calidad("make ci"), True)

    def test_script_test_noop_no_cuenta(self):
        for cuerpo in ("node --version", "node -e 0", "echo hola"):
            with self.subTest(cuerpo=cuerpo):
                self.escribir("package.json", json.dumps({"scripts": {"test": cuerpo}}))
                self.assertIs(self.calidad("npm test"), False, cuerpo)

    def test_script_test_real_sigue_contando(self):
        for cuerpo in ("jest", "vitest run", "react-scripts test", "ng test", "node --test", "next lint",
                       "npm run lint && npm run unit", "jest --passWithNoTests"):
            with self.subTest(cuerpo=cuerpo):
                self.escribir("package.json", json.dumps({"scripts": {"test": cuerpo, "lint": "eslint .",
                                                                      "unit": "vitest"}}))
                self.assertIs(self.calidad("npm test"), True, cuerpo)


# --------------------------------------------------------------------------------------------- G
SQL_PII = ("INSERT INTO pacientes (nombre, rut, diagnostico, email) VALUES\n"
           "('Juana Pérez Soto', '12.345.678-5', 'VIH', 'juana.perez@correo.cl'),\n"
           "('Pedro Rojas Díaz', '11.111.112-K', 'diabetes', 'pedro.rojas@correo.cl');\n")


class TestPiiR4(Tmp):
    def repo(self, archivos, commit=False):
        git(self.dir, "init", "-q")
        for rel, contenido in archivos.items():
            self.escribir(rel, contenido)
        git(self.dir, "add", "-A")
        if commit:
            git(self.dir, "commit", "-q", "-m", "x")
        return datos_confidenciales.analizar(self.dir)

    def assert_sin_valores(self, r):
        texto = json.dumps(r, ensure_ascii=False)
        for valor in ("Juana", "12.345.678-5", "juana.perez@correo.cl", "VIH", "diabetes"):
            self.assertNotIn(valor, texto)

    def test_seed_sql_con_pii_es_hallazgo(self):
        r = self.repo({"db/seed.sql": SQL_PII, "index.js": "x\n"})
        self.assertIn("check:datos_confidenciales.pii_tabular", self.reglas(r))
        self.assertEqual(r["checks_pass"], [])
        self.assert_sin_valores(r)

    def test_sql_de_esquema_sin_datos_no_bloquea(self):
        r = self.repo({"migrations/0001.sql": "CREATE TABLE pacientes (nombre text, rut text, email text);\n",
                       "index.js": "x\n"})
        self.assertEqual(self.reglas(r), set())
        self.assertEqual(self.pases(r), {"check:datos_confidenciales.no_trackeado"})

    def test_yaml_sospechoso_con_pii_es_hallazgo(self):
        r = self.repo({"db/export.yaml": "pacientes:\n  - nombre: Juana Pérez\n    rut: 12.345.678-5\n"})
        self.assertIn("check:datos_confidenciales.pii_tabular", self.reglas(r))
        self.assert_sin_valores(r)

    def test_tipos_no_inspeccionables_sospechosos_impiden_el_pase(self):
        casos = {"data/registros.txt": "Juana vino por control\n", "backups/respaldo.sql.gz": b"\x1f\x8b\x08binario",
                 "export/pacientes.xml": "<lista><p>sin estructura reconocible</p></lista>\n",
                 "dump.zip": b"PK\x03\x04x"}
        for rel, contenido in casos.items():
            with self.subTest(archivo=rel):
                with tempfile.TemporaryDirectory() as d:
                    self.dir = Path(d).resolve()
                    r = self.repo({rel: contenido, "index.js": "x\n"})
                    self.assertEqual(r["checks_pass"], [], (rel, r))
                    self.assertIn("no inspeccionable", r["motivo"] or "")

    def test_yaml_de_configuracion_no_sospechoso_no_bloquea(self):
        r = self.repo({".github/workflows/ci.yml": "on: push\njobs: {}\n", "config/app.yaml": "puerto: 3000\n",
                       "docs/notas.txt": "notas\n"})
        self.assertEqual(self.pases(r), {"check:datos_confidenciales.no_trackeado"})

    def test_json_grande_con_raiz_objeto_no_da_pase(self):
        regs = [{"nombre": f"Paciente {i}", "rut": "12.345.678-5", "diagnostico": "VIH"} for i in range(6000)]
        r = self.repo({"data/export.json": json.dumps({"pacientes_export": regs})})
        self.assertEqual(r["checks_pass"], [], r)
        self.assertTrue(self.reglas(r) & {"check:datos_confidenciales.pii_tabular"} or "no inspeccionable" in
                        (r["motivo"] or ""), r)
        self.assert_sin_valores(r)

    def test_json_grande_sin_pii_con_raiz_objeto_no_da_pase(self):
        datos = {"items": [{"sku": f"A{i}", "precio": i} for i in range(20000)]}
        r = self.repo({"data/catalogo.json": json.dumps(datos)})
        self.assertEqual(r["checks_pass"], [], r)
        self.assertIn("no inspeccionable", r["motivo"] or "")

    def test_lockfile_grande_no_bloquea(self):
        lock = {"name": "x", "lockfileVersion": 3,
                "packages": {f"node_modules/p{i}": {"version": "1.0.0", "resolved": "https://r/x.tgz"}
                             for i in range(8000)}}
        r = self.repo({"package-lock.json": json.dumps(lock)})
        self.assertEqual(self.pases(r), {"check:datos_confidenciales.no_trackeado"}, r)

    def test_csv_borrado_que_queda_en_el_historial(self):
        self.repo({"data/registro.csv": "nombre,rut,diagnostico\nJuana Pérez,12.345.678-5,VIH\n",
                   "index.js": "x\n"}, commit=True)
        git(self.dir, "rm", "-q", "data/registro.csv")
        git(self.dir, "commit", "-q", "-m", "borra")
        r = datos_confidenciales.analizar(self.dir)
        hs = [h for h in r["hallazgos"] if h["regla"] == "check:datos_confidenciales.pii_tabular"]
        self.assertEqual(len(hs), 1, r)
        self.assertIn("historial", hs[0]["mensaje"])
        self.assertEqual(r["checks_pass"], [])
        self.assert_sin_valores(r)

    def test_carpeta_confidencial_borrada_que_queda_en_el_historial(self):
        self.repo({"datos-reales/a.csv": "x\n", "index.js": "x\n"}, commit=True)
        git(self.dir, "rm", "-q", "-r", "datos-reales")
        git(self.dir, "commit", "-q", "-m", "borra")
        r = datos_confidenciales.analizar(self.dir)
        self.assertIn("check:datos_confidenciales.trackeado_historial", self.reglas(r))
        self.assertEqual(catalogo.control_por_regla("check", "datos_confidenciales.trackeado_historial"),
                         "DAT-PII-REPO")

    def test_historial_limpio_mantiene_el_pase(self):
        self.repo({"data/productos.csv": "sku,precio\nA,1\n", "index.js": "x\n"}, commit=True)
        git(self.dir, "rm", "-q", "data/productos.csv")
        git(self.dir, "commit", "-q", "-m", "borra")
        r = datos_confidenciales.analizar(self.dir)
        self.assertEqual(self.pases(r), {"check:datos_confidenciales.no_trackeado"}, r)
        self.assertIn("historial", r["checks_pass"][0]["mensaje"])


# --------------------------------------------------------------------------------------------- H
class TestMedios(Tmp):
    def test_migracion_solo_con_comentarios_no_da_pase(self):
        self.escribir("package.json", json.dumps({"dependencies": {"pg": "^8"}}))
        self.escribir("migrations/0001_init.sql", "-- TODO: escribir el esquema\n/* nada */\n")
        r = archivos_clave.analizar(self.dir)
        self.assertNotIn("check:archivos_clave.migraciones", self.pases(r))
        self.assertIn("check:archivos_clave.migraciones_ausentes", self.reglas(r))

    def test_migracion_sql_real_da_pase(self):
        self.escribir("package.json", json.dumps({"dependencies": {"pg": "^8"}}))
        self.escribir("migrations/0001_init.sql", "-- esquema\nCREATE TABLE t (id int);\n")
        self.assertIn("check:archivos_clave.migraciones", self.pases(archivos_clave.analizar(self.dir)))

    def test_health_del_cliente_no_cuenta(self):
        self.escribir("package.json", json.dumps({"dependencies": {"express": "^4"}}))
        self.escribir("server/index.js", EXPRESS)
        for cliente in ("axios.get('/api/health')", "http.get('/health')", "this.http.get('/health')",
                        "client.get('/healthz')", "api.get('/health')", "ky.get('/health')"):
            with self.subTest(cliente=cliente):
                self.escribir("web/monitor.js", f"export const ping = () => {cliente};\n")
                self.assertNotIn("check:archivos_clave.health", self.pases(archivos_clave.analizar(self.dir)))

    def test_health_del_servidor_sigue_contando(self):
        self.escribir("package.json", json.dumps({"dependencies": {"express": "^4"}}))
        for ruta in ("app.get('/health', h)", "router.get('/api/healthz', h)", "fastify.get('/health', h)",
                     "server.get('/status', h)", "r.get('/ping', h)", "@app.get('/health')"):
            with self.subTest(ruta=ruta):
                self.escribir("server/index.js", EXPRESS + ruta + "\n")
                self.assertIn("check:archivos_clave.health", self.pases(archivos_clave.analizar(self.dir)))

    def test_plugin_de_sentry_no_es_error_tracking(self):
        for pkg in ({"devDependencies": {"@sentry/vite-plugin": "^2"}},
                    {"dependencies": {"@sentry/webpack-plugin": "^2", "@sentry/cli": "^2"}}):
            with self.subTest(pkg=pkg):
                self.escribir("package.json", json.dumps(pkg))
                self.escribir("src/index.js", "console.log(1)\n")
                self.assertNotIn("check:archivos_clave.error_tracking",
                                 self.pases(archivos_clave.analizar(self.dir)))

    def test_sdk_de_sentry_sigue_contando(self):
        self.escribir("package.json", json.dumps({"dependencies": {"@sentry/react": "^8"},
                                                  "devDependencies": {"@sentry/vite-plugin": "^2"}}))
        self.escribir("src/index.js", "console.log(1)\n")
        self.assertIn("check:archivos_clave.error_tracking", self.pases(archivos_clave.analizar(self.dir)))


# --------------------------------------------------------------------------------------------- I
class TestDepsPython(Tmp):
    REALES = {"requests", "pytest", "flask"}

    def consulta(self, eco, nombre, timeout):
        return {"existe": nombre in self.REALES, "creado": "2015-01-01T00:00:00Z", "versiones": 50}

    def analizar(self):
        return registro_deps.analizar(self.dir, consulta=self.consulta, hoy=FECHA)

    def inexistentes(self, r):
        return sorted(x["evidencia"].split()[0].strip("\"'=") for x in r["hallazgos"]
                      if x["regla"] == "check:registro_deps.inexistente")

    def test_sigue_los_r_de_requirements(self):
        self.escribir("requirements.txt", "requests\n-r deps/base.txt\n")
        self.escribir("deps/base.txt", "flask-alucinado-zz93\n-c ../constraints.txt\n")
        self.escribir("constraints.txt", "pytest==8.0\n")
        r = self.analizar()
        self.assertEqual([x["archivo"] for x in r["hallazgos"] if x["regla"] == "check:registro_deps.inexistente"],
                         ["deps/base.txt"], r)

    def test_r_que_sale_del_proyecto_o_no_existe_impide_el_pase(self):
        self.escribir("requirements.txt", "requests\n-r no-existe.txt\n")
        r = self.analizar()
        self.assertEqual(r["checks_pass"], [], r)
        self.assertIn("no-existe.txt", r["motivo"])

    def test_dependency_groups_y_grupos_de_poetry(self):
        self.escribir("pyproject.toml",
                      '[project]\nname = "x"\nversion = "0.1"\ndependencies = ["requests"]\n\n'
                      '[dependency-groups]\ndev = ["pytest-alucinado-zz91", {include-group = "otro"}]\n'
                      'otro = ["pytest"]\n\n'
                      '[tool.poetry.group.dev.dependencies]\notro-alucinado-zz92 = "^1.0"\n\n'
                      '[tool.poetry.dev-dependencies]\ntercero-alucinado-zz94 = "^1"\n')
        r = self.analizar()
        nombres = {x["evidencia"] for x in r["hallazgos"] if x["regla"] == "check:registro_deps.inexistente"}
        texto = " ".join(nombres)
        for n in ("pytest-alucinado-zz91", "otro-alucinado-zz92", "tercero-alucinado-zz94"):
            self.assertIn(n, texto, r)

    def test_setup_py_setup_cfg_environment_impiden_el_pase(self):
        casos = {"setup.py": 'from setuptools import setup\nsetup(name="x", install_requires=["magicz-7781"])\n',
                 "setup.cfg": "[options]\ninstall_requires =\n    magicz-7781\n",
                 "environment.yml": "name: x\ndependencies:\n  - python=3.11\n  - pip:\n    - magicz-7781\n"}
        for nombre, texto in casos.items():
            with self.subTest(manifiesto=nombre):
                self.escribir("requirements.txt", "requests\n")
                self.escribir(nombre, texto)
                r = self.analizar()
                self.assertEqual(r["checks_pass"], [], nombre)
                self.assertIn(nombre, r["motivo"])
                (self.dir / nombre).unlink()

    def test_estado_queda_no_evaluado(self):
        self.escribir("requirements.txt", "requests\n")
        self.escribir("setup.py", 'setup(install_requires=["magicz-7781"])\n')
        r = self.analizar()
        self.assertEqual(calc("SEG-DEPS-EXISTEN", {"registro_deps": "ok"},
                              checks={p["regla"] for p in r["checks_pass"]})["estado"], "no_evaluado")


if __name__ == "__main__":
    unittest.main()
