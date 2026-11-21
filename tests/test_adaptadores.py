"""Tests de scripts/adaptadores/*.sh, scripts/con_timeout.py y scripts/ejecutar_scanners.sh.

Integración con las herramientas reales cuando no requieren red (gitleaks, semgrep solo con reglas
locales, zizmor --offline). osv-scanner necesita red: se prueba con un binario falso.
Los secretos de las fixtures son canarios generados al azar en cada corrida.
"""
import json
import os
import secrets
import shutil
import stat
import string
import subprocess
import sys
import time
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
ADAPT = RAIZ / "scripts" / "adaptadores"
TIMEOUT_PY = RAIZ / "scripts" / "con_timeout.py"
DESPACHADOR = RAIZ / "scripts" / "ejecutar_scanners.sh"
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
TMP_BASE.mkdir(parents=True, exist_ok=True)
CAMPOS_META = {"herramienta", "version", "estado", "exit_code", "duracion_s", "comando", "error"}


def azar(n, alfabeto=string.ascii_letters + string.digits):
    return "".join(secrets.choice(alfabeto) for _ in range(n))


def pat_canario():
    return "ghp_" + azar(36)


def escribir_falso(directorio, nombre, cuerpo):
    ruta = Path(directorio) / nombre
    ruta.write_text("#!/bin/bash\n" + cuerpo + "\n")
    ruta.chmod(ruta.stat().st_mode | stat.S_IXUSR)
    return ruta


def herramienta_disponible(nombre):
    return shutil.which(nombre) is not None


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = TMP_BASE / f"adapt_{self.id().split('.')[-1]}_{azar(6)}"
        self.proy = self.dir / "proyecto"
        self.crudo = self.dir / "corrida" / "crudo"
        self.proy.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.env = dict(os.environ, TMPDIR=str(TMP_BASE), GIT_CEILING_DIRECTORIES=str(TMP_BASE),
                        AUDITOR_SEMGREP_REGISTRO="", AUDITOR_REGISTRO_SIN_RED="1")

    def escribir(self, rel, texto):
        p = self.proy / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(texto, encoding="utf-8")
        return p

    def correr(self, script, *extra, env=None, timeout=300):
        return subprocess.run(["bash", str(script), str(self.proy), str(self.crudo), *extra],
                              capture_output=True, text=True, env=env or self.env, timeout=timeout)

    def meta(self, nombre):
        datos = json.loads((self.crudo / f"{nombre}.meta.json").read_text())
        self.assertTrue(CAMPOS_META <= set(datos), datos)
        return datos


# ----------------------------------------------------------------------------- con_timeout

class TestConTimeout(unittest.TestCase):
    def test_pasa_codigo_de_salida(self):
        r = subprocess.run([sys.executable, str(TIMEOUT_PY), "5", "bash", "-c", "exit 7"], capture_output=True)
        self.assertEqual(r.returncode, 7)

    def test_corta_y_mata_al_grupo(self):
        marca = TMP_BASE / f"hijo_{azar(6)}"
        inicio = time.monotonic()
        r = subprocess.run([sys.executable, str(TIMEOUT_PY), "1", "bash", "-c",
                            f"(sleep 3; touch '{marca}') & sleep 30"], capture_output=True)
        self.assertEqual(r.returncode, 124)
        self.assertLess(time.monotonic() - inicio, 10)
        time.sleep(3.5)
        self.assertFalse(marca.exists(), "el proceso hijo debió morir con el grupo")

    def test_uso_incorrecto(self):
        r = subprocess.run([sys.executable, str(TIMEOUT_PY), "x", "true"], capture_output=True)
        self.assertEqual(r.returncode, 2)


# ----------------------------------------------------------------------------- ausente

class TestHerramientaAusente(Base):
    def test_cada_adaptador_ausente_deja_meta(self):
        env = dict(self.env)
        for var in ("GITLEAKS", "SEMGREP", "OSV", "ZIZMOR"):
            env[f"AUDITOR_BIN_{var}"] = str(self.dir / "no-existe")
        self.escribir(".github/workflows/ci.yml", "on: push\njobs: {}\n")
        for nombre, script in (("gitleaks", "gitleaks.sh"), ("semgrep", "semgrep.sh"), ("osv", "osv.sh"),
                               ("zizmor", "zizmor.sh")):
            r = self.correr(ADAPT / script, env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            m = self.meta(nombre)
            self.assertEqual(m["estado"], "ausente")
            self.assertEqual(m["herramienta"], nombre)
            self.assertIsNone(m["version"])
            self.assertIn("no está instalad", m["error"])


# ----------------------------------------------------------------------------- gitleaks

@unittest.skipUnless(herramienta_disponible("gitleaks"), "gitleaks no instalado")
class TestGitleaks(Base):
    def test_working_tree_bundle_ignorado_e_historial(self):
        canario_src, canario_dist, canario_hist = pat_canario(), pat_canario(), pat_canario()
        self.escribir("src/config.js", f"export const token = '{canario_src}'\n")
        self.escribir(".gitignore", "dist/\nnode_modules/\n")
        self.escribir("dist/assets/index.js", f'const t="{canario_dist}";\n')
        self.escribir("node_modules/x/index.js", f"const t = '{pat_canario()}'\n")
        # historial: un secreto que se agregó y luego se borró
        subprocess.run(["git", "init", "-q", str(self.proy)], check=True, env=self.env)
        h = self.escribir("viejo.js", f"const t = '{canario_hist}'\n")
        git = ["git", "-C", str(self.proy), "-c", "user.email=a@b.c", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
        subprocess.run(git + ["add", "viejo.js", ".gitignore"], check=True, env=self.env)
        subprocess.run(git + ["commit", "-qm", "x"], check=True, env=self.env)
        h.unlink()
        subprocess.run(git + ["commit", "-qam", "borra"], check=True, env=self.env)

        r = self.correr(ADAPT / "gitleaks.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        m = self.meta("gitleaks")
        self.assertEqual(m["estado"], "ok", m)
        self.assertEqual(m["exit_code"], 0)
        self.assertRegex(m["version"], r"^\d+\.\d+\.\d+$")
        modos = {e["modo"]: e for e in m["ejecuciones"]}
        self.assertEqual(set(modos), {"dir", "git", "bundle"})

        arbol = json.loads((self.crudo / "gitleaks.json").read_text())
        self.assertEqual({x["File"] for x in arbol}, {"src/config.js"})  # sin node_modules ni dist
        bundle = json.loads((self.crudo / "gitleaks-bundle.json").read_text())
        self.assertEqual([x["File"] for x in bundle], ["dist/assets/index.js"])
        hist = json.loads((self.crudo / "gitleaks-git.json").read_text())
        self.assertIn("viejo.js", {x["File"] for x in hist})

    def test_config_del_proyecto_no_desactiva_reglas(self):
        self.escribir("src/a.js", f"const t = '{pat_canario()}'\n")
        self.escribir(".gitleaks.toml", '[allowlist]\npaths = [".*"]\n')
        r = self.correr(ADAPT / "gitleaks.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        arbol = json.loads((self.crudo / "gitleaks.json").read_text())
        self.assertEqual(len(arbol), 1)
        modos = {e["modo"] for e in self.meta("gitleaks")["ejecuciones"]}
        self.assertEqual(modos, {"dir"})  # sin repo ni carpetas de build

    def test_gitleaksignore_del_proyecto_queda_registrado(self):
        # gitleaks siempre lee el .gitleaksignore de la carpeta escaneada (no hay opción para
        # apagarlo): el adaptador no puede impedirlo, pero lo deja a la vista en el meta.
        self.escribir("src/a.js", f"const t = '{pat_canario()}'\n")
        self.escribir(".gitleaksignore", "# silenciado\nsrc/a.js:github-pat:1\n")
        self.correr(ADAPT / "gitleaks.sh")
        m = self.meta("gitleaks")
        self.assertEqual(m["gitleaksignore_proyecto"], {"archivo": ".gitleaksignore", "entradas": 1})

    def test_sin_hallazgos_lista_vacia(self):
        self.escribir("src/a.js", "console.log('hola')\n")
        self.correr(ADAPT / "gitleaks.sh")
        self.assertEqual(json.loads((self.crudo / "gitleaks.json").read_text()), [])
        self.assertEqual(self.meta("gitleaks")["estado"], "ok")

    def test_error_de_la_herramienta(self):
        falsos = self.dir / "bin"
        falsos.mkdir()
        escribir_falso(falsos, "gitleaks", 'case "$1" in version) echo 8.0.0;; *) echo boom >&2; exit 2;; esac')
        env = dict(self.env, AUDITOR_BIN_GITLEAKS=str(falsos / "gitleaks"))
        r = self.correr(ADAPT / "gitleaks.sh", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        m = self.meta("gitleaks")
        self.assertEqual(m["estado"], "error")
        self.assertEqual(m["exit_code"], 2)
        self.assertIn("boom", m["error"])


# ----------------------------------------------------------------------------- semgrep

@unittest.skipUnless(herramienta_disponible("semgrep"), "semgrep no instalado")
class TestSemgrep(Base):
    def setUp(self):
        super().setUp()
        # semgrep respeta el .gitignore del repo que contiene la carpeta, y tests/.tmp está ignorado en el
        # repo del auditor: cada fixture se vuelve su propio repo (como un proyecto real).
        subprocess.run(["git", "init", "-q", str(self.proy)], check=True, env=self.env)

    def test_reglas_locales_sarif(self):
        self.escribir("server/r.js", "router.post('/x', (req, res) => { res.json(eval(req.body.f)) })\n")
        self.escribir("node_modules/y/i.js", "eval(req.body.f)\n")
        r = self.correr(ADAPT / "semgrep.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        m = self.meta("semgrep")
        self.assertEqual(m["estado"], "ok", m)
        self.assertIn("--metrics=off", m["comando"])
        self.assertNotIn("p/owasp-top-ten", m["comando"])
        sarif = json.loads((self.crudo / "semgrep.sarif").read_text())
        resultados = sarif["runs"][0]["results"]
        self.assertEqual(len(resultados), 1)
        self.assertTrue(resultados[0]["ruleId"].endswith("vibe-coding.eval-dinamico"))
        uri = resultados[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "server/r.js")

    def test_fallo_del_registro_sigue_con_reglas_locales(self):
        self.escribir("a.js", "eval(x + y)\n")
        env = dict(self.env, AUDITOR_SEMGREP_REGISTRO=str(self.dir / "config-que-no-existe.yaml"))
        r = self.correr(ADAPT / "semgrep.sh", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        m = self.meta("semgrep")
        self.assertEqual(m["estado"], "parcial", m)
        self.assertIn("config-que-no-existe", m["error"])
        sarif = json.loads((self.crudo / "semgrep.sarif").read_text())
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)


# ----------------------------------------------------------------------------- osv (falso)

class TestOsv(Base):
    def falso(self, codigo, salida_json):
        falsos = self.dir / "bin"
        falsos.mkdir(exist_ok=True)
        cuerpo = f"""if [ "$1" = "--version" ]; then echo 'osv-scanner version: 2.7.0'; exit 0; fi
salida=""
while [ $# -gt 0 ]; do case "$1" in --output-file) salida="$2"; shift 2;; *) shift;; esac; done
[ -n "$salida" ] && printf '%s' '{salida_json}' > "$salida"
exit {codigo}"""
        escribir_falso(falsos, "osv-scanner", cuerpo)
        return dict(self.env, AUDITOR_BIN_OSV=str(falsos / "osv-scanner"))

    def test_vulnerabilidades_exit_1_es_ok(self):
        env = self.falso(1, '{"results": [{"packages": [{"vulnerabilities": [{"id": "GHSA-x"}]}]}]}')
        r = self.correr(ADAPT / "osv.sh", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        m = self.meta("osv")
        self.assertEqual((m["estado"], m["exit_code"], m["version"]), ("ok", 1, "2.7.0"))
        self.assertIn("--format json", m["comando"])
        self.assertIn(" -r ", m["comando"])
        self.assertEqual(json.loads((self.crudo / "osv.json").read_text())["results"][0]["packages"][0]
                         ["vulnerabilities"][0]["id"], "GHSA-x")

    def test_sin_paquetes_128_es_ok(self):
        env = self.falso(128, "")
        self.correr(ADAPT / "osv.sh", env=env)
        m = self.meta("osv")
        self.assertEqual(m["estado"], "ok")
        self.assertEqual(json.loads((self.crudo / "osv.json").read_text()), {"results": []})

    def test_error_127(self):
        env = self.falso(127, "")
        self.correr(ADAPT / "osv.sh", env=env)
        self.assertEqual(self.meta("osv")["estado"], "error")


# ----------------------------------------------------------------------------- zizmor

@unittest.skipUnless(herramienta_disponible("zizmor"), "zizmor no instalado")
class TestZizmor(Base):
    def test_sin_workflows_no_aplica(self):
        r = self.correr(ADAPT / "zizmor.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.meta("zizmor")["estado"], "no_aplica")

    def test_workflow_inseguro_sarif(self):
        self.escribir(".github/workflows/x.yml", """on:
  pull_request_target:
permissions: write-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
""")
        self.escribir("zizmor.yml", "rules:\n  dangerous-triggers:\n    disable: true\n")
        r = self.correr(ADAPT / "zizmor.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        m = self.meta("zizmor")
        self.assertEqual(m["estado"], "ok", m)
        self.assertIn("--offline", m["comando"])
        sarif = json.loads((self.crudo / "zizmor.sarif").read_text())
        reglas = {x["ruleId"] for x in sarif["runs"][0]["results"]}
        self.assertIn("zizmor/dangerous-triggers", reglas)  # la config del proyecto no la desactiva
        self.assertIn("zizmor/template-injection", reglas)

    def test_uris_relativas_al_proyecto_aunque_este_dentro_de_otro_repo(self):
        # zizmor informa rutas relativas a la raíz del repo git; el adaptador las deja relativas al proyecto.
        subprocess.run(["git", "init", "-q", str(self.dir)], check=True, env=self.env)
        self.escribir(".github/workflows/x.yml", "on:\n  pull_request_target:\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                      "    steps:\n      - uses: actions/checkout@v4\n")
        self.correr(ADAPT / "zizmor.sh")
        sarif = json.loads((self.crudo / "zizmor.sarif").read_text())
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in sarif["runs"][0]["results"]}
        self.assertEqual(uris, {".github/workflows/x.yml"})
        self.assertGreater(self.meta("zizmor")["uris_reescritas"], 0)


# ----------------------------------------------------------------------------- despachador

class TestDespachador(Base):
    def falsos(self, lento=None):
        """Binarios falsos rápidos para las 4 herramientas; `lento` duerme 30 s."""
        d = self.dir / "bin"
        d.mkdir(exist_ok=True)
        env = dict(self.env)
        for var, nombre, cuerpo in (
            ("GITLEAKS", "gitleaks", 'r=""; while [ $# -gt 0 ]; do [ "$1" = --report-path ] && r="$2"; shift; done; '
                                     '[ -n "$r" ] && echo "[]" > "$r"; exit 0'),
            ("SEMGREP", "semgrep", 'o=""; while [ $# -gt 0 ]; do [ "$1" = --output ] && o="$2"; shift; done; '
                                   '[ -n "$o" ] && echo \'{"version":"2.1.0","runs":[{"results":[{"ruleId":"a"},{"ruleId":"b"}]}]}\' > "$o"; exit 0'),
            ("OSV", "osv-scanner", 'o=""; while [ $# -gt 0 ]; do [ "$1" = --output-file ] && o="$2"; shift; done; '
                                   '[ -n "$o" ] && echo \'{"results":[]}\' > "$o"; exit 0'),
            ("ZIZMOR", "zizmor", 'echo \'{"version":"2.1.0","runs":[{"results":[]}]}\'; exit 0'),
        ):
            pre = 'if [ "$1" = "--version" ] || [ "$1" = version ]; then echo 1.0.0; exit 0; fi\n'
            if nombre == lento:
                pre += "sleep 30\n"
            escribir_falso(d, nombre, pre + cuerpo)
            env[f"AUDITOR_BIN_{var}"] = str(d / nombre)
        return env

    def correr_despachador(self, *args, env):
        return subprocess.run(["bash", str(DESPACHADOR), *args], capture_output=True, text=True, env=env, timeout=120)

    def test_posicional_despacha_todo_y_resume(self):
        self.escribir("package.json", '{"dependencies": {"react": "18.3.1"}}')
        self.escribir(".env", "VITE_DB_PASSWORD=" + azar(20) + "\n")
        self.escribir(".github/workflows/ci.yml", "on: push\njobs: {}\n")
        corrida = self.crudo.parent
        r = self.correr_despachador(str(self.proy), str(corrida), "rapido", env=self.falsos())
        self.assertEqual(r.returncode, 0, r.stderr)
        for meta in ("gitleaks", "semgrep", "osv", "zizmor", "check_env_publicas", "check_registro_deps",
                     "check_archivos_clave", "check_config_agentes"):
            self.assertTrue((self.crudo / f"{meta}.meta.json").exists(), meta)
        resumen = json.loads((self.crudo / "resumen_scan.json").read_text())
        self.assertEqual(resumen["modo"], "rapido")
        por = {x["herramienta"]: x for x in resumen["herramientas"]}
        self.assertEqual(por["semgrep"]["hallazgos"], 2)
        self.assertEqual(por["check:env_publicas"]["hallazgos"], 1)
        self.assertEqual(por["check:registro_deps"]["estado"], "no_evaluado")
        self.assertIn("semgrep", r.stdout)  # tabla legible por stdout

    def test_banderas_como_bin_auditar(self):
        corrida = self.crudo.parent
        r = self.correr_despachador("--proyecto", str(self.proy), "--corrida", str(corrida), "--modo", "estandar",
                                    env=self.falsos())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.crudo / "resumen_scan.json").exists())

    def test_timeout_por_herramienta(self):
        corrida = self.crudo.parent
        env = dict(self.falsos(lento="semgrep"), AUDITOR_TIMEOUT_S="2")
        inicio = time.monotonic()
        r = self.correr_despachador(str(self.proy), str(corrida), "rapido", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertLess(time.monotonic() - inicio, 25)
        m = self.meta("semgrep")
        self.assertEqual(m["estado"], "timeout")
        self.assertEqual(m["exit_code"], 124)
        self.assertEqual(self.meta("gitleaks")["estado"], "ok")

    def test_uso_incorrecto(self):
        r = self.correr_despachador(str(self.dir / "no-existe"), str(self.crudo.parent), env=self.env)
        self.assertEqual(r.returncode, 2)
        r = self.correr_despachador(str(self.proy), str(self.crudo.parent), "turbo", env=self.env)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
