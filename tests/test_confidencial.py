"""Tests de DECISIONES.md #3 generalizada: carpetas y archivos confidenciales (config/confidencial.toml).

- Ningún adaptador ni el normalizador producen evidencia a partir del CONTENIDO de esas rutas.
- scripts/checks/datos_confidenciales.py reporta solo metadatos (existencia, n.º de archivos, tamaño,
  .gitignore, versionado en git) y nunca abre esos archivos.
- Prueba de punta a punta: ningún byte del contenido confidencial aparece en los artefactos.
Los canarios son valores FALSOS generados al azar en cada corrida.
"""
import builtins
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import catalogo  # noqa: E402
import datos_confidenciales as dc  # noqa: E402
import utiles  # noqa: E402
from normalizar import run as n_run  # noqa: E402

sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
TMP_BASE.mkdir(parents=True, exist_ok=True)
GIT_ID = ["-c", "user.name=prueba", "-c", "user.email=prueba@example.invalid", "-c", "commit.gpgsign=false"]


def azar(n, alfabeto=string.ascii_uppercase + string.digits):
    return "".join(secrets.choice(alfabeto) for _ in range(n))


def git(proy, *args):
    return subprocess.run(["git", *GIT_ID, "-C", str(proy), *args], capture_output=True, text=True,
                          env=dict(os.environ, GIT_CEILING_DIRECTORIES=str(TMP_BASE)), check=True)


class TestConfig(unittest.TestCase):
    def test_patrones_por_defecto(self):
        conf = dc.cargar()
        for carpeta in ("datos-reales", "datos-abiertos", "data/raw"):
            self.assertIn(carpeta, conf["carpetas"])
        # DECISIONES #12 (ronda 6, verificación ciega node-next): «pacientes»/«patients» pasan de `carpetas`
        # (todo confidencial) a `carpetas_ambiguas` (solo sus archivos de datos son confidenciales).
        for carpeta in ("pacientes", "patients"):
            self.assertIn(carpeta, conf["carpetas_ambiguas"])
            self.assertNotIn(carpeta, conf["carpetas"])
        for patron in ("*.dcm", "*.DCM"):
            self.assertIn(patron, conf["archivos"])

    def test_es_confidencial(self):
        si = ("datos-reales/a.csv", "x/datos-reales/b/c.json", "datos-abiertos/z.edf", "data/raw/s.csv",
              "app/data/raw/s.csv", "pacientes/p.json", "img/estudio.dcm", "IMG/ESTUDIO.DCM", "datos-reales")
        no = ("src/datos-reales.js", "data/raw.js", "data/rawdata/x.csv", "src/app.js", "docs/pacientes.md")
        for r in si:
            self.assertTrue(dc.es_confidencial(r), r)
        for r in no:
            self.assertFalse(dc.es_confidencial(r), r)

    def test_exclusiones_semgrep(self):
        ex = dc.exclusiones_semgrep()
        for e in ("datos-reales", "data/raw", "**/data/raw", "*.dcm", "*.DCM"):
            self.assertIn(e, ex)

    def test_regex_gitleaks(self):
        import re
        rx = [re.compile(r) for r in dc.regex_gitleaks()]
        # DECISIONES #12 (ronda 6): en una carpeta ambigua solo se excluyen los archivos de datos; antes el caso era
        # «a/pacientes/b» (sin extensión), que ahora no se distingue de una subcarpeta y se escanea como el resto.
        for ruta in ("datos-reales/a.js", "sub/data/raw/b.txt", "img/x.DCM", "a/pacientes/b.csv", "a/PATIENTS/x/b.Json"):
            self.assertTrue(any(r.search(ruta) for r in rx), ruta)
        for ruta in ("src/app.js", "a/pacientes/b.js", "pages/api/patients/search.ts", "a/pacientes/b"):
            self.assertFalse(any(r.search(ruta) for r in rx), ruta)

    def test_config_gitleaks_extiende_la_base(self):
        base = RAIZ / "reglas" / "gitleaks" / "arbol.toml"
        texto = dc.config_gitleaks(base)
        import tomllib
        d = tomllib.loads(texto)
        self.assertEqual(d["extend"]["path"], str(base))
        self.assertTrue(d["allowlists"][0]["paths"])

    def test_ruta_alternativa_por_entorno(self):
        tmp = Path(ap.tmp_dir())
        try:
            alt = tmp / "c.toml"
            alt.write_text('carpetas = ["secreto-x"]\narchivos = ["*.zz"]\n', encoding="utf-8")
            with mock.patch.dict(os.environ, {"AUDITOR_CONFIDENCIAL": str(alt)}):
                self.assertTrue(dc.es_confidencial("secreto-x/a"))
                self.assertFalse(dc.es_confidencial("datos-reales/a"))
        finally:
            ap.limpiar(tmp)


class TestCatalogo(unittest.TestCase):
    def test_dat_pii_repo(self):
        c = {x["id"]: x for x in catalogo.cargar_catalogo()}["DAT-PII-REPO"]
        self.assertEqual(c["titulo"], "Datos personales o de salud versionados en el repositorio")
        self.assertEqual(c["gate"], "N1")
        self.assertIs(c["bloquea_global"], True)
        self.assertEqual(c["severidad_base"], "critica")
        self.assertEqual(catalogo.control_por_regla("check", "datos_confidenciales.trackeado"), "DAT-PII-REPO")


class TestCheck(unittest.TestCase):
    def setUp(self):
        self.dir = Path(ap.tmp_dir(self))
        self.addCleanup(ap.limpiar, self.dir)
        self.proy = self.dir / "proy"
        self.canario = "PACIENTE-" + azar(16)
        for rel in ("datos-reales/p1.csv", "datos-reales/sub/p2.csv", "img/estudio.dcm"):
            p = self.proy / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(f"rut,nombre\n{self.canario},x\n", encoding="utf-8")
        (self.proy / "src").mkdir()
        (self.proy / "src" / "app.js").write_text("console.log(1)\n", encoding="utf-8")

    def _analizar_sin_leer_contenido(self):
        abrir = builtins.open
        abrir_os = os.open
        base = os.path.realpath(self.proy) + os.sep
        conf = dc.cargar()  # se lee antes: el TOML de configuración no es confidencial

        def prohibido(f):
            if not isinstance(f, (str, bytes, os.PathLike)):
                return False
            real = os.path.realpath(os.fsdecode(f))
            return real.startswith(base) and dc.es_confidencial(real[len(base):], conf)

        def vigilado(f, *a, **kw):
            if prohibido(f):
                raise AssertionError(f"el check abrió un archivo confidencial: {f}")
            return abrir(f, *a, **kw)

        def vigilado_os(f, *a, **kw):
            if prohibido(f):
                raise AssertionError(f"el check abrió un archivo confidencial: {f}")
            return abrir_os(f, *a, **kw)
        with mock.patch("builtins.open", vigilado), mock.patch("os.open", vigilado_os), \
                mock.patch.object(dc, "cargar", return_value=conf):
            return dc.analizar(self.proy)

    def test_repo_sin_commits_inventario_y_pass(self):
        # Antes se llamaba test_sin_git_…: los temporales vivían en tests/.tmp, DENTRO del repo del auditor, y el test
        # pasaba por ese repo padre. Con los temporales fuera del árbol, el caso «repo sin nada versionado y candidatos
        # locales (ignorados, como lo estaba tests/.tmp)» se arma explícito con git init y .gitignore; sin repo el check
        # declara no_aplica (test_sin_git_no_aplica).
        git(self.proy, "init", "-q")
        (self.proy / ".gitignore").write_text("datos-reales/\n*.dcm\n", encoding="utf-8")
        res = self._analizar_sin_leer_contenido()
        self.assertEqual(res["estado"], "ok")
        inv = {i["ruta"]: i for i in res["inventario"]}
        self.assertEqual(inv["datos-reales"]["archivos"], 2)
        self.assertGreater(inv["datos-reales"]["bytes"], 0)
        self.assertIn("img/estudio.dcm", inv)
        self.assertEqual(res["hallazgos"], [])
        self.assertIn("check:datos_confidenciales.no_trackeado", [p["regla"] for p in res["checks_pass"]])
        self.assertNotIn(self.canario, json.dumps(res))

    def test_sin_git_no_aplica(self):
        res = self._analizar_sin_leer_contenido()
        self.assertEqual(res["estado"], "no_aplica")
        self.assertEqual(res["checks_pass"], [])
        inv = {i["ruta"]: i for i in res["inventario"]}
        self.assertEqual(inv["datos-reales"]["archivos"], 2)
        self.assertNotIn(self.canario, json.dumps(res))

    def test_trackeado_es_critico_con_ruta_y_conteo(self):
        git(self.proy, "init", "-q")
        git(self.proy, "add", "-A")
        git(self.proy, "commit", "-q", "-m", "x")
        res = self._analizar_sin_leer_contenido()
        trk = [h for h in res["hallazgos"] if h["regla"] == "check:datos_confidenciales.trackeado"]
        self.assertEqual({h["archivo"] for h in trk}, {"datos-reales", "img/estudio.dcm"})
        dr = [h for h in trk if h["archivo"] == "datos-reales"][0]
        self.assertEqual(dr["severidad_sugerida"], "critica")
        self.assertIn("2", dr["evidencia"])
        self.assertNotIn(self.canario, json.dumps(res))
        inv = {i["ruta"]: i for i in res["inventario"]}
        self.assertEqual(inv["datos-reales"]["trackeados"], 2)
        self.assertIs(inv["datos-reales"]["en_gitignore"], False)

    def test_ignorado_y_no_trackeado(self):
        git(self.proy, "init", "-q")
        (self.proy / ".gitignore").write_text("datos-reales/\n*.dcm\n", encoding="utf-8")
        git(self.proy, "add", "-A")
        git(self.proy, "commit", "-q", "-m", "x")
        res = self._analizar_sin_leer_contenido()
        self.assertEqual([h for h in res["hallazgos"] if h["regla"].endswith(".trackeado")], [])
        inv = {i["ruta"]: i for i in res["inventario"]}
        self.assertIs(inv["datos-reales"]["en_gitignore"], True)
        self.assertEqual(inv["datos-reales"]["trackeados"], 0)

    def test_no_ignorado_es_aviso(self):
        git(self.proy, "init", "-q")
        res = self._analizar_sin_leer_contenido()
        sin = [h for h in res["hallazgos"] if h["regla"] == "check:datos_confidenciales.sin_gitignore"]
        self.assertTrue(sin)
        self.assertEqual(catalogo.control_por_regla("check", "datos_confidenciales.sin_gitignore"),
                         "DAT-PII-INVENTARIO")

    def test_cli_escribe_check_y_meta(self):
        crudo = self.dir / "crudo"
        r = subprocess.run([sys.executable, str(RAIZ / "scripts" / "checks" / "datos_confidenciales.py"),
                            str(self.proy), str(crudo)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((crudo / "check_datos_confidenciales.json").is_file())
        self.assertTrue((crudo / "check_datos_confidenciales.meta.json").is_file())
        self.assertNotIn(self.canario, (crudo / "check_datos_confidenciales.json").read_text(encoding="utf-8"))


class TestNormalizarDescarta(unittest.TestCase):
    def test_hallazgo_en_ruta_confidencial_no_llega_a_artefactos(self):
        tmp = Path(ap.tmp_dir())
        try:
            c = ap.preparar_corrida(tmp)
            canario = "PACIENTE-" + azar(16)
            (c / "crudo" / "check_env_publicas.json").write_text(json.dumps({
                "estado": "ok", "motivo": None, "checks_pass": [], "hallazgos": [
                    {"regla": "check:env_publicas.valor", "archivo": "datos-reales/.env", "linea": 1,
                     "mensaje": "valor", "evidencia": canario, "severidad_sugerida": "critica"}]}), encoding="utf-8")
            limitados, todos, resumen = n_run.normalizar(c)
            self.assertNotIn(canario, json.dumps(todos))
            self.assertGreaterEqual(resumen["excluidos_confidenciales"], 1)
        finally:
            ap.limpiar(tmp)

    def test_normalize_invoca_el_check_si_falta(self):
        tmp = Path(ap.tmp_dir())
        try:
            c = ap.preparar_corrida(tmp)
            n_run.main([str(c)])
            self.assertTrue((c / "crudo" / "check_datos_confidenciales.json").is_file())
            r = {x["control"]: x for x in __import__("estado").generar(c)["controles"]}
            # Ronda 1 de pases vacíos: la app sembrada está en un repo git sin archivos versionados ni candidatos
            # confidenciales → el check declara no_aplica (antes daba un pase vacío). Lo que se prueba es que normalize
            # invoque el check y que el estado salga de él (no quede no_evaluado por falta del check).
            self.assertIn(r["DAT-PII-REPO"]["estado"], ("pass", "fail", "no_aplica"))
        finally:
            ap.limpiar(tmp)


class TestAdaptadores(unittest.TestCase):
    def setUp(self):
        self.dir = Path(ap.tmp_dir(self))
        self.addCleanup(ap.limpiar, self.dir)
        self.proy = self.dir / "proy"
        (self.proy / "src").mkdir(parents=True)
        (self.proy / "src" / "a.js").write_text("eval(x)\n", encoding="utf-8")
        self.crudo = self.dir / "crudo"

    def test_semgrep_recibe_exclusiones(self):
        bindir = self.dir / "bin"
        bindir.mkdir()
        args = self.dir / "args.txt"
        falso = bindir / "semgrep"
        falso.write_text("#!/bin/bash\nif [ \"$1\" = --version ]; then echo 1.0.0; exit 0; fi\n"
                         f"printf '%s\\n' \"$@\" > '{args}'\n"
                         "while [ $# -gt 0 ]; do if [ \"$1\" = --output ]; then echo '{\"runs\": []}' > \"$2\"; fi; shift; done\n")
        falso.chmod(0o755)
        env = dict(os.environ, AUDITOR_BIN_SEMGREP=str(falso), AUDITOR_SEMGREP_REGISTRO="")
        r = subprocess.run(["bash", str(RAIZ / "scripts" / "adaptadores" / "semgrep.sh"), str(self.proy),
                            str(self.crudo)], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        lineas = args.read_text().splitlines()
        excl = {lineas[i + 1] for i, x in enumerate(lineas) if x == "--exclude"}
        for e in ("datos-reales", "**/data/raw", "*.dcm"):
            self.assertIn(e, excl)
        meta = json.loads((self.crudo / "semgrep.meta.json").read_text())
        self.assertIn("datos-reales", meta.get("exclusiones_confidenciales", []))

    @unittest.skipUnless(shutil.which("gitleaks"), "gitleaks no instalado")
    def test_gitleaks_no_escanea_confidenciales(self):
        token_conf = "ghp_" + azar(32, string.ascii_letters + string.digits) + "QZXW"
        token_ok = "ghp_" + azar(36, string.ascii_letters + string.digits)
        (self.proy / "datos-reales").mkdir()
        (self.proy / "datos-reales" / "k.js").write_text(f'const t = "{token_conf}";\n', encoding="utf-8")
        (self.proy / "estudio.dcm").write_text(f'token = "{token_conf}"\n', encoding="utf-8")
        (self.proy / "src" / "k.js").write_text(f'const t = "{token_ok}";\n', encoding="utf-8")
        git(self.proy, "init", "-q")
        git(self.proy, "add", "-A")
        git(self.proy, "commit", "-q", "-m", "x")
        env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(TMP_BASE))
        r = subprocess.run(["bash", str(RAIZ / "scripts" / "adaptadores" / "gitleaks.sh"), str(self.proy),
                            str(self.crudo)], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        dir_ = json.loads((self.crudo / "gitleaks.json").read_text())
        hist = json.loads((self.crudo / "gitleaks-git.json").read_text())
        self.assertTrue(any(f["File"].endswith("src/k.js") for f in dir_))  # control positivo
        for f in dir_ + hist:
            self.assertFalse(dc.es_confidencial(f["File"]), f["File"])
        for p in self.crudo.rglob("*"):
            if p.is_file():
                self.assertNotIn(token_conf[-12:], p.read_text(encoding="utf-8", errors="replace"), p)
        meta = json.loads((self.crudo / "gitleaks.meta.json").read_text())
        self.assertIn("datos-reales", meta.get("exclusiones_confidenciales", []))


@unittest.skipUnless(shutil.which("git"), "git no instalado")
class TestPuntaAPunta(unittest.TestCase):
    """bin/auditar all sobre un repo con datos confidenciales versionados: el contenido no sale."""

    def test_ningun_byte_confidencial_en_artefactos(self):
        base = Path(ap.tmp_dir())
        self.addCleanup(ap.limpiar, base)
        proy = base / "proy"
        canario = "PACIENTE-" + azar(20)
        token = "ghp_" + azar(32, string.ascii_letters + string.digits) + "QZXW"
        archivos = {
            "datos-reales/pacientes.csv": f"rut,diagnostico\n{canario},lumbalgia\n",
            "datos-reales/script.js": f'const k = "{token}"; eval(req.body.x); // {canario}\n',
            "datos-abiertos/.env": f"VITE_SECRET_KEY={token}\n# {canario}\n",
            "data/raw/sesion.csv": f"{canario}\n",
            "pacientes/ficha.json": json.dumps({"rut": canario, "token": token}),
            "estudios/serie.dcm": f"DICM{canario}{token}",
            "src/app.js": "export const x = 1;\n",
        }
        for rel, texto in archivos.items():
            p = proy / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(texto, encoding="utf-8")
        git(proy, "init", "-q")
        git(proy, "add", "-A")
        git(proy, "commit", "-q", "-m", "datos")
        salida = base / "salida"
        env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(TMP_BASE), AUDITOR_SEMGREP_REGISTRO="",
                   AUDITOR_REGISTRO_SIN_RED="1", TMPDIR=str(TMP_BASE))
        r = subprocess.run(["bash", str(RAIZ / "bin" / "auditar"), "all", str(proy), "--modo", "rapido",
                            "--salida", str(salida)], capture_output=True, text=True, env=env, timeout=600)
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        prohibidos = [canario, token, token[-12:], "QZXW"]
        revisados = 0
        for p in salida.rglob("*"):
            if not p.is_file():
                continue
            datos = p.read_bytes()
            revisados += 1
            for x in prohibidos:
                self.assertNotIn(x.encode(), datos, f"{x!r} apareció en {p.relative_to(salida)}")
        self.assertGreater(revisados, 5)
        hall = utiles.leer_jsonl(salida / "hallazgos_todos.jsonl")
        pii = [h for h in hall if h["control"] == "DAT-PII-REPO"]
        self.assertTrue(pii)
        g = json.loads((salida / "gates.json").read_text())
        self.assertIn("DAT-PII-REPO", {b["control"] for b in g["global"]["bloqueos"]})


if __name__ == "__main__":
    unittest.main()
