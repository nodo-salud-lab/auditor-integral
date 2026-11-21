"""D1 y O1 (investigacion/18-evaluacion-herramienta.md): AUDITOR_SIN_RED=1 apaga TODA consulta de red y osv-scanner
no lee las salidas del propio auditor (.auditoria/ ni la carpeta de corrida).

- registro_deps: con AUDITOR_SIN_RED=1 no se abre ninguna conexión (urllib interceptado) y el motivo lo dice;
  AUDITOR_REGISTRO_SIN_RED=1 sigue funcionando (alias, solo para este check).
- osv.sh: con AUDITOR_SIN_RED=1 corre en modo --offline contra una base local ya descargada; si no hay base local
  (o la versión no admite --offline) NO se ejecuta y queda no_evaluado «sin red (AUDITOR_SIN_RED)». Con base local
  queda «parcial» (fail-closed: osv-scanner --offline devuelve 0 resultados en silencio para un ecosistema sin base,
  así que no puede respaldar un pass). Sin la variable, el comportamiento es el de siempre (en línea).
- semgrep.sh: con AUDITOR_SIN_RED=1 no descarga el paquete del registro (solo reglas locales, estado parcial).
- zizmor.sh: con AUDITOR_SIN_RED=1 queda --offline aunque AUDITOR_ZIZMOR_EN_LINEA=1.
- O1: dos corridas seguidas con osv-scanner real (base local fabricada, sin red) dejan crudos de osv iguales.
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_adaptadores import ADAPT, Base, DESPACHADOR, TMP_BASE, azar, escribir_falso  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
CHECKS = RAIZ / "scripts" / "checks"
sys.path.insert(0, str(CHECKS))
import registro_deps  # noqa: E402

TEXTO_SIN_RED = "sin red (AUDITOR_SIN_RED)"
AYUDA_27 = ("   --x-exclude string  exclude directory paths during scanning\n"
            "   --offline           run in offline mode, disabling any features requiring network access\n"
            "   --offline-vulnerabilities  checks for vulnerabilities using local databases\n")
AYUDA_VIEJA = "   --recursive, -r  check subdirectories\n"


def entorno_limpio(**extra):
    env = {k: v for k, v in os.environ.items()
           if k not in ("AUDITOR_SIN_RED", "AUDITOR_REGISTRO_SIN_RED", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY",
                        "OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY", "AUDITOR_ZIZMOR_EN_LINEA", "XDG_CACHE_HOME")}
    env.update(extra)
    return env


# ----------------------------------------------------------------------------- registro_deps

class RespuestaFalsa(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestRegistroSinRed(unittest.TestCase):
    def setUp(self):
        registro_deps._CONTEXTO_TLS = None

    def _prohibido(self, *a, **k):
        raise AssertionError(f"consulta de red con AUDITOR_SIN_RED: {a[0].full_url if a else k}")

    def test_sin_red_global_no_abre_conexion(self):
        with mock.patch.dict(os.environ, entorno_limpio(AUDITOR_SIN_RED="1"), clear=True), \
             mock.patch("urllib.request.urlopen", side_effect=self._prohibido) as abrir:
            with self.assertRaises(registro_deps.ErrorRed) as cm:
                registro_deps.consultar_registro("npm", "react", 5)
            self.assertIn(TEXTO_SIN_RED, str(cm.exception))
            with self.assertRaises(registro_deps.ErrorRed):
                registro_deps._get_json("https://registry.npmjs.org/react", 5)  # defensa en profundidad
            with self.assertRaises(registro_deps.ErrorRed):
                registro_deps.consultar_registro("pypi", "requests", 5)
        abrir.assert_not_called()

    def test_cualquier_valor_distinto_de_0_cuenta_como_no(self):
        with mock.patch.dict(os.environ, entorno_limpio(AUDITOR_SIN_RED="true"), clear=True), \
             mock.patch("urllib.request.urlopen", side_effect=self._prohibido) as abrir:
            with self.assertRaises(registro_deps.ErrorRed):
                registro_deps.consultar_registro("npm", "react", 5)
        abrir.assert_not_called()

    def test_alias_registro_sin_red(self):
        with mock.patch.dict(os.environ, entorno_limpio(AUDITOR_REGISTRO_SIN_RED="1"), clear=True), \
             mock.patch("urllib.request.urlopen", side_effect=self._prohibido) as abrir:
            with self.assertRaises(registro_deps.ErrorRed):
                registro_deps.consultar_registro("npm", "react", 5)
        abrir.assert_not_called()

    def test_sin_variable_consulta_como_siempre(self):
        urls = []

        def falsa(req, timeout=None, context=None):
            urls.append(req.full_url)
            return RespuestaFalsa(json.dumps({"versions": {str(i): {} for i in range(10)}}).encode())

        with mock.patch.dict(os.environ, entorno_limpio(AUDITOR_SIN_RED="0"), clear=True), \
             mock.patch("urllib.request.urlopen", side_effect=falsa):
            r = registro_deps.consultar_registro("npm", "react", 5)
        self.assertEqual(r["existe"], True)
        self.assertEqual(urls, ["https://registry.npmjs.org/react"])

    def test_cli_motivo_explicito(self):
        d = TMP_BASE / f"sinred_reg_{azar(6)}"
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        (d / "p").mkdir(parents=True)
        (d / "p" / "package.json").write_text('{"dependencies": {"react": "18.3.1"}}')
        crudo = d / "c" / "crudo"
        p = subprocess.run([sys.executable, "-I", str(CHECKS / "registro_deps.py"), str(d / "p"), str(crudo)],
                           capture_output=True, text=True, timeout=60,
                           env=entorno_limpio(AUDITOR_SIN_RED="1", PATH="/usr/bin:/bin"))
        self.assertEqual(p.returncode, 0, p.stderr)
        datos = json.loads((crudo / "check_registro_deps.json").read_text())
        self.assertEqual(datos["estado"], "no_evaluado")
        self.assertIn(TEXTO_SIN_RED, datos["motivo"])
        self.assertEqual(datos["checks_pass"], [])
        self.assertEqual(json.loads((crudo / "check_registro_deps.meta.json").read_text())["estado"], "no_evaluado")


# ----------------------------------------------------------------------------- osv.sh (binario falso)

class TestOsvSinRed(Base):
    def setUp(self):
        super().setUp()
        self.registro = self.dir / "args.log"
        self.home = self.dir / "home"
        self.home.mkdir()

    def falso(self, ayuda=AYUDA_27, codigo=0, salida_json='{"results": []}', **extra):
        falsos = self.dir / "bin"
        falsos.mkdir(exist_ok=True)
        cuerpo = f"""if [ "$1" = "--version" ]; then echo 'osv-scanner version: 2.7.0'; exit 0; fi
for a in "$@"; do if [ "$a" = "--help" ]; then printf '%s' '{ayuda}'; exit 0; fi; done
{{ echo "== invocacion"; echo "DB=${{OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY:-}}"; for a in "$@"; do echo "$a"; done; }} >> '{self.registro}'
salida=""
while [ $# -gt 0 ]; do case "$1" in --output-file) salida="$2"; shift 2;; *) shift;; esac; done
[ -n "$salida" ] && printf '%s' '{salida_json}' > "$salida"
exit {codigo}"""
        escribir_falso(falsos, "osv-scanner", cuerpo)
        env = entorno_limpio(TMPDIR=str(TMP_BASE), GIT_CEILING_DIRECTORIES=str(TMP_BASE), AUDITOR_SEMGREP_REGISTRO="",
                             AUDITOR_BIN_OSV=str(falsos / "osv-scanner"), HOME=str(self.home))
        env.update(extra)
        return env

    def invocaciones(self):
        if not self.registro.exists():
            return []
        bloques = self.registro.read_text().split("== invocacion\n")[1:]
        return [b.splitlines() for b in bloques]

    def base_local(self):
        db = self.dir / "osvdb"
        (db / "osv-scalibr" / "npm").mkdir(parents=True)
        with zipfile.ZipFile(db / "osv-scalibr" / "npm" / "all.zip", "w") as z:
            z.writestr("X.json", "{}")
        return db

    def test_sin_red_sin_base_local_no_ejecuta(self):
        vacia = self.dir / "vacia"
        vacia.mkdir()
        env = self.falso(AUDITOR_SIN_RED="1", OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=str(vacia))
        r = self.correr(ADAPT / "osv.sh", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.invocaciones(), [], "osv-scanner no debe escanear sin base local")
        m = self.meta("osv")
        self.assertEqual(m["estado"], "no_evaluado", m)
        self.assertIn(TEXTO_SIN_RED, m["error"])
        self.assertIn("base OSV local", m["error"])
        self.assertFalse((self.crudo / "osv.json").exists())
        self.assertNotIn("api.osv.dev", json.dumps(m["base_osv"]))
        self.assertEqual(m["base_osv"]["modo"], "no_consultada")

    def test_sin_red_con_base_local_corre_offline_y_queda_parcial(self):
        db = self.base_local()
        env = self.falso(AUDITOR_SIN_RED="1", OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=str(db),
                         salida_json='{"results": [{"packages": [{"vulnerabilities": [{"id": "GHSA-x"}]}]}]}',
                         codigo=1)
        self.correr(ADAPT / "osv.sh", env=env)
        inv = self.invocaciones()
        self.assertEqual(len(inv), 1)
        self.assertIn("--offline", inv[0])
        self.assertIn(f"DB={db}", inv[0])
        m = self.meta("osv")
        self.assertEqual(m["estado"], "parcial", m)
        self.assertIn(TEXTO_SIN_RED, m["error"])
        self.assertEqual(m["base_osv"]["modo"], "local_sin_red")
        self.assertNotIn("api.osv.dev", m["base_osv"]["fuente"])
        self.assertTrue((self.crudo / "osv.json").exists())  # los hallazgos de la base local se reportan

    def test_sin_red_base_por_defecto_del_usuario(self):
        db = self.home / "Library" / "Caches"
        (db / "osv-scalibr" / "PyPI").mkdir(parents=True)
        (db / "osv-scalibr" / "PyPI" / "all.zip").write_bytes(b"PK\x05\x06" + b"\0" * 18)
        env = self.falso(AUDITOR_SIN_RED="1", XDG_CACHE_HOME=str(db))
        self.correr(ADAPT / "osv.sh", env=env)
        inv = self.invocaciones()
        self.assertEqual(len(inv), 1)
        self.assertIn("--offline", inv[0])
        self.assertIn(f"DB={db}", inv[0])

    def test_sin_red_version_sin_offline_no_ejecuta(self):
        db = self.base_local()
        env = self.falso(ayuda=AYUDA_VIEJA, AUDITOR_SIN_RED="1", OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=str(db))
        self.correr(ADAPT / "osv.sh", env=env)
        self.assertEqual(self.invocaciones(), [])
        m = self.meta("osv")
        self.assertEqual(m["estado"], "no_evaluado")
        self.assertIn(TEXTO_SIN_RED, m["error"])
        self.assertIn("--offline", m["error"])

    def test_sin_variable_en_linea_como_siempre(self):
        env = self.falso()
        self.correr(ADAPT / "osv.sh", env=env)
        inv = self.invocaciones()
        self.assertEqual(len(inv), 1)
        self.assertNotIn("--offline", inv[0])
        m = self.meta("osv")
        self.assertEqual(m["estado"], "ok")
        self.assertEqual(m["base_osv"]["modo"], "en_linea")

    # --- O1
    def test_excluye_auditoria_y_carpeta_de_corrida(self):
        crudo = self.proy / "salida-propia" / "r1" / "crudo"
        env = self.falso()
        subprocess.run(["bash", str(ADAPT / "osv.sh"), str(self.proy), str(crudo)], capture_output=True, text=True,
                       env=env, timeout=120)
        args = self.invocaciones()[0]
        pares = {args[i + 1] for i, a in enumerate(args[:-1]) if a == "--x-exclude"}
        self.assertIn("g:**/.auditoria", pares)
        self.assertIn(str((self.proy / "salida-propia" / "r1").resolve()), pares)
        meta = json.loads((crudo / "osv.meta.json").read_text())
        self.assertIn("g:**/.auditoria", meta["exclusiones"])

    def test_version_sin_exclude_lo_registra(self):
        env = self.falso(ayuda=AYUDA_VIEJA)
        self.correr(ADAPT / "osv.sh", env=env)
        args = self.invocaciones()[0]
        self.assertNotIn("--x-exclude", args)
        self.assertEqual(self.meta("osv")["exclusiones"], [])


@unittest.skipUnless(shutil.which("osv-scanner"), "osv-scanner no instalado")
class TestOsvDosCorridasReal(Base):
    """O1 con osv-scanner real, sin red: base local fabricada (un aviso para lodash@4.17.20) y --offline."""

    def test_dos_corridas_seguidas_crudos_iguales(self):
        # osv-scanner aplica el .gitignore de los repos que contienen la carpeta (tests/.tmp está ignorado en el repo
        # del auditor, aun con un git init propio): esta fixture vive en una carpeta temporal fuera del repo.
        afuera = Path(tempfile.mkdtemp(prefix="auditor osv "))  # con espacio, como «PROYECTOS »
        self.addCleanup(shutil.rmtree, afuera, ignore_errors=True)
        self.proy = afuera / "proyecto"
        self.proy.mkdir()
        db = self.dir / "osvdb"
        (db / "osv-scalibr" / "npm").mkdir(parents=True)
        aviso = {"schema_version": "1.6.0", "id": "TEST-OSV-0001", "modified": "2026-01-01T00:00:00Z",
                 "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "versions": ["4.17.20"]},
                              {"package": {"ecosystem": "npm", "name": "minimist"}, "versions": ["0.0.8"]}]}
        with zipfile.ZipFile(db / "osv-scalibr" / "npm" / "all.zip", "w") as z:
            z.writestr("TEST-OSV-0001.json", json.dumps(aviso))
        self.escribir("package-lock.json", json.dumps({
            "name": "x", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
            "packages": {"": {"name": "x", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}},
                         "node_modules/lodash": {"version": "4.17.20",
                                                         "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                                                         "integrity": "sha512-x"}}}))
        env = entorno_limpio(TMPDIR=str(TMP_BASE), HOME=str(self.dir), AUDITOR_SIN_RED="1",
                             OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=str(db))
        resultados = []
        for n in (1, 2):
            crudo = self.proy / ".auditoria" / f"corrida{n}" / "crudo"
            r = subprocess.run(["bash", str(ADAPT / "osv.sh"), str(self.proy), str(crudo)], capture_output=True,
                               text=True, env=env, timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr)
            # lo que dejaría el check sbom de la corrida: un SBOM con otro paquete vulnerable
            (crudo / "sbom.cdx.json").write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                "components": [{"type": "library", "name": "minimist", "version": "0.0.8",
                                "purl": "pkg:npm/minimist@0.0.8"}]}))
            datos = json.loads((crudo / "osv.json").read_text())
            rutas = sorted(x["source"]["path"] for x in datos["results"])
            paquetes = sorted(p["package"]["name"] for x in datos["results"] for p in x["packages"])
            resultados.append((rutas, paquetes))
        self.assertEqual(resultados[0], resultados[1])
        self.assertEqual(resultados[0][1], ["lodash"])
        self.assertFalse(any(".auditoria" in p for p in resultados[1][0]))


# ----------------------------------------------------------------------------- semgrep / zizmor / despachador

class TestOtrosAdaptadoresSinRed(Base):
    def falsos(self):
        d = self.dir / "bin"
        d.mkdir(exist_ok=True)
        self.registro = self.dir / "args.log"
        semgrep = (f'if [ "$1" = "--version" ]; then echo 1.0.0; exit 0; fi\n'
                   f'printf "%s\\n" "== invocacion" "$@" >> \'{self.registro}\'\n'
                   'o=""; while [ $# -gt 0 ]; do [ "$1" = --output ] && o="$2"; shift; done; '
                   '[ -n "$o" ] && echo \'{"version":"2.1.0","runs":[{"results":[]}]}\' > "$o"; exit 0')
        zizmor = (f'if [ "$1" = "--version" ]; then echo 1.0.0; exit 0; fi\n'
                  f'printf "%s\\n" "== invocacion" "$@" >> \'{self.registro}\'\n'
                  'echo \'{"version":"2.1.0","runs":[{"results":[]}]}\'; exit 0')
        escribir_falso(d, "semgrep", semgrep)
        escribir_falso(d, "zizmor", zizmor)
        return entorno_limpio(TMPDIR=str(TMP_BASE), GIT_CEILING_DIRECTORIES=str(TMP_BASE),
                              AUDITOR_BIN_SEMGREP=str(d / "semgrep"), AUDITOR_BIN_ZIZMOR=str(d / "zizmor"))

    def args(self):
        return [b.splitlines() for b in self.registro.read_text().split("== invocacion\n")[1:]]

    def test_semgrep_sin_red_no_usa_registro(self):
        self.escribir("a.js", "eval(x)\n")
        env = dict(self.falsos(), AUDITOR_SIN_RED="1", AUDITOR_SEMGREP_REGISTRO="p/owasp-top-ten")
        self.correr(ADAPT / "semgrep.sh", env=env)
        todas = [a for inv in self.args() for a in inv]
        self.assertNotIn("p/owasp-top-ten", todas)
        m = self.meta("semgrep")
        self.assertEqual(m["estado"], "parcial", m)
        self.assertIn(TEXTO_SIN_RED, m["error"])

    def test_semgrep_sin_variable_usa_registro(self):
        self.escribir("a.js", "eval(x)\n")
        env = dict(self.falsos(), AUDITOR_SEMGREP_REGISTRO="p/owasp-top-ten")
        self.correr(ADAPT / "semgrep.sh", env=env)
        self.assertIn("p/owasp-top-ten", [a for inv in self.args() for a in inv])
        self.assertEqual(self.meta("semgrep")["estado"], "ok")

    def test_zizmor_sin_red_ignora_en_linea(self):
        self.escribir(".github/workflows/ci.yml", "on: push\njobs: {}\n")
        env = dict(self.falsos(), AUDITOR_SIN_RED="1", AUDITOR_ZIZMOR_EN_LINEA="1", GH_TOKEN="x" * 8)
        self.correr(ADAPT / "zizmor.sh", env=env)
        self.assertIn("--offline", self.args()[0])

    def test_despachador_registra_sin_red(self):
        self.escribir("package.json", '{"dependencies": {"react": "18.3.1"}}')
        corrida = self.crudo.parent
        env = dict(self.falsos(), AUDITOR_SIN_RED="1", AUDITOR_BIN_OSV="/nonexistent/osv-scanner",
                   AUDITOR_BIN_GITLEAKS="/nonexistent/gitleaks")
        r = subprocess.run(["bash", str(DESPACHADOR), str(self.proy), str(corrida), "rapido"], capture_output=True,
                           text=True, env=env, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(TEXTO_SIN_RED, r.stderr)
        self.assertEqual(json.loads((self.crudo / "check_registro_deps.meta.json").read_text())["estado"],
                         "no_evaluado")


class TestBinAuditarSinRed(Base):
    """`auditar … --sin-red` exporta AUDITOR_SIN_RED=1 a las fases: cada llamada del skill lo lleva explícito (en
    Claude Code cada comando Bash es un shell nuevo y un `export` previo no se conserva)."""

    def test_flag_sin_red_llega_al_scan(self):
        self.escribir("package.json", '{"dependencies": {"react": "18.3.1"}}')
        corrida = self.dir / "corrida"
        env = entorno_limpio(TMPDIR=str(TMP_BASE), GIT_CEILING_DIRECTORIES=str(TMP_BASE),
                             AUDITOR_BIN_OSV="/nonexistent/osv", AUDITOR_BIN_GITLEAKS="/nonexistent/g",
                             AUDITOR_BIN_SEMGREP="/nonexistent/s", AUDITOR_BIN_ZIZMOR="/nonexistent/z")
        bin_auditar = RAIZ / "bin" / "auditar"
        r = subprocess.run(["bash", str(bin_auditar), "stack", str(self.proy), "--salida", str(corrida), "--sin-red"],
                           capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run(["bash", str(bin_auditar), "scan", str(self.proy), "--salida", str(corrida), "--sin-red",
                            "--modo", "rapido"], capture_output=True, text=True, env=env, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(TEXTO_SIN_RED, r.stderr)
        datos = json.loads((corrida / "crudo" / "check_registro_deps.json").read_text())
        self.assertEqual(datos["estado"], "no_evaluado")
        self.assertIn(TEXTO_SIN_RED, datos["motivo"])

    def test_ayuda_menciona_sin_red(self):
        r = subprocess.run(["bash", str(RAIZ / "bin" / "auditar"), "--help"], capture_output=True, text=True,
                           timeout=30)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--sin-red", r.stdout)
        self.assertIn("AUDITOR_SIN_RED", r.stdout)


if __name__ == "__main__":
    unittest.main()
