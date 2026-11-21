"""Tests de regresión de los defectos encontrados por los verificadores independientes (post F0+F1).

Cada clase reproduce un defecto del informe de verificación; ver investigacion/10-f0-f1-resultados.md,
sección "Correcciones post-verificación". Los secretos que aparecen son canarios falsos generados aquí.
"""
import json
import os
import secrets
import shutil
import stat
import string
import subprocess
import sys
import threading
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import catalogo  # noqa: E402
import corrida  # noqa: E402
import estado  # noqa: E402
import gates  # noqa: E402
import utiles  # noqa: E402
from normalizar import run as n_run  # noqa: E402

ADAPT = RAIZ / "scripts" / "adaptadores"
AUDITAR = RAIZ / "bin" / "auditar"
HOOK = RAIZ / "hooks" / "proteger_escritura.py"
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
GIT = ["git", "-c", "user.name=prueba", "-c", "user.email=prueba@example.invalid", "-c", "commit.gpgsign=false"]


def azar(n, alfabeto=string.ascii_letters + string.digits):
    return "".join(secrets.choice(alfabeto) for _ in range(n))


def pat_canario():
    return "ghp_" + azar(36)


def git(cwd, *args):
    return subprocess.run([*GIT, *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def ctrl(id_, **kw):
    base = {"id": id_, "titulo": id_, "alias": [], "dominio": id_.split("-")[0], "etapa": "E2", "gate": "N1",
            "severidad_base": "alta", "metodo": "determinista", "herramientas": ["gitleaks"], "condicion": "siempre",
            "bloquea_global": False, "mapea_reglas": [], "esfuerzo": "S", "aplicabilidad": "aplica",
            # Sin «pases vacíos» (test_evidencia_pass.py): estos controles sintéticos prueban la regla «herramienta ok
            # sin hallazgos → pass», que ahora exige declararla (ausencia_suficiente) con precondición de alcance.
            "evidencia_pass": "ausencia_suficiente"}
    base.update(kw)
    base.setdefault("alcance_requerido", [f"{h}.objetos" for h in base["herramientas"]
                                          if h not in base.get("herramientas_parciales", [])])
    return base


def alcance_de(herr):
    """Alcance ≥ 1 para toda herramienta del estado simulado (la precondición no es lo que se prueba aquí)."""
    return {utiles.canon_herramienta(h): {"objetos": 1} for h in (herr or {})}


def calcular_estado(controles, hallazgos=(), herr=None, pasan=(), modo="estandar"):
    indice = {c["id"]: c for c in controles}
    return {r["control"]: r for r in estado.calcular(indice, list(hallazgos), herr or {}, set(pasan), modo,
                                                     "2026-11-18", alcance=alcance_de(herr))}


class BaseTmp(unittest.TestCase):
    def setUp(self):
        TMP_BASE.mkdir(parents=True, exist_ok=True)
        self.dir = TMP_BASE / f"postver_{self.id().split('.')[-1]}_{azar(6)}"
        self.dir.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.proy = self.dir / "proyecto"
        self.proy.mkdir()
        self.crudo = self.dir / "corrida" / "crudo"
        self.env = dict(os.environ, TMPDIR=str(TMP_BASE), GIT_CEILING_DIRECTORIES=str(TMP_BASE),
                        AUDITOR_SEMGREP_REGISTRO="", AUDITOR_REGISTRO_SIN_RED="1")

    def escribir(self, rel, texto, base=None):
        p = (base or self.proy) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(texto, encoding="utf-8")
        return p

    def adaptador(self, nombre, proyecto=None, env=None):
        return subprocess.run(["bash", str(ADAPT / f"{nombre}.sh"), str(proyecto or self.proy), str(self.crudo)],
                              capture_output=True, text=True, env=env or self.env, timeout=300)

    def meta(self, nombre):
        return json.loads((self.crudo / f"{nombre}.meta.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- 1. herramientas parciales

class TestHerramientaParcialNoDaPass(unittest.TestCase):
    """Defecto: con gitleaks ausente y semgrep ok, SEG-SECRETO-BUNDLE quedaba en pass."""

    def test_parcial_sola_no_basta(self):
        c = ctrl("SEG-B", herramientas=["gitleaks", "semgrep"], herramientas_parciales=["semgrep"])
        r = calcular_estado([c], [], {"gitleaks": "ausente", "semgrep": "ok"})
        self.assertEqual(r["SEG-B"]["estado"], "no_evaluado")
        self.assertIn("gitleaks: herramienta ausente", r["SEG-B"]["motivo"])
        self.assertIn("semgrep", r["SEG-B"]["motivo"])
        self.assertEqual(calcular_estado([c], [], {"gitleaks": "ok", "semgrep": "ausente"})["SEG-B"]["estado"], "pass")

    def test_parcial_con_hallazgo_sigue_en_fail(self):
        c = ctrl("SEG-B", herramientas=["gitleaks", "semgrep"], herramientas_parciales=["semgrep"])
        h = {"id": "H-1", "control": "SEG-B", "severidad": "critica", "gate": "N1", "estado_hallazgo": "abierto"}
        self.assertEqual(calcular_estado([c], [h], {"gitleaks": "ausente", "semgrep": "ok"})["SEG-B"]["estado"], "fail")

    def test_catalogo_real_secreto_bundle(self):
        indice = utiles.indice_controles({"banderas": {}})
        res = {r["control"]: r for r in estado.calcular(indice, [], {"gitleaks": "ausente", "semgrep": "ok"},
                                                        set(), "estandar", "2026-11-18")}
        self.assertEqual(res["SEG-SECRETO-BUNDLE"]["estado"], "no_evaluado")
        res = {r["control"]: r for r in estado.calcular(indice, [], {"gitleaks": "ok", "semgrep": "ausente"},
                                                        set(), "estandar", "2026-11-18")}
        self.assertEqual(res["SEG-JWT"]["estado"], "no_evaluado")  # gitleaks no verifica la firma de un JWT

    def test_catalogo_parciales_son_herramientas_del_control(self):
        for c in catalogo.cargar_catalogo():
            parciales = set(c.get("herramientas_parciales", []))
            self.assertTrue(parciales <= set(c.get("herramientas", [])), c["id"])
            # Ronda 7 (DECISIONES #12, adenda 2): todas parciales solo si el control nunca puede pasar en estático
            # (DAT-RLS-DENY-ALL, DAT-MIGRACION-RECONSTRUCCION: sus únicas herramientas son fallbacks, que deben ser
            # parciales según test_integracion_fallbacks).
            self.assertTrue(set(c.get("herramientas", [])) - parciales or not c.get("herramientas")
                            or c.get("evidencia_pass") == "no_demostrable_estatico", c["id"])


# --------------------------------------------------------------------------- 2. nivel potencial y manual

class TestPotencialManualPendiente(unittest.TestCase):
    """§4.2.3: solo no_evaluado es 'desconocido' en NP; manual_pendiente sigue contando como fallo."""

    def test_manual_pendiente_bloquea_potencial(self):
        ind = {f"SEG-{n}": {"id": f"SEG-{n}", "dominio": "SEG", "gate": n, "severidad_base": "media",
                            "bloquea_global": False} for n in ("N1", "N2", "N3", "N4", "N5")}
        est = [{"control": k, "estado": "manual_pendiente" if k == "SEG-N1" else "pass", "hallazgos": []} for k in ind]
        g = gates.calcular(est, ind, [], {}, set())
        self.assertEqual(g["dominios"]["SEG"]["nivel_potencial"], "N0")
        est = [{"control": k, "estado": "no_evaluado" if k == "SEG-N1" else "pass", "hallazgos": []} for k in ind]
        self.assertEqual(gates.calcular(est, ind, [], {}, set())["dominios"]["SEG"]["nivel_potencial"], "N5")


# --------------------------------------------------------------------------- 3. modo rápido

class TestFueraDeModoConHallazgo(unittest.TestCase):
    def test_fail_fuera_de_modo_lo_declara(self):
        c = ctrl("SEG-N3", gate="N3", herramientas=["zizmor"])
        h = {"id": "H-1", "control": "SEG-N3", "severidad": "alta", "gate": "N3", "estado_hallazgo": "abierto"}
        r = calcular_estado([c], [h], {"zizmor": "ok"}, modo="rapido")["SEG-N3"]
        self.assertEqual(r["estado"], "fail")
        self.assertIn("fuera del alcance del modo rapido", r["motivo"])
        self.assertIsNone(calcular_estado([c], [h], {"zizmor": "ok"}, modo="estandar")["SEG-N3"]["motivo"])


# --------------------------------------------------------------------------- 4-6. carpeta de corrida

class TestCarpetaDeCorrida(BaseTmp):
    def test_misma_hora_no_reutiliza(self):
        import datetime as dt
        ahora = dt.datetime(2026, 11, 18, 1, 0, tzinfo=dt.timezone.utc)
        a = corrida.crear(self.proy, "rapido", ahora=ahora)
        corrida.registrar_fase(a, "scan", "ok", 0, 1.0)
        b = corrida.crear(self.proy, "rapido", ahora=ahora)
        self.assertNotEqual(a, b)
        self.assertIn("scan", json.loads((a / "run.json").read_text())["fases"])
        self.assertEqual(json.loads((b / "run.json").read_text())["fases"], {})
        self.assertEqual(corrida.ultima(self.proy), b)

    def test_registrar_fase_concurrente(self):
        d = corrida.crear(self.proy, "rapido")
        hilos = [threading.Thread(target=corrida.registrar_fase, args=(d, f"f{i}", "ok", 0, 0.1)) for i in range(30)]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join()
        fases = json.loads((d / "run.json").read_text())["fases"]
        self.assertEqual(set(fases), {f"f{i}" for i in range(30)})
        self.assertFalse(list(d.glob("*.tmp")))

    def test_ultima_ignora_corrida_plantada(self):
        plantada = self.proy / ".auditoria" / "9999-12-31_2359-plantado"
        plantada.mkdir(parents=True)
        (plantada / "run.json").write_text(json.dumps({"id": plantada.name, "proyecto": str(self.proy.resolve()),
                                                       "carpeta": str(plantada.resolve()), "modo": "rapido"}))
        mal = self.proy / ".auditoria" / "zzz"
        mal.mkdir()
        (mal / "run.json").write_text("{}")
        creada = corrida.crear(self.proy, "rapido")
        self.assertEqual(corrida.ultima(self.proy), creada)

    def test_ultima_ignora_corrida_de_otro_proyecto(self):
        creada = corrida.crear(self.proy, "rapido")
        ajena = self.proy / ".auditoria" / "2026-11-18_2359-sin-git"
        if ajena.name > creada.name:
            ajena.mkdir()
            (ajena / "run.json").write_text(json.dumps({"id": ajena.name, "proyecto": "/otro", "carpeta": "/otro/x"}))
            self.assertEqual(corrida.ultima(self.proy), creada)

    def test_auditoria_symlink_rechazada(self):
        fuera = self.dir / "fuera"
        fuera.mkdir()
        (self.proy / ".auditoria").symlink_to(fuera)
        with self.assertRaises(OSError):
            corrida.crear(self.proy, "rapido")
        self.assertEqual(list(fuera.iterdir()), [])

    def test_hook_resuelve_symlinks(self):
        fuera = self.dir / "fuera"
        fuera.mkdir()
        (self.proy / ".auditoria").symlink_to(fuera)
        e = {"tool_name": "Write", "cwd": str(self.proy), "tool_input": {"file_path": str(self.proy / ".auditoria" / "x.md")}}
        p = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(e), capture_output=True, text=True,
                           env=dict(os.environ, AUDITAR_ACTIVO="1"), timeout=30)
        self.assertIn('"deny"', p.stdout)


# --------------------------------------------------------------------------- 7. Python con cwd del proyecto

class TestPythonNoImportaDelProyecto(BaseTmp):
    def plantar(self):
        marca = self.dir / "PWNED"
        self.escribir("json.py", f"open({str(marca)!r}, 'w').write('x')\nfrom _json import *\n")
        return marca

    def test_gitleaks_semgrep_zizmor_osv(self):
        marca = self.plantar()
        self.escribir("src/a.js", f"const t = '{pat_canario()}'\n")
        self.escribir("dist/a.js", "x\n")
        self.escribir(".github/workflows/ci.yml", "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                                                  "    steps:\n      - uses: actions/checkout@v4\n")
        falsos = self.dir / "bin"
        falsos.mkdir()
        osv = falsos / "osv-scanner"
        osv.write_text("#!/bin/bash\n[ \"$1\" = --version ] && { echo 2.7.0; exit 0; }\nexit 128\n")
        osv.chmod(osv.stat().st_mode | stat.S_IXUSR)
        env = dict(self.env, AUDITOR_BIN_OSV=str(osv))
        for nombre in ("gitleaks", "semgrep", "zizmor", "osv"):
            if nombre != "osv" and not shutil.which(nombre):
                continue
            r = subprocess.run(["bash", str(ADAPT / f"{nombre}.sh"), str(self.proy), str(self.crudo)],
                               capture_output=True, text=True, env=env, timeout=300, cwd=str(self.proy))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(marca.exists(), f"{nombre} importó json.py del proyecto")

    def test_bin_auditar_desde_el_proyecto(self):
        marca = self.plantar()
        salida = self.dir / "salida"
        r = subprocess.run([str(AUDITAR), "stack", ".", "--salida", str(salida)], capture_output=True, text=True,
                           cwd=str(self.proy), env=self.env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = subprocess.run([str(AUDITAR), "gates", ".", "--salida", str(salida)], capture_output=True, text=True,
                           cwd=str(self.proy), env=self.env, timeout=120)
        self.assertFalse(marca.exists())


# --------------------------------------------------------------------------- 8. configuración git del repo

class TestConfigGitDelRepo(BaseTmp):
    def repo(self):
        git(self.proy, "init", "-q")
        self.escribir("a.txt", "hola\n")
        git(self.proy, "add", "-A")
        git(self.proy, "commit", "-qm", "x")

    def test_fsmonitor_no_se_ejecuta(self):
        self.repo()
        marca = self.dir / "PWNED_fsmonitor"
        git(self.proy, "config", "core.fsmonitor", f"touch '{marca}'; false")
        corrida.crear(self.proy, "rapido")
        r = subprocess.run([sys.executable, str(RAIZ / "scripts" / "checks" / "archivos_clave.py"),
                            str(self.proy), str(self.crudo)], capture_output=True, text=True, env=self.env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(marca.exists())

    @unittest.skipUnless(shutil.which("gitleaks"), "gitleaks no instalado")
    def test_textconv_no_se_ejecuta_en_historial(self):
        self.repo()
        marca = self.dir / "PWNED_textconv"
        self.escribir(".gitattributes", "*.txt diff=pwn\n")
        git(self.proy, "config", "diff.pwn.textconv", f"touch '{marca}'; cat")
        git(self.proy, "config", "diff.external", f"touch '{marca}'; true")
        self.escribir("a.txt", "cambio\n")
        git(self.proy, "add", "-A")
        git(self.proy, "commit", "-qm", "y")
        r = self.adaptador("gitleaks")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(marca.exists())
        self.assertIn("git", {e["modo"] for e in self.meta("gitleaks")["ejecuciones"]})


# --------------------------------------------------------------------------- 9, 11, 13. gitleaks

@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks no instalado")
class TestGitleaks(BaseTmp):
    def test_historial_con_espacios_en_el_prefijo(self):
        raiz = self.dir / "repo"
        sub = raiz / "mi app"
        sub.mkdir(parents=True)
        git(raiz, "init", "-q")
        self.escribir("viejo.js", f"const t = '{pat_canario()}'\n", base=sub)
        self.escribir("otro/fuera.js", f"const t = '{pat_canario()}'\n", base=raiz)
        git(raiz, "add", "-A")
        git(raiz, "commit", "-qm", "x")
        (sub / "viejo.js").unlink()
        git(raiz, "commit", "-qam", "borra")
        r = self.adaptador("gitleaks", proyecto=sub)
        self.assertEqual(r.returncode, 0, r.stderr)
        hist = json.loads((self.crudo / "gitleaks-git.json").read_text())
        self.assertEqual({x["File"] for x in hist}, {"mi app/viejo.js"})  # sin los secretos fuera del proyecto
        self.assertEqual(self.meta("gitleaks")["prefijo_git"], "mi app")

    def test_gitleaksignore_en_raiz_git_y_bundle(self):
        raiz = self.dir / "repo"
        app = raiz / "app"
        app.mkdir(parents=True)
        git(raiz, "init", "-q")
        self.escribir("src/a.js", f"const t = '{pat_canario()}'\n", base=app)
        self.escribir(".gitleaksignore", "abc:src/a.js:github-pat:1\n", base=raiz)
        self.escribir("dist/.gitleaksignore", "x:y:z:1\n", base=app)
        git(raiz, "add", "-A")
        git(raiz, "commit", "-qm", "x")
        r = self.adaptador("gitleaks", proyecto=app)
        self.assertEqual(r.returncode, 0, r.stderr)
        m = self.meta("gitleaks")
        archivos = {x["archivo"] for x in m["gitleaksignore"]}
        self.assertEqual(archivos, {"<raiz_git>/.gitleaksignore", "dist/.gitleaksignore"})
        self.assertEqual(m["estado"], "parcial")

    def test_carpeta_bundle_que_empieza_con_guion(self):
        canario = pat_canario()
        self.escribir("-x/dist/a.js", f'const t="{canario}";\n')
        r = self.adaptador("gitleaks")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.meta("gitleaks")["estado"], "ok", self.meta("gitleaks"))
        bundle = json.loads((self.crudo / "gitleaks-bundle.json").read_text())
        self.assertEqual([x["File"] for x in bundle], ["-x/dist/a.js"])


# --------------------------------------------------------------------------- 10. semgrep

@unittest.skipUnless(shutil.which("semgrep"), "semgrep no instalado")
class TestSemgrepIgnore(BaseTmp):
    def test_semgrepignore_y_gitignore_del_proyecto_no_ocultan(self):
        self.escribir("src/a.js", "function f(req) { eval(req.body.code) }\n")
        self.escribir(".semgrepignore", "src/\n")
        git(self.proy, "init", "-q")
        self.escribir(".gitignore", "src/\n")
        r = self.adaptador("semgrep")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads((self.crudo / "semgrep.sarif").read_text())
        reglas = [x["ruleId"] for run in d["runs"] for x in run["results"]]
        self.assertTrue(any(x.endswith("eval-dinamico") for x in reglas), reglas)
        self.assertEqual(self.meta("semgrep")["ignores_proyecto"], [".gitignore", ".semgrepignore"])


# --------------------------------------------------------------------------- 12. osv-scanner

class TestOsvConfigPropia(BaseTmp):
    def test_config_del_proyecto_neutralizada(self):
        falsos = self.dir / "bin"
        falsos.mkdir()
        args = self.dir / "args.txt"
        f = falsos / "osv-scanner"
        f.write_text(f"""#!/bin/bash
[ "$1" = --version ] && {{ echo 2.7.0; exit 0; }}
printf '%s\\n' "$@" > '{args}'
while [ $# -gt 0 ]; do case "$1" in --output-file) printf '{{"results": []}}' > "$2"; shift 2;; *) shift;; esac; done
exit 0
""")
        f.chmod(f.stat().st_mode | stat.S_IXUSR)
        self.escribir("osv-scanner.toml", "[[IgnoredVulns]]\nid = 'GHSA-xxxx'\n")
        self.escribir("sub/osv-scanner.toml", "[[PackageOverrides]]\nignore = true\n")
        r = self.adaptador("osv", env=dict(self.env, AUDITOR_BIN_OSV=str(f)))
        self.assertEqual(r.returncode, 0, r.stderr)
        lineas = args.read_text().splitlines()
        self.assertIn("--config", lineas)
        conf = Path(lineas[lineas.index("--config") + 1])
        self.assertTrue(conf.is_file())
        self.assertFalse(str(conf).startswith(str(self.proy)))
        self.assertEqual(self.meta("osv")["config_proyecto"], ["osv-scanner.toml", "sub/osv-scanner.toml"])


# --------------------------------------------------------------------------- 14. gates sin normalize

class TestGatesSinNormalize(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)
        self.addCleanup(ap.limpiar, self.tmp)

    def test_sin_normalize_nada_pasa(self):
        c = ap.preparar_corrida(self.tmp)
        d = estado.generar(c)
        r = {x["control"]: x for x in d["controles"]}
        self.assertEqual(r["SEG-SECRETO-REPO"]["estado"], "no_evaluado")
        self.assertIn("normalize", r["SEG-SECRETO-REPO"]["motivo"])
        self.assertFalse([x for x in d["controles"] if x["estado"] == "pass"])

    def test_normalize_con_error_nada_pasa(self):
        c = ap.preparar_corrida(self.tmp)
        n_run.main([str(c)])
        run = json.loads((c / "run.json").read_text())
        run["fases"] = {"normalize": {"estado": "error", "codigo": 1}}
        (c / "run.json").write_text(json.dumps(run))
        d = estado.generar(c)
        self.assertFalse([x for x in d["controles"] if x["estado"] == "pass"])

    def test_crudo_sin_meta_no_cuenta_como_ok(self):
        c = ap.preparar_corrida(self.tmp)
        (c / "crudo" / "gitleaks.meta.json").unlink()
        (c / "crudo" / "gitleaks.json").write_text("[]")
        n_run.main([str(c)])
        r = {x["control"]: x for x in estado.generar(c)["controles"]}
        self.assertEqual(r["SEG-SECRETO-REPO"]["estado"], "no_evaluado")


# --------------------------------------------------------------------------- F1-3 con un commit real

class TestDeterminismoConCommit(BaseTmp):
    def test_dos_corridas_mismo_commit(self):
        proy = self.dir / "app"
        shutil.copytree(ap.APP, proy, ignore=shutil.ignore_patterns(".auditoria"))
        git(proy, "init", "-q")
        git(proy, "add", "-A")
        git(proy, "commit", "-qm", "inicial")
        commit7 = git(proy, "rev-parse", "--short=7", "HEAD")
        env = dict(self.env, AUDITOR_TIMEOUT_S="120")
        corridas = []
        for _ in range(2):
            r = subprocess.run([str(AUDITAR), "all", str(proy), "--modo", "rapido"], capture_output=True, text=True,
                               env=env, timeout=600)
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            corridas.append(Path(r.stdout.strip().splitlines()[-1]))
        a, b = corridas
        self.assertNotEqual(a, b)
        self.assertTrue(a.name.split("-", 3)[-1].startswith(commit7) or commit7 in a.name)
        for nombre in ("gates.json", "hallazgos.jsonl", "hallazgos_todos.jsonl"):
            self.assertEqual((a / nombre).read_bytes(), (b / nombre).read_bytes(), nombre)
        meta = json.loads((a / "crudo" / "gitleaks.meta.json").read_text())
        self.assertIn("git", {e["modo"] for e in meta["ejecuciones"]})
        self.assertTrue((a / "crudo" / "gitleaks-git.json").is_file())
        fps = {json.loads(l)["fingerprint"] for l in (a / "hallazgos_todos.jsonl").read_text().splitlines() if l}
        self.assertTrue(fps)


if __name__ == "__main__":
    unittest.main()
