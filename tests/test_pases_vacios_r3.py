"""Ronda 3 de pases vacíos (fail-closed): reproduce los pases vacíos PV-R2-01…08 de la re-auditoría de la ronda 2 y
otros problemas reportados, y comprueba que ya no dan `pass` sin evidencia positiva.

  A  PV-R2-02 COD-CI-BASICO: cortocircuito de shell (`true || npm test`, `exit 0; npm run lint`, `false && …`) y
     heredocs (`cat <<EOF` con `npm test` dentro): el comando de calidad nunca corre.
  B  PV-R2-03 COD-CI-BASICO: fallos enmascarados (`npm test || true`, `|| exit 0`), continue-on-error, filtros
     branches/paths que no coinciden, `if:` con github.event_name imposible y script `test` que no hace nada.
  C  PV-R2-04 SEG-LOCKFILE: `npm ci` dentro de un echo no es instalación reproducible.
  D  PV-R2-05 SEG-LOCKFILE: lockfile que solo tiene la raíz (no fija dependencias) no es válido ni prueba hosts.
  E  PV-R2-01 DAT-PII-REPO: CSV/JSON versionado con datos personales y de salud → hallazgo crítico (sin exponer
     valores); datos binarios no inspeccionables impiden el pase.
  F  PV-R2-06 SEG-SAST-INY: una inyección SQL de semgrep (DAT-SQL-CONCATENADO) contradice el pass.
  G  PV-R2-07 SEG-DEPS-EXISTEN: Pipfile se verifica; go.mod, Cargo.toml, Gemfile, composer.json… no cubiertos
     impiden el pase.
  H  PV-R2-08 INF-INVENTARIO: exige plataforma de despliegue detectada, no solo un lenguaje.
  I  h_env SEG-SECRETO-REPO: secretos privados en .env (contraseñas, JWT service_role) → hallazgo.
  J  alcance_excluyente fail-closed: una clave excluyente no registrada bloquea el pass.
"""
import base64
import json
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
import detectar_stack  # noqa: E402
import estado  # noqa: E402
import registro_deps  # noqa: E402
import workflows  # noqa: E402

FECHA = "2026-11-18"


def cat():
    return {c["id"]: c for c in catalogo.cargar_catalogo()}


def calc(cid, herr, checks=(), alcance_=None, hallazgos=()):
    c = dict(cat()[cid], aplicabilidad="aplica")
    return estado.calcular({cid: c}, list(hallazgos), herr, set(checks), "profundo", FECHA, alcance=alcance_)[0]


def git(proy, *args):
    ident = ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
    return subprocess.run(["git", *ident, "-C", str(proy), *args], capture_output=True, text=True, check=True)


def jwt(rol):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'iss': 'supabase', 'role': rol})}.firmaFicticia123"


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


def wf(on, cuerpo, job_extra=""):
    return f"name: CI\non: {on}\njobs:\n  ci:\n    runs-on: ubuntu-latest\n{job_extra}{cuerpo}"


def pasos(*runs):
    return "    steps:\n" + "".join(f"      - run: {r}\n" for r in runs)


def bloque(*lineas):
    return "    steps:\n      - run: |\n" + "".join(f"          {l}\n" for l in lineas)


# --------------------------------------------------------------------------------------------- A
class TestCiCortocircuito(Tmp):
    """PV-R2-02: el comando de calidad aparece, pero el shell nunca lo ejecuta."""

    def calidad(self, texto):
        self.escribir(".github/workflows/ci.yml", texto)
        return workflows.calidad_ci(self.dir)[0]

    def assert_nunca(self, texto):
        self.assertIs(self.calidad(texto), False, texto)
        self.assertNotIn("check:archivos_clave.ci", self.pases(archivos_clave.analizar(self.dir)))
        res = workflows.analizar(self.dir)
        self.assertIn("check:workflows.ci_sin_calidad", self.reglas(res))
        self.assertNotIn("check:workflows.ok_ci_calidad", self.pases(res))

    def test_true_o_npm_test(self):
        self.assert_nunca(wf("push", pasos("true || npm test")))

    def test_dos_puntos_o_npm_test(self):
        self.assert_nunca(wf("push", pasos(": || npm test")))

    def test_exit_0_antes_del_lint(self):
        self.assert_nunca(wf("push", pasos("exit 0; npm run lint")))

    def test_exit_0_en_una_linea_previa_del_bloque(self):
        self.assert_nunca(wf("push", bloque("npm ci", "exit 0", "npm test")))

    def test_false_y_npm_test(self):
        self.assert_nunca(wf("push", pasos("false && npm test")))

    def test_heredoc_no_ejecuta_su_contenido(self):
        self.assert_nunca(wf("push", bloque("cat <<EOF > script.sh", "npm test", "EOF")))

    def test_heredoc_con_comillas_y_guion(self):
        self.assert_nunca(wf("push", bloque("cat <<'FIN' > s.sh", "npm run lint", "FIN")))
        self.assert_nunca(wf("push", bloque("cat <<-EOF", "pytest", "EOF")))

    def test_comando_despues_del_heredoc_si_cuenta(self):
        self.assertIs(self.calidad(wf("push", bloque("cat <<EOF > x.txt", "hola", "EOF", "npm test"))), True)

    def test_segundo_plano_no_bloquea(self):
        self.assert_nunca(wf("push", pasos("npm test &")))

    def test_negacion_no_cuenta(self):
        self.assert_nunca(wf("push", pasos("'! npm test'")))

    def test_cadenas_reales_siguen_contando(self):
        for run in ("npm ci && npm test", "npm test && echo ok", "npm test || exit 1", "npm test || false",
                    "npm test | tee salida.log", "set -euo pipefail; npm test", "cd app && npm test"):
            with self.subTest(run=run):
                self.assertIs(self.calidad(wf("push", pasos(run))), True, run)

    def test_ejecuta_calidad_publica(self):
        self.assertFalse(workflows.ejecuta_calidad("true || npm test"))
        self.assertFalse(workflows.ejecuta_calidad("exit 0; npm run lint"))
        self.assertTrue(workflows.ejecuta_calidad("npm ci && npm test"))


# --------------------------------------------------------------------------------------------- B
class TestCiEnmascarado(Tmp):
    """PV-R2-03: el comando corre, pero su fallo nunca hace fallar el CI (o el workflow no se dispara)."""

    def calidad(self, texto):
        self.escribir(".github/workflows/ci.yml", texto)
        return workflows.calidad_ci(self.dir)[0]

    def assert_falla_nunca(self, texto):
        self.assertIs(self.calidad(texto), False, texto)
        self.assertIn("check:workflows.ci_sin_calidad", self.reglas(workflows.analizar(self.dir)))
        self.assertNotIn("check:archivos_clave.ci", self.pases(archivos_clave.analizar(self.dir)))

    def assert_sin_pase(self, texto):
        self.assertIsNot(self.calidad(texto), True, texto)
        self.assertNotIn("check:archivos_clave.ci", self.pases(archivos_clave.analizar(self.dir)))
        self.assertNotIn("check:workflows.ok_ci_calidad", self.pases(workflows.analizar(self.dir)))

    def test_o_true_y_o_exit_0(self):
        for run in ("npm test || true", "npm test || exit 0", "npm test || echo fallo", "npm test || :",
                    "pytest || true"):
            with self.subTest(run=run):
                self.assert_falla_nunca(wf("push", pasos(run)))

    def test_y_echo_seguido_de_otra_linea(self):
        # bash -e no termina por un fallo dentro de `a && b` si no es el último comando; la línea siguiente corre
        self.assert_falla_nunca(wf("push", bloque("npm test && echo ok", "echo fin")))

    def test_set_mas_e(self):
        self.assert_falla_nunca(wf("push", bloque("set +e", "npm test", "echo fin")))
        self.assertIs(self.calidad(wf("push", bloque("set +e", "npm test"))), True)

    def test_continue_on_error_del_job(self):
        self.assert_falla_nunca(wf("push", pasos("npm test"), job_extra="    continue-on-error: true\n"))

    def test_continue_on_error_del_paso(self):
        self.assert_falla_nunca(wf("push", "    steps:\n      - name: t\n        continue-on-error: true\n"
                                           "        run: npm test\n"))

    def test_continue_on_error_con_expresion_es_dudoso(self):
        self.assert_sin_pase(wf("push", pasos("npm test"),
                                job_extra="    continue-on-error: ${{ matrix.experimental }}\n"))

    def test_rama_que_no_existe(self):
        self.assert_sin_pase(wf("\n  push:\n    branches: [rama-que-no-existe-jamas]\n", pasos("npm test")))

    def test_paths_que_no_existen(self):
        self.escribir("src/a.js", "x\n")
        self.assert_sin_pase(wf("\n  push:\n    paths: ['no/existe/**']\n", pasos("npm test")))

    def test_filtros_que_si_coinciden(self):
        self.escribir("src/a.js", "x\n")
        for on in ("\n  push:\n    branches: [main]\n", "\n  pull_request:\n    branches: ['**']\n",
                   "\n  push:\n    paths:\n      - 'src/**'\n", "{push: {branches: [master]}}"):
            with self.subTest(on=on):
                self.assertIs(self.calidad(wf(on, pasos("npm test"))), True)

    def test_rama_existente_en_el_repo(self):
        git(self.dir, "init", "-q", "-b", "desarrollo")
        self.escribir("a.txt", "x\n")
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", "i")
        self.assertIs(self.calidad(wf("\n  push:\n    branches: [desarrollo]\n", pasos("npm test"))), True)

    def test_if_event_name_imposible(self):
        self.assert_falla_nunca(wf("push", pasos("npm test"),
                                   job_extra="    if: ${{ github.event_name == 'nunca' }}\n"))
        self.assert_falla_nunca(wf("[push]", "    steps:\n      - if: github.event_name == 'pull_request'\n"
                                             "        run: npm test\n"))

    def test_if_failure_no_cuenta(self):
        self.assert_falla_nunca(wf("push", "    steps:\n      - if: failure()\n        run: npm test\n"))

    def test_if_posibles(self):
        for cond in ("github.event_name == 'push'", "${{ always() }}", "success()", "!cancelled()",
                     "github.event_name != 'schedule'", "true"):
            with self.subTest(cond=cond):
                self.assertIs(self.calidad(wf("push", pasos("npm test"), job_extra=f"    if: {cond}\n")), True)

    def test_if_desconocido_es_dudoso(self):
        self.assert_sin_pase(wf("push", pasos("npm test"), job_extra="    if: matrix.os == 'ubuntu-latest'\n"))

    def test_m_ci2_script_test_que_no_hace_nada(self):
        self.escribir("package.json", json.dumps({"scripts": {"test": "echo no tests && exit 0"}}))
        self.assert_falla_nunca(wf("push", pasos("npm test")))

    def test_script_inexistente_no_cuenta(self):
        self.escribir("package.json", json.dumps({"scripts": {"build": "vite build"}}))
        self.assert_falla_nunca(wf("push", pasos("npm test")))
        self.assert_falla_nunca(wf("push", pasos("npm run lint --if-present")))

    def test_script_real_cuenta(self):
        self.escribir("package.json", json.dumps({"scripts": {"test": "vitest run", "lint": "eslint .",
                                                              "ci": "npm run lint && vitest run"}}))
        for run in ("npm test", "npm run lint", "pnpm lint", "yarn test", "npm run ci"):
            with self.subTest(run=run):
                self.assertIs(self.calidad(wf("push", pasos(run))), True, run)

    def test_script_en_subcarpeta(self):
        self.escribir("web/package.json", json.dumps({"scripts": {"test": "jest"}}))
        self.assertIs(self.calidad(wf("push", "    defaults:\n      run:\n        working-directory: web\n"
                                              + pasos("npm test"))), True)

    def test_m_ci2_combinado(self):
        self.escribir("package.json", json.dumps({"scripts": {"test": "echo no tests && exit 0"}}))
        self.assert_sin_pase("on:\n  push:\n    branches: [rama-que-no-existe-jamas]\njobs:\n  t:\n"
                             "    runs-on: x\n    continue-on-error: true\n    steps:\n      - run: npm test || true\n")


# --------------------------------------------------------------------------------------------- C, D
LOCK_OK = json.dumps({"name": "x", "lockfileVersion": 3, "requires": True, "packages": {
    "": {"name": "x", "dependencies": {"express": "4.21.2"}},
    "node_modules/express": {"version": "4.21.2",
                             "resolved": "https://registry.npmjs.org/express/-/express-4.21.2.tgz",
                             "integrity": "sha512-x"}}}, indent=2)


class TestLockfileR3(Tmp):
    def proyecto(self, lock=LOCK_OK, ci=None, deps=None, nombre="package-lock.json"):
        deps = {"express": "4.21.2"} if deps is None else deps
        self.escribir("package.json", json.dumps({"name": "x", "dependencies": deps}))
        self.escribir(nombre, lock)
        if ci:
            self.escribir(".github/workflows/ci.yml", ci)
        git(self.dir, "init", "-q")
        git(self.dir, "add", "-A")
        return archivos_clave.analizar(self.dir)

    def test_q_lockecho_npm_ci_dentro_de_echo(self):
        ci = ("on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: npm install\n"
              "      - run: echo \"acuérdate de usar npm ci algún día\"\n      - run: npm test\n")
        self.assertNotIn("check:archivos_clave.lockfile_ci", self.pases(self.proyecto(ci=ci)))

    def test_npm_ci_enmascarado_o_inalcanzable(self):
        for run in ("npm ci || npm install", "true || npm ci", "exit 0; npm ci", "printf 'npm ci'"):
            with self.subTest(run=run):
                ci = f"on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: {run}\n"
                self.assertNotIn("check:archivos_clave.lockfile_ci", self.pases(self.proyecto(ci=ci)))

    def test_npm_ci_real_da_pase(self):
        ci = "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: npm ci && npm test\n"
        self.assertIn("check:archivos_clave.lockfile_ci", self.pases(self.proyecto(ci=ci)))

    def test_l_lock_solo_raiz_no_es_valido(self):
        lock = json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "x", "version": "1.0.0"}}})
        r = self.proyecto(lock=lock, ci="on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: npm ci\n")
        p = self.pases(r)
        self.assertNotIn("check:archivos_clave.lockfile_valido", p)
        self.assertNotIn("check:archivos_clave.lockfile_hosts", p)
        self.assertIn("check:archivos_clave.lockfile_incompleto", self.reglas(r))
        self.assertEqual(catalogo.control_por_regla("check", "archivos_clave.lockfile_incompleto"), "SEG-LOCKFILE")

    def test_dependencia_directa_ausente_del_lockfile(self):
        # Desincronización parcial: sin pase lockfile_valido (no se demuestra la reproducibilidad) y sin hallazgo
        # (decisión pendiente: la verdad de terreno de la app sembrada declara limpio un lockfile así, L56).
        r = self.proyecto(deps={"express": "4.21.2", "lodash": "4.17.21"})
        self.assertNotIn("check:archivos_clave.lockfile_valido", self.pases(r))
        self.assertNotIn("check:archivos_clave.lockfile_incompleto", self.reglas(r))
        self.assertEqual(r["lockfile_desincronizado"], ["package-lock.json: lodash"])

    def test_lockfile_v1_sin_dependencias(self):
        r = self.proyecto(lock=json.dumps({"lockfileVersion": 1, "dependencies": {}}))
        self.assertNotIn("check:archivos_clave.lockfile_valido", self.pases(r))

    def test_pnpm_lock_solo_version(self):
        r = self.proyecto(lock="lockfileVersion: '9.0'\n", nombre="pnpm-lock.yaml")
        self.assertNotIn("check:archivos_clave.lockfile_valido", self.pases(r))
        self.assertNotIn("check:archivos_clave.lockfile_hosts", self.pases(r))

    def test_pnpm_lock_completo_es_valido(self):
        lock = ("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      express:\n"
                "        specifier: 4.21.2\n        version: 4.21.2\npackages:\n  express@4.21.2:\n"
                "    resolution: {integrity: sha512-x}\n")
        r = self.proyecto(lock=lock, nombre="pnpm-lock.yaml")
        self.assertIn("check:archivos_clave.lockfile_valido", self.pases(r))
        self.assertIn("check:archivos_clave.lockfile_hosts", self.pases(r))

    def test_sin_dependencias_no_hay_pase_de_hosts(self):
        lock = json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "x"}}})
        r = self.proyecto(lock=lock, deps={})
        self.assertNotIn("check:archivos_clave.lockfile_hosts", self.pases(r))
        self.assertNotIn("check:archivos_clave.lockfile_incompleto", self.reglas(r))

    def test_lockfile_completo_mantiene_los_pases(self):
        p = self.pases(self.proyecto())
        for sub in ("lockfile_valido", "lockfile_versionado", "lockfile_hosts"):
            self.assertIn(f"check:archivos_clave.{sub}", p)


# --------------------------------------------------------------------------------------------- E
CSV_PII = ("nombre,RUT,email,diagnóstico\n"
           "Juana Ficticia Pérez,12.345.678-5,juana.ficticia@ejemplo.cl,diabetes\n"
           "Pedro Inventado Soto,9.876.543-3,pedro.inventado@ejemplo.cl,VIH\n")


class TestPiiTabular(Tmp):
    def repo(self, archivos):
        git(self.dir, "init", "-q")
        for rel, contenido in archivos.items():
            self.escribir(rel, contenido)
        git(self.dir, "add", "-A")
        return datos_confidenciales.analizar(self.dir)

    def test_p_pii_csv_con_datos_de_salud(self):
        r = self.repo({"export/clientes_2024.csv": CSV_PII, "index.js": "console.log(1)\n"})
        hs = [h for h in r["hallazgos"] if h["regla"] == "check:datos_confidenciales.pii_tabular"]
        self.assertEqual(len(hs), 1, r)
        self.assertEqual(hs[0]["archivo"], "export/clientes_2024.csv")
        self.assertEqual(hs[0]["severidad_sugerida"], "critica")
        self.assertEqual(r["checks_pass"], [])
        texto = json.dumps(r, ensure_ascii=False)
        for valor in ("Juana", "12.345.678-5", "juana.ficticia@ejemplo.cl", "VIH", "diabetes"):
            self.assertNotIn(valor, texto)  # nunca se exponen valores, solo nombres de columna y conteos
        self.assertIn("rut", hs[0]["evidencia"].lower())
        self.assertEqual(catalogo.control_por_regla("check", "datos_confidenciales.pii_tabular"), "DAT-PII-REPO")

    def test_contenido_sin_encabezado_reconocible(self):
        r = self.repo({"datos/contactos.tsv": "id\tcontacto\n1\tana.ficticia@ejemplo.cl\n2\tluis@ejemplo.cl\n"})
        self.assertIn("check:datos_confidenciales.pii_tabular", self.reglas(r))
        self.assertEqual(r["checks_pass"], [])

    def test_json_con_registros_personales(self):
        datos = [{"nombre": "Ana Ficticia", "rut": "12.345.678-5", "diagnostico": "asma"}]
        r = self.repo({"seed/pacientes_demo.json": json.dumps(datos)})
        self.assertIn("check:datos_confidenciales.pii_tabular", self.reglas(r))

    def test_csv_sin_datos_personales_da_pase(self):
        r = self.repo({"data/productos.csv": "sku,nombre_producto,precio\nA1,Lápiz,100\n",
                       "package.json": json.dumps({"name": "x"})})
        self.assertEqual(self.reglas(r), set())
        self.assertEqual(self.pases(r), {"check:datos_confidenciales.no_trackeado"})
        self.assertIn("1 archivo(s) de datos", r["checks_pass"][0]["mensaje"])

    def test_datos_binarios_no_inspeccionables_impiden_el_pase(self):
        r = self.repo({"export/clientes.xlsx": b"PK\x03\x04binario", "index.js": "x\n"})
        self.assertEqual(r["checks_pass"], [])
        self.assertEqual(r["estado"], "ok")
        self.assertIn("no inspeccionable", r["motivo"])

    def test_sin_archivos_de_datos_mantiene_el_pase(self):
        r = self.repo({"index.js": "console.log(1)\n", "README.md": "# x\n"})
        self.assertEqual(self.pases(r), {"check:datos_confidenciales.no_trackeado"})


# --------------------------------------------------------------------------------------------- F
class TestSastContradicho(unittest.TestCase):
    ALC = {"semgrep": {"fuentes": 1, "fuentes_sin_reglas": 0, "consultas_sql": 1, "consultas_sql_sin_reglas": 0,
                       "fuentes_no_escaneadas": 0}}

    def calcular(self, hallazgos):
        c = cat()
        idx = {k: dict(c[k], aplicabilidad="aplica") for k in ("SEG-SAST-INY", "DAT-SQL-CONCATENADO")}
        res = estado.calcular(idx, hallazgos, {"semgrep": "ok"}, set(), "profundo", FECHA, alcance=self.ALC)
        return {r["control"]: r for r in res}

    def test_f_espacios_sqli_contradice_el_pass_de_sast(self):
        h = {"id": "H-1", "control": "DAT-SQL-CONCATENADO", "severidad": "critica", "gate": "N1",
             "herramienta": "semgrep"}
        r = self.calcular([h])
        self.assertEqual(r["DAT-SQL-CONCATENADO"]["estado"], "fail")
        self.assertEqual(r["SEG-SAST-INY"]["estado"], "no_evaluado", r["SEG-SAST-INY"])
        self.assertIn("DAT-SQL-CONCATENADO", r["SEG-SAST-INY"]["motivo"])

    def test_sin_sqli_sigue_pasando(self):
        r = self.calcular([])
        self.assertEqual(r["SEG-SAST-INY"]["estado"], "pass")

    def test_catalogo_declara_la_contradiccion(self):
        controles = [x["control"] for x in cat()["SEG-SAST-INY"].get("pass_contradicho_por", [])]
        self.assertIn("DAT-SQL-CONCATENADO", controles)


# --------------------------------------------------------------------------------------------- G
class TestManifiestosNoCubiertos(Tmp):
    REALES = {"ms", "requests", "pytest", "express"}

    def consulta(self, eco, nombre, timeout):
        return {"existe": nombre in self.REALES, "creado": "2015-01-01T00:00:00Z", "versiones": 50}

    def analizar(self):
        return registro_deps.analizar(self.dir, consulta=self.consulta, hoy=FECHA)

    def test_t_pipfile_se_verifica(self):
        self.escribir("package.json", json.dumps({"dependencies": {"ms": "2.1.3"}}))
        self.escribir("Pipfile", "[packages]\nrequests-oauth-magicz-7781 = \"*\"\n\n[dev-packages]\npytest = \"*\"\n")
        r = self.analizar()
        h = [x for x in r["hallazgos"] if x["regla"] == "check:registro_deps.inexistente"]
        self.assertEqual([(x["archivo"], x["linea"]) for x in h], [("Pipfile", 2)])

    def test_go_mod_no_cubierto_impide_el_pase(self):
        self.escribir("package.json", json.dumps({"dependencies": {"ms": "2.1.3"}}))
        self.escribir("go.mod", "module x\n\ngo 1.22\n\nrequire github.com/nonexistent-zz9/fakepkg v1.0.0\n")
        r = self.analizar()
        self.assertEqual(r["hallazgos"], [])
        self.assertEqual(r["checks_pass"], [])
        self.assertIn("go.mod", r["motivo"])

    def test_otros_manifiestos_no_cubiertos(self):
        casos = {"Cargo.toml": "[package]\nname = \"x\"\n[dependencies]\nserde = \"1\"\n",
                 "Gemfile": "source 'https://rubygems.org'\ngem 'rails'\n",
                 "composer.json": json.dumps({"require": {"php": ">=8", "monolog/monolog": "^3"}})}
        for nombre, texto in casos.items():
            with self.subTest(manifiesto=nombre):
                self.escribir("package.json", json.dumps({"dependencies": {"ms": "2.1.3"}}))
                self.escribir(nombre, texto)
                r = self.analizar()
                self.assertEqual(r["checks_pass"], [], nombre)
                self.assertIn(nombre, r["motivo"])
                (self.dir / nombre).unlink()

    def test_manifiesto_sin_dependencias_no_bloquea(self):
        self.escribir("package.json", json.dumps({"dependencies": {"ms": "2.1.3"}}))
        self.escribir("go.mod", "module x\n\ngo 1.22\n")
        r = self.analizar()
        self.assertIn("check:registro_deps.inexistente", self.pases(r))

    def test_estado_t_pipfile(self):
        self.escribir("package.json", json.dumps({"dependencies": {"ms": "2.1.3"}}))
        self.escribir("go.mod", "module x\nrequire github.com/nonexistent-zz9/fakepkg v1.0.0\n")
        r = self.analizar()
        self.assertEqual(calc("SEG-DEPS-EXISTEN", {"registro_deps": "ok"},
                              checks={p["regla"] for p in r["checks_pass"]})["estado"], "no_evaluado")


# --------------------------------------------------------------------------------------------- H
class TestInventarioPlataforma(Tmp):
    def test_d_sh_solo_lenguaje_no_es_inventario(self):
        self.assertFalse(estado.inventario_no_vacio({"lenguajes": ["shell"], "frameworks": []}))
        self.assertFalse(estado.inventario_no_vacio({"lenguajes": ["python"], "frameworks": [],
                                                     "plataformas_despliegue": []}))

    def test_con_plataforma_si_es_inventario(self):
        self.assertTrue(estado.inventario_no_vacio({"lenguajes": ["javascript"], "frameworks": ["react"],
                                                    "plataformas_despliegue": ["vercel"]}))
        self.assertFalse(estado.inventario_no_vacio({"lenguajes": [], "frameworks": [],
                                                     "plataformas_despliegue": ["vercel"]}))

    def test_detectar_plataformas(self):
        self.escribir("run.sh", "echo hola\n")
        self.assertEqual(detectar_stack.detectar(self.dir)["plataformas_despliegue"], [])
        casos = {"vercel.json": "vercel", "netlify.toml": "netlify", "fly.toml": "fly", "render.yaml": "render",
                 "railway.json": "railway", "Procfile": "heroku", "Dockerfile": "contenedor",
                 "wrangler.toml": "cloudflare"}
        for archivo, plataforma in casos.items():
            with self.subTest(archivo=archivo):
                p = self.escribir(archivo, "x\n")
                self.assertIn(plataforma, detectar_stack.detectar(self.dir)["plataformas_despliegue"])
                p.unlink()

    def test_plataforma_por_paso_de_despliegue(self):
        self.escribir("index.js", "console.log(1)\n")
        self.escribir(".github/workflows/deploy.yml", "on: push\njobs:\n  d:\n    runs-on: x\n    steps:\n"
                                                      "      - uses: amondnet/vercel-action@v25\n")
        self.assertIn("vercel", detectar_stack.detectar(self.dir)["plataformas_despliegue"])
        (self.dir / ".github" / "workflows" / "deploy.yml").unlink()
        self.escribir("package.json", json.dumps({"scripts": {"deploy": "npm run build && firebase deploy"}}))
        self.assertIn("firebase", detectar_stack.detectar(self.dir)["plataformas_despliegue"])
        self.escribir("package.json", json.dumps({"scripts": {"deploy": "echo 'vercel deploy pendiente'"}}))
        self.assertEqual(detectar_stack.detectar(self.dir)["plataformas_despliegue"], [])

    def test_perfil_tecnico_valida_contra_schema(self):
        import validar_schema as vs
        self.escribir("vercel.json", "{}\n")
        esquema = vs.subschema(json.loads((RAIZ / "schemas" / "perfil.schema.json").read_text()), "perfil_tecnico")
        self.assertEqual(vs.validar(detectar_stack.detectar(self.dir), esquema), [])


# --------------------------------------------------------------------------------------------- I
class TestSecretoEnEnv(Tmp):
    def test_h_env_password_y_service_role(self):
        self.escribir(".env", "DB_PASSWORD=hunter2hunter2\n"
                              f"VITE_SUPABASE_SERVICE_ROLE_KEY={jwt('service_role')}\n"
                              "PORT=3000\nAPI_URL=https://api.ejemplo.cl\nVITE_SUPABASE_ANON_KEY=" + jwt("anon") +
                              "\nSMTP_PASSWORD=changeme\nJWT_SECRET=${JWT_SECRET}\nDB_PASSWORD_2=\n")
        r = archivos_clave.analizar(self.dir)
        hs = {h["linea"]: h for h in r["hallazgos"] if h["regla"] == "check:archivos_clave.secreto_en_env"}
        self.assertEqual(sorted(hs), [1, 2], r["hallazgos"])
        self.assertEqual(hs[2]["severidad_sugerida"], "critica")
        texto = json.dumps(r)
        self.assertNotIn("hunter2hunter2", texto)
        self.assertNotIn(jwt("service_role").split(".")[1], texto)
        self.assertEqual(catalogo.control_por_regla("check", "archivos_clave.secreto_en_env"), "SEG-SECRETO-REPO")

    def test_ejemplos_no_cuentan(self):
        self.escribir(".env.example", "DB_PASSWORD=hunter2hunter2\n")
        r = archivos_clave.analizar(self.dir)
        self.assertNotIn("check:archivos_clave.secreto_en_env", self.reglas(r))

    def test_estado_falla(self):
        h = {"id": "H-1", "control": "SEG-SECRETO-REPO", "severidad": "alta", "gate": "N1"}
        r = calc("SEG-SECRETO-REPO", {"gitleaks": "ok"}, alcance_={"gitleaks": {"arbol": 3}}, hallazgos=[h])
        self.assertEqual(r["estado"], "fail")


# --------------------------------------------------------------------------------------------- J
class TestExcluyenteFailClosed(Tmp):
    def test_clave_excluyente_no_registrada_bloquea(self):
        r = calc("SEG-SAST-INY", {"semgrep": "ok"}, alcance_={"semgrep": {"fuentes": 5}})
        self.assertEqual(r["estado"], "no_evaluado", r)
        self.assertIn("sin registrar", r["motivo"])
        r = calc("DAT-SQL-CONCATENADO", {"semgrep": "ok"}, alcance_={"semgrep": {"fuentes": 5, "consultas_sql": 2}})
        self.assertEqual(r["estado"], "no_evaluado", r)

    def test_adaptador_siempre_registra_las_claves(self):
        self.escribir("a.js", "console.log(1)\n")
        a = alcance.desde_semgrep({"results": [], "paths": {"scanned": ["a.js"]}}, self.dir)
        self.assertEqual(a["fuentes_sin_reglas"], 0)
        self.assertEqual(a["consultas_sql_sin_reglas"], 0)


if __name__ == "__main__":
    unittest.main()
