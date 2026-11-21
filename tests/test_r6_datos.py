"""Ronda 6 — grupo «datos» (verificación ciega: el nivel global salía N0 en proyectos limpios por falsos positivos de
DAT-PII-REPO). Casos reales: node-next-limpio/vulnerable (pages/api/patients/search.js), harness (policy.yaml) y
artescritura-app (pruebas pgTAP con correos @example.test).

  A  Carpetas AMBIGUAS (pacientes, patients): el código se analiza y no es DAT-PII-REPO; los datos siguen siendo
     confidenciales; las carpetas inequívocas (datos-reales…) no cambian. Retrocompatibilidad del TOML.
  B  trackeado_historial: solo archivos (no carpetas) que estuvieron en el historial y NO están en el árbol actual.
  C  pii_tabular: un YAML/JSON es tabular solo si es una lista de registros (≥ 2 mapeos con claves comunes).
  D  Correos de dominios reservados (RFC 2606/6761) y buzones de sistema no son datos personales.
  E  Archivos de test/fixture con datos que parecen personales → pii_en_test (media, sin pase).
  F  Fail-closed: xlsx/sav/sqlite/DICOM versionados siguen impidiendo el pase (o son críticos en carpetas de datos).
Cada corrección tiene casos positivos y negativos.
"""
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "scripts" / "adaptadores"))
sys.path.insert(0, str(RAIZ / "tests"))

import alcance  # noqa: E402
import catalogo  # noqa: E402
import datos_confidenciales as dc  # noqa: E402
from tmp_tests import TMP_BASE, tmp_dir  # noqa: E402

GIT_ID = ["-c", "user.name=prueba", "-c", "user.email=prueba@example.invalid", "-c", "commit.gpgsign=false"]
PII = "check:datos_confidenciales.pii_tabular"
EN_TEST = "check:datos_confidenciales.pii_en_test"
TRK = "check:datos_confidenciales.trackeado"
HIST = "check:datos_confidenciales.trackeado_historial"
PASE = "check:datos_confidenciales.no_trackeado"


def git(proy, *args):
    return subprocess.run(["git", *GIT_ID, "-C", str(proy), *args], capture_output=True, text=True, check=True,
                          env=dict(os.environ, GIT_CEILING_DIRECTORIES=str(TMP_BASE)))


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tmp_dir(self)

    def escribir(self, rel, contenido=""):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contenido, bytes):
            p.write_bytes(contenido)
        else:
            p.write_text(contenido, encoding="utf-8")
        return p

    def repo(self, archivos, commit=True):
        git(self.dir, "init", "-q")
        for rel, contenido in archivos.items():
            self.escribir(rel, contenido)
        git(self.dir, "add", "-A")
        if commit:
            git(self.dir, "commit", "-q", "-m", "init")
        return dc.analizar(self.dir)

    @staticmethod
    def reglas(res):
        return [h["regla"] for h in res["hallazgos"]]

    @staticmethod
    def pases(res):
        return {p["regla"] for p in res["checks_pass"]}


# ----------------------------------------------------------------------------------------------------------------- A
class TestCarpetasAmbiguas(unittest.TestCase):
    def test_codigo_en_carpeta_ambigua_no_es_confidencial(self):
        for ruta in ("pages/api/patients/search.js", "src/pacientes/servicio.ts", "PATIENTS/x.py",
                     "app/patients/package.json", "app/patients/tsconfig.base.json", "patients/.env.local",
                     "patients/Dockerfile", "patients/sub", "pages/api/patients", "patients/estilos.css"):
            with self.subTest(ruta=ruta):
                self.assertFalse(dc.es_confidencial(ruta), ruta)

    def test_datos_en_carpeta_ambigua_siguen_siendo_confidenciales(self):
        casos = {"patients/export.csv": "patients", "src/pacientes/ficha.json": "src/pacientes",
                 "pacientes/sub/2024/planilla.XLSX": "pacientes", "patients/notas.md": "patients",
                 "patients/base.sqlite": "patients", "patients/serie.dcm": "patients",
                 "patients/registro.desconocida": "patients", "patients/datos.yaml": "patients"}
        for ruta, raiz in casos.items():
            with self.subTest(ruta=ruta):
                self.assertEqual(dc.raiz_confidencial(ruta), raiz)

    def test_carpetas_inequivocas_no_cambian_y_ganan(self):
        for ruta in ("datos-reales/script.js", "x/datos_abiertos/a.py", "data/raw/b.ts", "datos-reales",
                     "pacientes/datos-reales/a.js", "datos-reales/pacientes/a.js"):
            with self.subTest(ruta=ruta):
                self.assertTrue(dc.es_confidencial(ruta), ruta)
        self.assertEqual(dc.raiz_confidencial("pacientes/datos-reales/a.js"), "pacientes/datos-reales")

    def test_toml_antiguo_sin_ambiguas_es_retrocompatible(self):
        d = tmp_dir(self)
        viejo = d / "viejo.toml"
        viejo.write_text('carpetas = ["datos-reales", "pacientes"]\narchivos = ["*.dcm"]\n', encoding="utf-8")
        with mock.patch.dict(os.environ, {"AUDITOR_CONFIDENCIAL": str(viejo)}):
            conf = dc.cargar()
            self.assertEqual(conf["carpetas_ambiguas"], [])
            self.assertTrue(dc.es_confidencial("src/pacientes/servicio.js", conf))  # como antes: todo confidencial
            self.assertFalse(dc.es_confidencial("src/patients/servicio.js", conf))  # no listada
            self.assertIn("pacientes", dc.exclusiones_semgrep(conf))

    def test_nombre_en_ambas_listas_gana_la_inequivoca(self):
        d = tmp_dir(self)
        t = d / "c.toml"
        t.write_text('carpetas = ["pacientes"]\ncarpetas_ambiguas = ["pacientes", "patients"]\narchivos = []\n',
                     encoding="utf-8")
        conf = dc.cargar(t)
        self.assertEqual(conf["carpetas_ambiguas"], ["patients"])
        self.assertTrue(dc.es_confidencial("pacientes/a.js", conf))
        self.assertFalse(dc.es_confidencial("patients/a.js", conf))
        # sin [ambiguas] se usan las listas por defecto
        self.assertIn(".js", conf["codigo_ambiguas"]["extensiones"])

    def test_ambiguas_configurables(self):
        d = tmp_dir(self)
        t = d / "c.toml"
        t.write_text('carpetas = []\ncarpetas_ambiguas = ["clientes"]\narchivos = []\n'
                     '[ambiguas]\nextensiones_codigo = ["js"]\nnombres_codigo = ["*.config.json"]\n', encoding="utf-8")
        conf = dc.cargar(t)
        self.assertFalse(dc.es_confidencial("clientes/a.js", conf))
        self.assertFalse(dc.es_confidencial("clientes/app.config.json", conf))
        self.assertTrue(dc.es_confidencial("clientes/a.py", conf))  # .py ya no es código para esta configuración

    def test_exclusiones_de_escaneres_solo_datos(self):
        ex = dc.exclusiones_semgrep()
        self.assertNotIn("patients", ex)
        self.assertNotIn("pacientes", ex)
        self.assertIn("**/patients/**/*.csv", ex)
        self.assertIn("**/pacientes/**/*.json", ex)
        self.assertIn("**/PACIENTES/**/*.XLSX", ex)
        self.assertFalse([e for e in ex if e.endswith((".js", ".ts", ".py"))])
        rx = [re.compile(r) for r in dc.regex_gitleaks()]
        for ruta in ("pages/api/patients/registro.csv", "a/pacientes/b/c.json", "PATIENTS/x.SQLITE"):
            self.assertTrue(any(r.search(ruta) for r in rx), ruta)
        for ruta in ("pages/api/patients/search.js", "src/pacientes/servicio.ts", "patients/.env"):
            self.assertFalse(any(r.search(ruta) for r in rx), ruta)

    def test_patrones_listan_las_ambiguas(self):
        r = subprocess.run([sys.executable, "-I", str(RAIZ / "scripts" / "checks" / "datos_confidenciales.py"),
                            "--patrones"], capture_output=True, text=True, check=True)
        self.assertIn("datos-reales", r.stdout.splitlines())
        self.assertIn("patients (solo archivos de datos)", r.stdout.splitlines())


class TestCheckCarpetasAmbiguas(Base):
    def test_codigo_versionado_en_patients_no_es_dat_pii_repo(self):
        # Caso node-next-limpio: repo de 1 commit con pages/api/patients/search.js.
        r = self.repo({"pages/api/patients/search.js": "export default function h(req, res) {}\n",
                       "pages/index.js": "export default 1;\n"})
        self.assertEqual(self.reglas(r), [], r)
        self.assertEqual(self.pases(r), {PASE})
        self.assertEqual(r["inventario"], [])

    def test_datos_versionados_en_patients_siguen_siendo_criticos(self):
        r = self.repo({"pages/api/patients/search.js": "x\n", "pages/api/patients/export.csv": "a\n1\n"})
        hs = [h for h in r["hallazgos"] if h["regla"] == TRK]
        self.assertEqual(len(hs), 1, r)
        self.assertEqual(hs[0]["archivo"], "pages/api/patients")
        self.assertEqual(hs[0]["severidad_sugerida"], "critica")
        self.assertIn("archivos versionados: 1", hs[0]["evidencia"])
        inv = {i["ruta"]: i for i in r["inventario"]}
        self.assertEqual(inv["pages/api/patients"]["archivos"], 1)  # solo el CSV, no el código
        self.assertEqual(r["checks_pass"], [])

    def test_datos_locales_sin_ignorar_en_patients(self):
        git(self.dir, "init", "-q")
        self.escribir("src/patients/a.js", "x\n")
        self.escribir("src/patients/listado.xlsx", b"PK\x03\x04")
        r = dc.analizar(self.dir)
        self.assertIn("check:datos_confidenciales.sin_gitignore", self.reglas(r))
        self.escribir(".gitignore", "*.xlsx\n")
        r = dc.analizar(self.dir)
        self.assertNotIn("check:datos_confidenciales.sin_gitignore", self.reglas(r))

    def test_alcance_escanea_el_codigo_de_patients(self):
        self.escribir("pages/api/patients/search.js", "export default 1;\n")
        self.escribir("pages/api/patients/registro.csv", "a\n")
        self.escribir("datos-reales/script.js", "x\n")
        a = alcance.calcular(self.dir)
        self.assertEqual(a["codigo_confidencial"], 1, a)  # solo datos-reales/script.js
        self.assertEqual(a["fuentes"], 1)  # pages/api/patients/search.js sí entra al alcance
        r = alcance.desde_semgrep({"paths": {"scanned": ["pages/api/patients/search.js"]}}, self.dir,
                                  ["vibe-coding.eval-dinamico"])
        self.assertEqual(r["fuentes_confidenciales"], 1)  # datos-reales/script.js, no el de patients


# ----------------------------------------------------------------------------------------------------------------- B
class TestHistorial(Base):
    def test_repo_de_un_commit_no_afirma_datos_borrados(self):
        r = self.repo({"pages/api/patients/search.js": "x\n", "src/pacientes/ficha.ts": "y\n"})
        self.assertNotIn(HIST, self.reglas(r))

    def test_carpeta_ambigua_con_datos_vigentes_no_es_historial(self):
        r = self.repo({"patients/a.csv": "a\n1\n", "index.js": "z\n"})
        self.assertIn(TRK, self.reglas(r))
        self.assertNotIn(HIST, self.reglas(r))

    def test_datos_borrados_de_carpeta_ambigua_si_son_historial(self):
        self.repo({"patients/a.csv": "a\n1\n", "patients/b.js": "b\n", "index.js": "z\n"})
        git(self.dir, "rm", "-q", "patients/a.csv")
        git(self.dir, "commit", "-q", "-m", "borra")
        r = dc.analizar(self.dir)
        hs = [h for h in r["hallazgos"] if h["regla"] == HIST]
        self.assertEqual(len(hs), 1, r)
        self.assertIn("archivos en el historial: 1", hs[0]["evidencia"])
        self.assertNotIn(TRK, self.reglas(r))

    def test_codigo_borrado_de_carpeta_ambigua_no_es_historial(self):
        self.repo({"patients/viejo.js": "b\n", "index.js": "z\n"})
        git(self.dir, "rm", "-q", "patients/viejo.js")
        git(self.dir, "commit", "-q", "-m", "borra")
        r = dc.analizar(self.dir)
        self.assertNotIn(HIST, self.reglas(r))
        self.assertEqual(self.pases(r), {PASE})

    def test_archivo_borrado_con_el_mismo_contenido_que_uno_vigente(self):
        # git deduplica contenidos: el blob de datos-reales/a.csv es el mismo que el de index.js. La ruta borrada se
        # detecta por git log --name-only, no por la ruta con que rev-list encontró el blob.
        self.repo({"datos-reales/a.csv": "x\n", "index.js": "x\n"})
        git(self.dir, "rm", "-q", "-r", "datos-reales")
        git(self.dir, "commit", "-q", "-m", "borra")
        self.assertIn(HIST, self.reglas(dc.analizar(self.dir)))

    def test_fallo_de_git_log_impide_el_pase(self):
        self.repo({"index.js": "z\n"})
        real = dc._git_lista

        def falso(proyecto, *args, **kw):
            if args[:1] == ("log",):
                return 128, []
            return real(proyecto, *args, **kw)
        with mock.patch.object(dc, "_git_lista", side_effect=falso):
            r = dc.analizar(self.dir)
        self.assertEqual(r["checks_pass"], [])
        self.assertIn("historial", r["motivo"])


# ----------------------------------------------------------------------------------------------------------------- C
POLICY = """version: 1
reglas:
  - id: R1
    tipo: bloqueo
    nombre: Bloquear salida sin fuente
    condicion: "sin_fuente == true"
    accion: bloquear
  - id: R2
    tipo: aviso
    nombre: Avisar latencia alta
    condicion: "latencia > 5"
    accion: avisar
"""
TASK = """id: resumen
owner: equipo
entrada:
  esquema:
    properties:
      diagnostico_principal:
        type: string
      nombre:
        type: string
preprocesadores:
  - nombre: normalizar
    parametros: {}
"""


class TestYamlJsonTabular(Base):
    def test_yaml_de_politica_no_es_tabular(self):
        r = self.repo({"harness/datos/policy.yaml": POLICY, "harness/datos/ejemplos/x/task.yaml": TASK})
        self.assertEqual(self.reglas(r), [], r)
        self.assertEqual(self.pases(r), {PASE})

    def test_yaml_con_registros_personales_es_hallazgo(self):
        y = ("pacientes:\n  - nombre: Juana Pérez\n    telefono: '+56 9 1234 5678'\n"
             "  - nombre: Pedro Rojas\n    telefono: '+56 9 8765 4321'\n")
        r = self.repo({"db/export.yaml": y})
        self.assertIn(PII, self.reglas(r))
        self.assertNotIn("Juana", json.dumps(r, ensure_ascii=False))

    def test_yaml_con_condicion_y_nombres_de_personas_es_hallazgo(self):
        y = ("- nombre: Juana Pérez Soto\n  condicion: VIH\n- nombre: Pedro Rojas\n  condicion: diabetes\n")
        r = self.repo({"datos/listado.yaml": y})
        self.assertIn(PII, self.reglas(r))

    def test_yaml_un_solo_mapeo_con_rut_valido_sigue_siendo_hallazgo(self):
        r = self.repo({"db/export.yaml": "pacientes:\n  - nombre: Juana\n    rut: 12.345.678-5\n"})
        self.assertIn(PII, self.reglas(r))

    def test_yaml_sin_estructura_sigue_sin_pase(self):
        r = self.repo({"data/registros.yaml": "texto libre sin claves\n"})
        self.assertEqual(r["checks_pass"], [])
        self.assertIn("no inspeccionable", r["motivo"])

    def test_registros_yaml_y_claves_comunes(self):
        tablas = dc._registros_yaml(POLICY)
        self.assertEqual(len(tablas), 1)
        self.assertIn("nombre", tablas[0][0])
        self.assertFalse(tablas[0][2])  # los nombres de reglas no parecen de personas
        self.assertEqual(dc._registros_yaml(TASK), [])  # una lista de 1 mapeo no es tabular

    def test_json_de_configuracion_no_es_tabular(self):
        cfg = {"nombre": "app", "email": "dueno@gmail.com", "diagnostico": {"activo": True}}
        r = self.repo({"data/config.json": json.dumps(cfg), "data/uno.json": json.dumps([{"a": 1}, {"b": 2}])})
        # Ronda 7 (#12, adenda 2): no es tabular → sin pii_tabular crítico por sus claves; pero el correo real de sus
        # valores ya no se pierde: pii_no_tabular (media) y sin pase. Sin correo, como en la ronda 6: pase.
        self.assertEqual(self.reglas(r), ["check:datos_confidenciales.pii_no_tabular"], r)
        self.assertEqual(self.pases(r), set())
        self.escribir("data/config.json", json.dumps({"nombre": "app", "diagnostico": {"activo": True}}))
        git(self.dir, "commit", "-qam", "sin correo")
        r = dc.analizar(self.dir)
        self.assertNotIn(PII, self.reglas(r))
        self.assertEqual([h["evidencia"].split(";")[0] for h in r["hallazgos"]], ["ruta: data/config.json (historial)"])

    def test_json_con_registros_personales_es_hallazgo(self):
        regs = [{"nombre": "Juana Pérez", "email": "juana@correo.cl"}, {"nombre": "Pedro Rojas", "email": "p@x.cl"}]
        r = self.repo({"data/usuarios.json": json.dumps(regs)})
        self.assertIn(PII, self.reglas(r))

    def test_json_lista_de_un_registro_con_rut_valido_es_hallazgo(self):
        r = self.repo({"data/uno.json": json.dumps([{"nombre": "Juana", "rut": "12.345.678-5"}])})
        self.assertIn(PII, self.reglas(r))


# ----------------------------------------------------------------------------------------------------------------- D
class TestCorreosReservados(Base):
    def test_dominios_reservados(self):
        for dom in ("example.com", "EXAMPLE.org", "example.net", "mail.example.com", "acme.example", "x.test",
                    "foo.invalid", "app.localhost", "example.test"):
            self.assertTrue(dc.email_reservado(dom), dom)
        for dom in ("gmail.com", "example.com.cl", "examples.com", "test.cl", "myexample.com", "correo.cl"):
            self.assertFalse(dc.email_reservado(dom), dom)
        self.assertTrue(dc.email_no_personal("noreply", "anthropic.com"))
        self.assertTrue(dc.email_no_personal("no-reply+x", "github.com"))
        self.assertFalse(dc.email_no_personal("juana", "anthropic.com"))

    def test_sql_con_correos_de_prueba_no_es_pii(self):
        sql = ("INSERT INTO auth.users (id, email, full_name) VALUES\n"
               "('1', 'autor@example.test', 'Autor Uno'), ('2', 'revisor@example.test', 'Revisor Dos');\n")
        r = self.repo({"supabase/seed.sql": sql, "index.js": "x\n"})
        self.assertEqual(self.reglas(r), [], r)
        self.assertEqual(self.pases(r), {PASE})

    def test_sql_con_correos_reales_sigue_siendo_pii(self):
        sql = ("INSERT INTO auth.users (id, email, full_name) VALUES\n"
               "('1', 'autor@example.test', 'Autor Uno'), ('2', 'juana.perez@gmail.com', 'Juana');\n")
        r = self.repo({"supabase/seed.sql": sql})
        self.assertIn(PII, self.reglas(r))

    def test_csv_columna_email_vacia_sigue_siendo_pii(self):
        r = self.repo({"data/usuarios.csv": "nombre,email\nJuana,\nPedro,\n"})
        self.assertIn(PII, self.reglas(r))  # sin valores que demuestren que es de prueba: fail-closed

    def test_csv_con_email_de_prueba_y_telefono_sigue_siendo_pii(self):
        r = self.repo({"data/usuarios.csv": "email,telefono\na@example.com,+56911112222\n"})
        self.assertIn(PII, self.reglas(r))  # la columna de teléfono no se neutraliza


# ----------------------------------------------------------------------------------------------------------------- E
class TestPiiEnTest(Base):
    CSV = "nombre,email\nJuana Pérez,juana.perez@gmail.com\nPedro Rojas,pedro@gmail.com\n"

    def test_fixture_con_pii_aparente_es_media_y_sin_pase(self):
        r = self.repo({"tests/fixtures/usuarios.csv": self.CSV, "index.js": "x\n"})
        hs = [h for h in r["hallazgos"] if h["regla"] == EN_TEST]
        self.assertEqual(len(hs), 1, r)
        self.assertEqual(hs[0]["severidad_sugerida"], "media")
        self.assertIn("en carpeta de test, verificar que sea ficticio", hs[0]["mensaje"])
        self.assertNotIn(PII, self.reglas(r))
        self.assertEqual(r["checks_pass"], [])  # fail-closed: no hay pase
        self.assertIn("verificar que sea ficticio", r["motivo"])
        self.assertNotIn("juana", json.dumps(r).lower())
        # no mapea a DAT-PII-REPO (crítico, bloquea el global): no puede bloquear
        self.assertNotEqual(catalogo.control_por_regla("check", "datos_confidenciales.pii_en_test"), "DAT-PII-REPO")

    def test_mismo_archivo_fuera_de_test_sigue_siendo_pii_tabular(self):
        r = self.repo({"data/usuarios.csv": self.CSV})
        self.assertIn(PII, self.reglas(r))
        self.assertNotIn(EN_TEST, self.reglas(r))

    def test_pii_real_fuera_de_test_manda_sobre_el_de_test(self):
        r = self.repo({"data/usuarios.csv": self.CSV, "__mocks__/u.csv": self.CSV})
        self.assertIn(PII, self.reglas(r))
        self.assertIn(EN_TEST, self.reglas(r))
        self.assertEqual(r["checks_pass"], [])

    def test_pgtap_con_example_test_queda_limpio(self):
        sql = ("select plan(1);\ninsert into auth.users (id, email) values ('1', 'a@example.test');\n"
               "insert into public.profiles (id, full_name) values ('1', 'Autor');\n")
        r = self.repo({"supabase/tests/rls_test.sql": sql})
        self.assertEqual(self.reglas(r), [], r)
        self.assertEqual(self.pases(r), {PASE})


# ----------------------------------------------------------------------------------------------------------------- F
class TestFailClosed(Base):
    def test_binarios_de_datos_versionados_impiden_el_pase(self):
        for rel in ("data/planilla.xlsx", "estudio/base.sav", "app/local.sqlite"):
            with self.subTest(rel=rel):
                self.dir = tmp_dir(self)
                r = self.repo({rel: b"\x00\x01binario", "index.js": "x\n"})
                self.assertEqual(r["checks_pass"], [], r)
                self.assertIn("no inspeccionable", r["motivo"])

    def test_binarios_en_carpeta_ambigua_son_criticos(self):
        r = self.repo({"src/pacientes/servicio.js": "x\n", "src/pacientes/base.sqlite": b"\x00SQLite"})
        self.assertIn(TRK, self.reglas(r))
        self.assertEqual(r["checks_pass"], [])

    def test_dicom_versionado_sigue_siendo_critico(self):
        r = self.repo({"img/estudio.dcm": b"\x00" * 10, "patients/serie.dcm": b"\x00" * 10, "index.js": "x\n"})
        trk = sorted(h["archivo"] for h in r["hallazgos"] if h["regla"] == TRK)
        self.assertEqual(trk, ["img/estudio.dcm", "patients"])
        self.assertEqual(r["checks_pass"], [])


if __name__ == "__main__":
    unittest.main()
