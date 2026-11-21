"""Tests de los fallbacks estáticos de la Decisión 6 (scripts/checks/: duplicacion, complejidad,
deps_muertas, migraciones_sql, dockerfile, iac, sbom, workflows, rls_estatico, ux_estatico,
presupuesto_build) y de su infraestructura común (scripts/checks/fallback.py).

Cada fallback se prueba con fixtures pequeñas creadas al vuelo (positivo y negativo), además del
contrato común: forma de salida de comun.py + campos `reemplaza` y `cobertura`, omisión cuando la
herramienta real está disponible (herramientas.json de doctor), exclusión de carpetas confidenciales
(Decisión 3) y de node_modules.
"""
import json
import secrets
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CHECKS = RAIZ / "scripts" / "checks"
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
TMP_BASE.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(CHECKS))

import complejidad  # noqa: E402
import deps_muertas  # noqa: E402
import dockerfile  # noqa: E402
import duplicacion  # noqa: E402
import fallback  # noqa: E402
import iac  # noqa: E402
import migraciones_sql  # noqa: E402
import presupuesto_build  # noqa: E402
import rls_estatico  # noqa: E402
import sbom  # noqa: E402
import ux_estatico  # noqa: E402
import workflows  # noqa: E402

MODULOS = {
    "duplicacion": (duplicacion, "jscpd"),
    "complejidad": (complejidad, "lizard"),
    "deps_muertas": (deps_muertas, "knip"),
    "migraciones_sql": (migraciones_sql, "squawk"),
    "dockerfile": (dockerfile, "hadolint"),
    "iac": (iac, "checkov"),
    "sbom": (sbom, "syft"),
    "workflows": (workflows, "actionlint"),
    "rls_estatico": (rls_estatico, "splinter"),
    "ux_estatico": (ux_estatico, "playwright"),
    "presupuesto_build": (presupuesto_build, "lhci"),
}
SEMGREP = shutil.which("semgrep")


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = TMP_BASE / f"fb_{self.id().split('.')[-1]}_{secrets.token_hex(3)}"
        self.dir.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def escribir(self, rel, texto):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(texto, bytes):
            p.write_bytes(texto)
        else:
            p.write_text(texto, encoding="utf-8")
        return p

    def subreglas(self, res):
        return [h["regla"].split(".", 1)[1] for h in res["hallazgos"]]

    def pases(self, res):
        return [p["regla"].split(".", 1)[1] for p in res["checks_pass"]]

    def validar(self, res, nombre):
        self.assertIn(res["estado"], ("ok", "no_evaluado", "error", "no_aplica", "parcial"), res)
        self.assertEqual(res["cobertura"], "parcial (fallback)")
        self.assertTrue(res["reemplaza"])
        for h in res["hallazgos"]:
            self.assertEqual(set(h), {"regla", "archivo", "linea", "mensaje", "evidencia", "severidad_sugerida"}, h)
            self.assertTrue(h["regla"].startswith(f"check:{nombre}."), h["regla"])
            self.assertIn(h["severidad_sugerida"], ("critica", "alta", "media", "baja", "info"))
            self.assertLessEqual(len(h["evidencia"]), 300)
        for p in res["checks_pass"]:
            # Los pases de un fallback llevan prefijo ok_: el catálogo los mapea solo de forma explícita
            # (un fallback es herramienta parcial y no debe dejar un control en pass por comodín).
            self.assertTrue(p["regla"].startswith(f"check:{nombre}.ok_"), p["regla"])


# --------------------------------------------------------------------------------------------------
class TestInfraestructura(Base):
    def test_disponible_lee_herramientas_json(self):
        crudo = self.dir / "corrida" / "crudo"
        crudo.mkdir(parents=True)
        (crudo.parent / "herramientas.json").write_text(json.dumps({"herramientas": {
            "jscpd": {"disponible": True}, "lizard": {"disponible": False}}}), encoding="utf-8")
        self.assertEqual(fallback.herramienta_real_disponible(crudo, ["jscpd"]), "jscpd")
        self.assertIsNone(fallback.herramienta_real_disponible(crudo, ["lizard"]))
        self.assertIsNone(fallback.herramienta_real_disponible(self.dir / "otro" / "crudo", ["jscpd"]))

    def test_exclusiones_por_defecto_y_confidencial(self):
        self.escribir("src/a.js", "x")
        self.escribir("datos-reales/p.js", "x")
        self.escribir("datos-abiertos/q.js", "x")
        self.escribir("node_modules/m/i.js", "x")
        self.escribir("dist/b.js", "x")
        self.escribir("privado/c.js", "x")
        conf = self.escribir("conf/confidencial.toml", 'excluir = ["privado/"]\n')
        rutas = [fallback.rel(self.dir, p) for p in fallback.recorrer(self.dir, {".js"}, confidencial=conf)]
        self.assertEqual(rutas, ["src/a.js"])
        # sin archivo de configuración: defaults (datos-reales, datos-abiertos, node_modules, dist)
        rutas = [fallback.rel(self.dir, p) for p in fallback.recorrer(self.dir, {".js"}, confidencial=self.dir / "no")]
        self.assertEqual(rutas, ["privado/c.js", "src/a.js"])

    def test_usa_datos_confidenciales_formato_oficial(self):
        # Formato de config/confidencial.toml (scripts/checks/datos_confidenciales.py): carpetas a
        # cualquier profundidad (también secuencias "data/raw") y globs de nombre de archivo.
        conf = self.escribir("c.toml", 'carpetas = ["data/raw", "pacientes"]\narchivos = ["*.dcm"]\n')
        self.escribir("src/a.js", "x")
        self.escribir("src/img.dcm", "x")
        self.escribir("app/data/raw/b.js", "x")
        self.escribir("app/Pacientes/c.js", "x")
        rutas = [fallback.rel(self.dir, p) for p in fallback.recorrer(self.dir, confidencial=conf)]
        self.assertEqual(rutas, ["c.toml", "src/a.js"])

    def test_config_real_excluye_datos_reales(self):
        self.escribir("datos-reales/x.js", "x")
        self.escribir("src/estudio.DCM", "x")
        self.escribir("src/a.js", "x")
        rutas = [fallback.rel(self.dir, p) for p in fallback.recorrer(self.dir)]
        self.assertEqual(rutas, ["src/a.js"])

    def test_confidencial_formato_tabla(self):
        conf = self.escribir("c.toml", '[confidencial]\ncarpetas = ["secreto", "x/y/**"]\n')
        excl = fallback.cargar_exclusiones(conf)
        self.assertIn("secreto", excl)
        self.assertIn("x/y", excl)
        self.assertIn("datos-reales", excl)
        self.assertIn("node_modules", excl)

    def test_cli_omite_si_la_herramienta_real_esta(self):
        self.escribir("Dockerfile", "FROM node:latest\n")
        crudo = self.dir / "corrida" / "crudo"
        crudo.mkdir(parents=True)
        (crudo.parent / "herramientas.json").write_text(json.dumps({"herramientas": {
            "hadolint": {"disponible": True}}}), encoding="utf-8")
        r = subprocess.run([sys.executable, "-I", str(CHECKS / "dockerfile.py"), str(self.dir), str(crudo)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        datos = json.loads((crudo / "check_dockerfile.json").read_text(encoding="utf-8"))
        self.assertEqual(datos["estado"], "no_evaluado")
        self.assertIn("hadolint", datos["motivo"])
        self.assertEqual(datos["hallazgos"], [])
        self.assertEqual(datos["reemplaza"], "hadolint")
        meta = json.loads((crudo / "check_dockerfile.meta.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["herramienta"], "check:dockerfile")

    def test_cli_corre_si_falta(self):
        self.escribir("Dockerfile", "FROM node:latest\n")
        crudo = self.dir / "corrida" / "crudo"
        r = subprocess.run([sys.executable, "-I", str(CHECKS / "dockerfile.py"), str(self.dir), str(crudo)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        datos = json.loads((crudo / "check_dockerfile.json").read_text(encoding="utf-8"))
        self.assertEqual(datos["check"], "dockerfile")
        self.assertEqual(datos["version"], "1")
        self.assertEqual(datos["estado"], "ok")
        self.assertEqual(datos["cobertura"], "parcial (fallback)")
        self.assertIn("check:dockerfile.tag_latest", [h["regla"] for h in datos["hallazgos"]])

    def test_todos_declaran_reemplaza_y_herramientas(self):
        for nombre, (mod, real) in MODULOS.items():
            self.assertEqual(mod.NOMBRE, nombre)
            self.assertEqual(mod.REEMPLAZA, real)
            self.assertIn(real, mod.HERRAMIENTAS_REALES)

    def test_proyecto_vacio_no_rompe(self):
        for nombre, (mod, _) in MODULOS.items():
            with self.subTest(nombre):
                res = mod.analizar(self.dir, crudo=self.dir / "crudo")
                self.validar(res, nombre)
                self.assertEqual(res["hallazgos"], [], nombre)


# --------------------------------------------------------------------------------------------------
BLOQUE_JS = """
export function procesar(lista, opciones) {
  const resultado = [];
  for (const item of lista) {
    if (item.activo && opciones.filtrar) {
      resultado.push({ id: item.id, nombre: item.nombre.trim(), total: item.precio * item.cantidad });
    } else if (item.pendiente) {
      resultado.push({ id: item.id, nombre: 'pendiente', total: 0 });
    }
  }
  return resultado.sort((a, b) => a.total - b.total);
}
"""


class TestDuplicacion(Base):
    def test_detecta_bloque_renombrado(self):
        self.escribir("src/a.js", BLOQUE_JS)
        self.escribir("src/b.js", "// copia\n" + BLOQUE_JS.replace("procesar", "calcular").replace("lista", "xs"))
        res = duplicacion.analizar(self.dir)
        self.validar(res, "duplicacion")
        self.assertIn("bloque_duplicado", self.subreglas(res))
        h = [h for h in res["hallazgos"] if h["regla"].endswith("bloque_duplicado")][0]
        self.assertIn("src/", h["mensaje"])
        self.assertIn("porcentaje_global", self.subreglas(res))  # 100 % duplicado > 5 %

    def test_sin_duplicacion_pasa(self):
        self.escribir("src/a.js", BLOQUE_JS)
        self.escribir("src/c.py", "def f(x):\n    return x + 1\n\n\ndef g(y):\n    return [y] * 3\n")
        res = duplicacion.analizar(self.dir)
        self.validar(res, "duplicacion")
        self.assertEqual(res["hallazgos"], [])
        self.assertIn("ok_porcentaje_global", self.pases(res))

    def test_sin_hallazgos_repetidos(self):
        repetido = "\n".join(f"  expect(page.getByText('t{i}')).toBeVisible();" for i in range(12))
        self.escribir("e2e/a.spec.ts", f"test('a', async () => {{\n{repetido}\n}});\n")
        self.escribir("e2e/b.spec.ts", f"test('b', async () => {{\n{repetido}\n}});\n")
        res = duplicacion.analizar(self.dir)
        claves = [(h["archivo"], h["linea"], h["mensaje"]) for h in res["hallazgos"] if h["regla"].endswith("bloque_duplicado")]
        self.assertTrue(claves)
        self.assertEqual(len(claves), len(set(claves)), claves)

    def test_excluye_node_modules_y_min(self):
        self.escribir("src/a.js", BLOQUE_JS)
        self.escribir("node_modules/x/a.js", BLOQUE_JS)
        self.escribir("src/a.min.js", BLOQUE_JS)
        res = duplicacion.analizar(self.dir)
        self.assertEqual(res["hallazgos"], [])


# --------------------------------------------------------------------------------------------------
PY_COMPLEJO = "def f(a, b, c):\n" + "".join(f"    if a == {i} and b:\n        c += {i}\n" for i in range(9)) + "    return c\n"


class TestComplejidad(Base):
    def test_python_ast_exacto(self):
        self.escribir("m.py", "def g(x):\n    if x or x > 2:\n        return [i for i in x if i]\n    return 0\n")
        funcs = complejidad.funciones_python(self.dir / "m.py", (self.dir / "m.py").read_text())
        self.assertEqual(funcs[0]["nombre"], "g")
        self.assertEqual(funcs[0]["ccn"], 5)  # 1 + if + or + for(comprensión) + if(comprensión)

    def test_python_ccn_alta(self):
        self.escribir("m.py", PY_COMPLEJO)
        res = complejidad.analizar(self.dir)
        self.validar(res, "complejidad")
        self.assertEqual(self.subreglas(res), ["ccn_alta"])
        self.assertIn("CCN 19", res["hallazgos"][0]["mensaje"])

    def test_js_ccn_y_funciones_anidadas(self):
        cuerpo = "".join(f"  if (x === {i} || y) {{ z++; }}\n" for i in range(8))
        self.escribir("src/a.ts", f"export function grande(x: number, y = 2) {{\n{cuerpo}  const h = () => {{ if (a) {{ b(); }} }};\n  return z;\n}}\n"
                                   "const chica = (a) => {\n  return a ? 1 : 2; // if (no cuenta)\n};\n")
        funcs = {f["nombre"]: f for f in complejidad.funciones_js((self.dir / "src/a.ts").read_text())}
        self.assertEqual(funcs["grande"]["ccn"], 1 + 16 + 1)  # 8 if + 8 || + 1 parámetro por defecto
        self.assertEqual(funcs["chica"]["ccn"], 2)
        self.assertEqual(funcs["h"]["ccn"], 2)
        res = complejidad.analizar(self.dir)
        self.assertEqual(self.subreglas(res), ["ccn_alta"])
        self.assertEqual(res["hallazgos"][0]["linea"], 1)

    def test_tsx_con_apostrofes_en_jsx(self):
        self.escribir("src/C.tsx", "export function C({ ok }) {\n  return <p>Don't {ok ? 'sí' : 'no'}</p>;\n}\n")
        funcs = complejidad.funciones_js((self.dir / "src/C.tsx").read_text())
        self.assertEqual([f["ccn"] for f in funcs], [2])

    def test_pasa_sin_hallazgos(self):
        self.escribir("m.py", "def f():\n    return 1\n")
        res = complejidad.analizar(self.dir)
        self.assertEqual(res["hallazgos"], [])
        self.assertIn("ok_ccn", self.pases(res))


# --------------------------------------------------------------------------------------------------
class TestDepsMuertas(Base):
    def test_sin_uso_y_no_declarada(self):
        self.escribir("package.json", json.dumps({
            "name": "app", "scripts": {"dev": "vite", "test": "vitest run"},
            "dependencies": {"react": "^18", "lodash": "^4", "@scope/ui": "1"},
            "devDependencies": {"vite": "^5", "vitest": "^1", "left-pad": "1"}}, indent=2))
        self.escribir("src/main.jsx", "import React from 'react';\nimport { x } from '@scope/ui/boton';\n"
                                      "import axios from 'axios';\nimport './a.css';\nimport fs from 'node:fs';\n"
                                      "import path from 'path';\nimport u from '@/util';\n")
        res = deps_muertas.analizar(self.dir)
        self.validar(res, "deps_muertas")
        porsub = {}
        for h in res["hallazgos"]:
            porsub.setdefault(h["regla"].split(".", 1)[1], []).append(h)
        self.assertEqual([h["evidencia"] for h in porsub["dep_sin_uso"]], ["lodash"])
        self.assertEqual([h["evidencia"] for h in porsub["devdep_sin_uso"]], ["left-pad"])
        self.assertEqual([h["evidencia"] for h in porsub["dep_no_declarada"]], ["axios"])
        self.assertEqual(porsub["dep_no_declarada"][0]["archivo"], "src/main.jsx")
        self.assertEqual(porsub["dep_no_declarada"][0]["linea"], 3)
        self.assertIsInstance(porsub["dep_sin_uso"][0]["linea"], int)

    def test_limpio_pasa(self):
        self.escribir("package.json", json.dumps({"name": "a", "dependencies": {"react": "1"},
                                                  "devDependencies": {"typescript": "5", "@types/react": "18"},
                                                  "scripts": {"build": "tsc -b"}}))
        self.escribir("src/a.tsx", "const R = require('react');\nexport default R;\n")
        res = deps_muertas.analizar(self.dir)
        self.assertEqual(res["hallazgos"], [])
        self.assertIn("ok_deps", self.pases(res))

    def test_citada_en_config_o_con_rc_cuenta_como_usada(self):
        self.escribir("package.json", json.dumps({"name": "a", "dependencies": {"@ffmpeg/util": "1"},
                                                  "devDependencies": {"jsdom": "1", "prettier": "3", "vite": "5"},
                                                  "scripts": {"dev": "vite"}}))
        self.escribir("vite.config.ts", "export default { optimizeDeps: { exclude: ['@ffmpeg/util'] }, "
                                        "test: { environment: 'jsdom' } };\n")
        self.escribir(".prettierrc", "{}\n")
        self.assertEqual(deps_muertas.analizar(self.dir)["hallazgos"], [])

    def test_sin_package_json_no_evaluado(self):
        # Un proyecto Python también puede tener código muerto: sin package.json no se evalúa (no es no_aplica).
        self.escribir("a.py", "import os\n")
        self.assertEqual(deps_muertas.analizar(self.dir)["estado"], "no_evaluado")


# --------------------------------------------------------------------------------------------------
class TestMigracionesSql(Base):
    def test_reglas_principales(self):
        self.escribir("supabase/migrations/001_init.sql",
                      "create table pacientes (id serial primary key, nombre varchar(50), creado timestamp);\n"
                      "create index idx_p on pacientes(nombre);\n")
        self.escribir("supabase/migrations/002_cambios.sql", """
-- comentario con DROP TABLE falso
ALTER TABLE pacientes ADD COLUMN rut text NOT NULL;
ALTER TABLE pacientes ADD COLUMN nota text NOT NULL DEFAULT '';
CREATE INDEX idx_rut ON pacientes (rut);
ALTER TABLE pacientes DROP COLUMN nombre;
ALTER TABLE pacientes ALTER COLUMN creado TYPE timestamptz;
ALTER TABLE pacientes RENAME COLUMN rut TO run;
ALTER TABLE citas ADD CONSTRAINT fk_p FOREIGN KEY (pid) REFERENCES pacientes(id);
DROP TABLE viejos;
CREATE FUNCTION f() RETURNS void AS $$ BEGIN DROP TABLE x; END; $$ LANGUAGE plpgsql;
""")
        res = migraciones_sql.analizar(self.dir)
        self.validar(res, "migraciones_sql")
        subs = self.subreglas(res)
        for s in ("not_null_sin_default", "index_sin_concurrently", "drop_column", "cambio_tipo", "rename",
                  "fk_sin_not_valid", "drop_table", "sin_lock_timeout", "tipo_serial_int", "tipo_varchar",
                  "tipo_timestamp"):
            self.assertIn(s, subs)
        self.assertEqual(subs.count("not_null_sin_default"), 1)
        self.assertEqual(subs.count("drop_table"), 1)  # el DROP dentro de $$ y el del comentario no cuentan
        # índice sobre tabla creada en la misma migración: no aplica
        self.assertFalse([h for h in res["hallazgos"] if h["regla"].endswith("index_sin_concurrently")
                          and h["archivo"].endswith("001_init.sql")])
        h = [h for h in res["hallazgos"] if h["regla"].endswith("drop_column")][0]
        self.assertEqual(h["linea"], 6)

    def test_concurrently_en_transaccion(self):
        self.escribir("migrations/1.sql", "BEGIN;\nCREATE INDEX CONCURRENTLY i ON t(c);\nCOMMIT;\n")
        self.assertIn("concurrently_en_transaccion", self.subreglas(migraciones_sql.analizar(self.dir)))

    def test_segura_pasa(self):
        self.escribir("migrations/1.sql", "SET lock_timeout = '2s';\nCREATE INDEX CONCURRENTLY i ON t(c);\n"
                                          "ALTER TABLE t ADD COLUMN x text;\n")
        res = migraciones_sql.analizar(self.dir)
        self.assertEqual(res["hallazgos"], [])
        self.assertIn("ok_migraciones", self.pases(res))

    def test_sin_migraciones_no_aplica(self):
        self.assertEqual(migraciones_sql.analizar(self.dir)["estado"], "no_aplica")


# --------------------------------------------------------------------------------------------------
class TestDockerfile(Base):
    def test_malo(self):
        self.escribir("Dockerfile", "FROM node\nENV API_KEY=abcdef123" "4567890xyz\nRUN apt-get update && \\\n"
                                    "    apt-get install -y curl git\nRUN curl -sL https://x.sh | bash\n"
                                    "ADD src /app\nCOPY . /app\nRUN npm ci\nCMD npm start\n")
        res = dockerfile.analizar(self.dir)
        self.validar(res, "dockerfile")
        subs = self.subreglas(res)
        for s in ("tag_latest", "usuario_root", "secreto_en_env", "apt_sin_pin", "curl_pipe_sh", "add_vs_copy",
                  "copy_todo_sin_dockerignore", "sin_multistage", "cmd_shell_form"):
            self.assertIn(s, subs)
        sec = [h for h in res["hallazgos"] if h["regla"].endswith("secreto_en_env")][0]
        self.assertNotIn("abcdef1234567890xyz", json.dumps(res))
        self.assertEqual(sec["severidad_sugerida"], "alta")
        apt = [h for h in res["hallazgos"] if h["regla"].endswith("apt_sin_pin")][0]
        self.assertEqual(apt["linea"], 3)

    def test_bueno(self):
        self.escribir(".dockerignore", ".env\n")
        self.escribir("Dockerfile", "FROM node:20.11-alpine AS build\nWORKDIR /app\nCOPY . .\nRUN npm ci\n"
                                    "FROM node:20.11-alpine\nCOPY --from=build /app/dist /app\nUSER node\n"
                                    'CMD ["node", "/app/index.js"]\n')
        res = dockerfile.analizar(self.dir)
        self.assertEqual(res["hallazgos"], [])
        self.assertIn("ok_tag_latest", self.pases(res))
        self.assertIn("ok_usuario_root", self.pases(res))

    def test_sin_dockerfile_no_aplica(self):
        self.assertEqual(dockerfile.analizar(self.dir)["estado"], "no_aplica")


# --------------------------------------------------------------------------------------------------
class TestIac(Base):
    def test_contextuales_sin_semgrep(self):
        self.escribir("k8s/dep.yaml", "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
                                      "      containers:\n        - name: a\n          image: nginx\n")
        self.escribir("docker-compose.yml", "services:\n  db:\n    image: postgres:16\n    ports:\n"
                                            "      - \"5432:5432\"\n  ok:\n    ports:\n      - \"127.0.0.1:6379:6379\"\n")
        res = iac.analizar(self.dir, usar_semgrep=False)
        self.validar(res, "iac")
        subs = self.subreglas(res)
        self.assertIn("k8s_sin_nonroot", subs)
        self.assertIn("k8s_sin_limites", subs)
        self.assertIn("k8s_latest", subs)
        self.assertEqual(subs.count("compose_puerto_bd"), 1)
        self.assertEqual(res["estado"], "parcial")

    @unittest.skipUnless(SEMGREP, "semgrep no instalado")
    def test_reglas_semgrep_locales(self):
        self.escribir("main.tf", 'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n'
                                 '  storage_encrypted = false\n  password = "superclave123"\n}\n'
                                 'resource "aws_security_group" "sg" {\n  ingress {\n    from_port = 22\n'
                                 '    to_port = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
        self.escribir("k8s/pod.yaml", "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n"
                                      "    - name: a\n      image: nginx:1.25\n      securityContext:\n"
                                      "        privileged: true\n        runAsNonRoot: true\n"
                                      "      resources:\n        limits:\n          cpu: 1\n")
        res = iac.analizar(self.dir)
        self.validar(res, "iac")
        self.assertEqual(res["estado"], "ok", res["motivo"])
        subs = self.subreglas(res)
        for s in ("tf_bd_publica", "tf_sin_cifrado", "tf_secreto_literal", "tf_ingreso_abierto",
                  "k8s_privilegiado", "k8s_host"):
            self.assertIn(s, subs)
        self.assertNotIn("superclave123", json.dumps(res))

    @unittest.skipUnless(SEMGREP, "semgrep no instalado")
    def test_semgrep_test_de_reglas(self):
        r = subprocess.run(["semgrep", "--test", "--metrics=off", "--disable-version-check",
                            str(RAIZ / "reglas" / "semgrep" / "iac")], capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_sin_iac_no_aplica(self):
        self.escribir(".github/workflows/ci.yml", "on: push\n")
        self.assertEqual(iac.analizar(self.dir, usar_semgrep=False)["estado"], "no_aplica")


# --------------------------------------------------------------------------------------------------
class TestSbom(Base):
    def test_lockfiles_y_licencias(self):
        self.escribir("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/react": {"version": "18.2.0", "license": "MIT"},
            "node_modules/@scope/x": {"version": "1.0.0", "license": "AGPL-3.0-only"},
            "node_modules/raro": {"version": "0.1.0"},
            "node_modules/dev-lib": {"version": "2.0.0", "license": "GPL-3.0", "dev": True}}}))
        self.escribir("requirements.txt", "flask==3.0.0\nrequests>=2\n")
        crudo = self.dir / "crudo"
        res = sbom.analizar(self.dir, crudo=crudo)
        self.validar(res, "sbom")
        subs = self.subreglas(res)
        self.assertIn("sbom_no_versionado", subs)
        self.assertIn("proyecto_sin_licencia", subs)
        cop = [h for h in res["hallazgos"] if h["regla"].endswith("licencia_copyleft")]
        self.assertEqual([h["evidencia"] for h in cop], ["@scope/x@1.0.0 (AGPL-3.0-only)"])
        self.assertIn("raro@0.1.0", [h["evidencia"] for h in res["hallazgos"] if h["regla"].endswith("licencia_desconocida")])
        bom = json.loads((crudo / "sbom.cdx.json").read_text(encoding="utf-8"))
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        purls = {c["purl"] for c in bom["components"]}
        self.assertIn("pkg:npm/%40scope/x@1.0.0", purls)
        self.assertIn("pkg:pypi/flask@3.0.0", purls)
        self.assertIn("ok_inventario", self.pases(res))

    def test_sbom_versionado_y_licencia(self):
        self.escribir("LICENSE", "MIT")
        self.escribir("yarn.lock", '"left-pad@^1.0.0":\n  version "1.3.0"\n')
        self.escribir(".github/workflows/rel.yml", "jobs:\n  s:\n    steps:\n      - run: syft . -o cyclonedx-json\n")
        res = sbom.analizar(self.dir, crudo=self.dir / "crudo")
        self.assertNotIn("sbom_no_versionado", self.subreglas(res))
        self.assertIn("ok_sbom_versionado", self.pases(res))

    def test_sin_lockfiles_no_evaluado(self):
        self.assertEqual(sbom.analizar(self.dir, crudo=self.dir / "crudo")["estado"], "no_evaluado")


# --------------------------------------------------------------------------------------------------
class TestWorkflows(Base):
    def test_problemas(self):
        self.escribir(".github/workflows/a.yml", "name: a\njobs:\n  build:\n    steps:\n      - run: echo ${{ github.sha }\n"
                                                 "  viejo:\n    runs-on: ubuntu-20.04\n    steps:\n\t- run: npm run build\n")
        res = workflows.analizar(self.dir)
        self.validar(res, "workflows")
        subs = self.subreglas(res)
        for s in ("sin_on", "job_sin_runs_on", "expresion_mal_cerrada", "runner_obsoleto", "tabulador", "ci_sin_calidad"):
            self.assertIn(s, subs)

    def test_correcto(self):
        self.escribir(".github/workflows/ci.yml", "on:\n  push:\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
                                                  "    steps:\n      - run: |\n          npm ci\n          npm test\n"
                                                  "  reuso:\n    uses: org/repo/.github/workflows/x.yml@v1\n")
        res = workflows.analizar(self.dir)
        self.assertEqual(res["hallazgos"], [])
        self.assertEqual(sorted(self.pases(res)), ["ok_ci_calidad", "ok_sintaxis"])

    def test_nombre_de_job_no_cuenta_como_test(self):
        self.escribir(".github/workflows/ci.yml", "on: push\njobs:\n  test:\n    name: test\n    runs-on: ubuntu-latest\n"
                                                  "    steps:\n      - run: npm run build\n")
        self.assertIn("ci_sin_calidad", self.subreglas(workflows.analizar(self.dir)))

    def test_sin_workflows_no_aplica(self):
        self.assertEqual(workflows.analizar(self.dir)["estado"], "no_aplica")


# --------------------------------------------------------------------------------------------------
class TestRlsEstatico(Base):
    def test_estado_acumulado(self):
        self.escribir("supabase/migrations/20240101_a.sql", """
create table public.perfiles (id uuid primary key, nombre text);
create table public.notas (id bigint generated always as identity primary key, perfil_id uuid references public.perfiles(id), texto text);
create table public.logs (msg text);
alter table public.perfiles enable row level security;
alter table public.notas enable row level security;
create policy "todo" on public.notas for all using (true);
create policy "meta" on public.perfiles for select using ((auth.jwt() -> 'user_metadata' ->> 'rol') = 'admin');
create function public.f() returns void language plpgsql security definer as $$ begin null; end; $$;
create view public.usuarios as select id, email from auth.users;
grant all on public.logs to anon;
insert into storage.buckets (id, name, public) values ('fotos', 'fotos', true);
""")
        self.escribir("supabase/migrations/20240102_b.sql", "create table public.temp (id int primary key);\n"
                                                            "drop table public.temp;\n")
        res = rls_estatico.analizar(self.dir)
        self.validar(res, "rls_estatico")
        subs = self.subreglas(res)
        for s in ("rls_deshabilitado", "politica_siempre_true", "politica_user_metadata", "secdef_sin_search_path",
                  "secdef_ejecutable_anon", "auth_users_expuesto", "vista_security_definer", "grant_anon_amplio",
                  "sin_pk", "fk_sin_indice", "bucket_publico"):
            self.assertIn(s, subs)
        rls = [h for h in res["hallazgos"] if h["regla"].endswith("rls_deshabilitado")]
        self.assertEqual([h["evidencia"] for h in rls], ["public.logs"])  # temp se eliminó después
        self.assertEqual(rls[0]["severidad_sugerida"], "critica")

    def test_correcto(self):
        self.escribir("supabase/migrations/1.sql", """
create table public.a (id uuid primary key, dueno uuid references auth.users(id));
create index a_dueno on public.a (dueno);
alter table public.a enable row level security;
create policy "p" on public.a for select using (auth.uid() = dueno);
create or replace function public.g() returns void language sql security definer set search_path = '' as $$ select 1 $$;
revoke execute on function public.g() from public, anon;
""")
        res = rls_estatico.analizar(self.dir)
        self.assertEqual(res["hallazgos"], [])
        self.assertIn("ok_rls_migraciones", self.pases(res))

    def test_rls_sin_politica(self):
        self.escribir("supabase/migrations/1.sql", "create table public.a (id int primary key);\n"
                                                   "alter table public.a enable row level security;\n")
        # DECISIONES #12 — ronda 6 (stack): RLS activo sin políticas es deny-all (anon/authenticated no acceden),
        # no una política permisiva; ya no es hallazgo de DAT-RLS-PERMISIVA. Sigue visible como informativo de
        # nivel info y sin pase (el control no puede quedar en pass por esta tabla).
        res = rls_estatico.analizar(self.dir)
        # DECISIONES #12 (adenda 2): además es hallazgo info rls_sin_politicas (→ DAT-RLS-DENY-ALL, no PERMISIVA).
        self.assertEqual(self.subreglas(res), ["rls_sin_politicas"])
        self.assertEqual([i["regla"].split(".", 1)[1] for i in res["informativos"]], ["rls_sin_politica"])
        self.assertEqual(res["informativos"][0]["severidad"], "info")
        self.assertEqual(self.pases(res), [])

    def test_sin_migraciones_no_evaluado(self):
        # Supabase sin migraciones versionadas (esquema hecho en el dashboard): no se puede afirmar no_aplica.
        res = rls_estatico.analizar(self.dir)
        self.assertEqual(res["estado"], "no_evaluado")
        self.assertIn("get_advisors", res["motivo"])


# --------------------------------------------------------------------------------------------------
class TestUxEstatico(Base):
    def test_heuristicas(self):
        self.escribir("index.html", '<!doctype html><html><head><title>x</title></head><body>'
                                    '<img src="a.png"><input id="n"></body></html>')
        self.escribir("src/App.tsx", """export function App({ props }) {
  return (<div>
    <img src={logo} alt="" />
    <img src={foto} className="x" />
    <img {...props} />
    <label htmlFor="email">Correo</label><input id="email" type="email" />
    <label>Nombre <input type="text" /></label>
    <input type="text" placeholder="sin label" />
    <input type="hidden" name="t" />
    <input aria-label="buscar" />
    <div onClick={() => abrir()}>abrir</div>
    <div role="button" tabIndex={0} onClick={x} onKeyDown={y}>ok</div>
    <span role="button" onClick={x}>sin teclado</span>
    <button className="outline-none">a</button>
    <button className="outline-none focus-visible:ring-2">b</button>
  </div>);
}
""")
        self.escribir("src/a.css", "button { outline: none; }\n")
        self.escribir("src/b.css", "a { outline: 0; }\na:focus-visible { box-shadow: 0 0 0 2px blue; }\n")
        res = ux_estatico.analizar(self.dir)
        self.validar(res, "ux_estatico")
        por = {}
        for h in res["hallazgos"]:
            por.setdefault(h["regla"].split(".", 1)[1], []).append((h["archivo"], h["linea"]))
        self.assertEqual(por["html_sin_lang"], [("index.html", 1)])
        self.assertEqual(por["sin_viewport"], [("index.html", 1)])
        self.assertEqual(por["img_sin_alt"], [("index.html", 1), ("src/App.tsx", 4)])
        self.assertEqual(por["input_sin_label"], [("index.html", 1), ("src/App.tsx", 8)])
        self.assertEqual(por["click_en_div"], [("src/App.tsx", 11), ("src/App.tsx", 13)])
        self.assertEqual(por["outline_none"], [("src/App.tsx", 14), ("src/a.css", 1)])

    def test_viewport_bloquea_zoom(self):
        self.escribir("index.html", '<html lang="es"><head><meta name="viewport" content="width=device-width, '
                                    'user-scalable=no"></head></html>')
        self.assertEqual(self.subreglas(ux_estatico.analizar(self.dir)), ["sin_viewport"])

    def test_limpio(self):
        self.escribir("index.html", '<html lang="es"><head><meta name="viewport" content="width=device-width, '
                                    'initial-scale=1"></head><body><img src="a" alt="logo"></body></html>')
        res = ux_estatico.analizar(self.dir)
        self.assertEqual(res["hallazgos"], [])
        self.assertIn("ok_html_lang", self.pases(res))


# --------------------------------------------------------------------------------------------------
class TestPresupuestoBuild(Base):
    def test_chunk_grande(self):
        self.escribir("dist/index.html", '<script type="module" src="/assets/index-abc12345.js"></script>')
        self.escribir("dist/assets/index-abc12345.js", b"a" * 600_000)
        self.escribir("dist/assets/vendor-def67890.js", b"b" * 1_200_000)
        self.escribir("dist/assets/chico-0a1b2c3d.js", b"c" * 1000)
        self.escribir("dist/assets/foto.png", b"\x89PNG" + b"0" * 300_000)
        self.escribir("dist/datos-reales/x.js", b"d" * 900_000)  # confidencial: no se mide
        res = presupuesto_build.analizar(self.dir)
        self.validar(res, "presupuesto_build")
        chunks = {h["archivo"]: h["severidad_sugerida"] for h in res["hallazgos"] if h["regla"].endswith("chunk_grande")}
        self.assertEqual(chunks, {"dist/assets/index-abc12345.js": "baja", "dist/assets/vendor-def67890.js": "media"})
        self.assertIn("imagen_grande", self.subreglas(res))
        self.assertIn("sin_cache_hash", self.subreglas(res))  # foto.png sin hash en el nombre

    def test_hash_base64url_con_guion(self):
        self.escribir("dist/assets/ort.wasm.bundle.min-Du-luQf8.js", b"a" * 10)
        self.escribir("dist/assets/logo-BkF_x2Qa.svg", b"a" * 10)
        self.assertNotIn("sin_cache_hash", self.subreglas(presupuesto_build.analizar(self.dir)))

    def test_bajo_presupuesto(self):
        self.escribir("dist/assets/index-abc12345.js", b"a" * 1000)
        res = presupuesto_build.analizar(self.dir)
        self.assertEqual(res["hallazgos"], [])
        self.assertIn("ok_presupuesto", self.pases(res))

    def test_sin_build_no_evaluado(self):
        self.escribir("src/a.js", "x")
        res = presupuesto_build.analizar(self.dir)
        self.assertEqual(res["estado"], "no_evaluado")
        self.assertIn("build", res["motivo"])


# --------------------------------------------------------------------------------------------------
class TestContratoConEstado(unittest.TestCase):
    """La integración propuesta (fallbacks_integracion.md) con scripts/estado.py tal como está hoy:
    fallback en `herramientas` y `herramientas_parciales`, hallazgos mapeados por subregla y pases ok_
    mapeados solo si el control queda cubierto por completo."""

    def setUp(self):
        sys.path.insert(0, str(RAIZ / "scripts"))
        import estado
        self.estado = estado

    def control(self, mapea, parciales=("dockerfile",)):
        return {"id": "INF-DOCKERFILE", "gate": "N2", "metodo": "determinista", "aplicabilidad": "aplica",
                "herramientas": ["hadolint", "trivy", "dockerfile"], "herramientas_parciales": list(parciales),
                "mapea_reglas": list(mapea)}

    def calcular(self, ctrl, hallazgos=(), pases=()):
        res = self.estado.calcular({ctrl["id"]: ctrl}, list(hallazgos), {"dockerfile": "ok", "hadolint": "ausente",
                                   "trivy": "ausente"}, set(pases), "estandar", "2026-11-18")
        return res[0]

    def test_fallback_sin_hallazgos_no_da_pass(self):
        ctrl = self.control(["hadolint:*", "check:dockerfile.tag_latest", "check:dockerfile.usuario_root"])
        r = self.calcular(ctrl, pases=["check:dockerfile.ok_tag_latest", "check:dockerfile.ok_usuario_root"])
        self.assertEqual(r["estado"], "no_evaluado")
        self.assertIn("cobertura parcial", r["motivo"])

    def test_fallback_con_hallazgo_da_fail(self):
        ctrl = self.control(["hadolint:*", "check:dockerfile.tag_latest"])
        h = {"id": "H1", "control": "INF-DOCKERFILE", "severidad": "media", "gate": "N2"}
        self.assertEqual(self.calcular(ctrl, hallazgos=[h])["estado"], "fail")

    def test_pase_ok_mapeado_explicito_da_pass(self):
        ctrl = self.control(["hadolint:*", "check:dockerfile.tag_latest", "check:dockerfile.ok_tag_latest"])
        r = self.calcular(ctrl, pases=["check:dockerfile.ok_tag_latest"])
        self.assertEqual(r["estado"], "pass")

    def test_comodin_dejaria_pasar_un_parcial(self):
        # Documenta por qué la propuesta NO usa "check:<n>.*": el comodín captura los pases ok_.
        ctrl = self.control(["hadolint:*", "check:dockerfile.*"])
        self.assertEqual(self.calcular(ctrl, pases=["check:dockerfile.ok_tag_latest"])["estado"], "pass")


if __name__ == "__main__":
    unittest.main()
