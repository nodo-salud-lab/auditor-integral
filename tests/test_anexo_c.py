"""Correcciones del Anexo C del brazo C (validacion/brazo-c-kine-us/INFORME-KINE-US.md).

AUD-INF   controles de servidor/BD/IaC condicionados al perfil (`servidor`, `bd`, `iac`) y sin «pases vacíos».
IUA-BANDA con cobertura < umbral.iua_cobertura_minima_banda la banda del IUA se omite (gris) y el informe lo dice.
AUD-WASM  presupuesto_build: subregla informativa wasm_grande (.wasm/.onnx > umbral.binario_wasm_max_kb).
M-01      scripts/checks/tipos.py: runner opcional de tsc (confiable; ronda 4) --noEmit → COD-TIPOS.
M-02      archivo_grande, funcion_larga, devdep_sin_uso y bloque_duplicado mapeados en el catálogo.
M-05      CCN en .tsx/.jsx sin contar los condicionales del JSX.
AUD-REM   remediación de OPS-ERROR-TRACKING según el perfil (salud o CSP connect-src 'self').
M-04      documentado que un vite.config que ejecuta git puede escribir .git/index.
"""
import json
import os
import stat
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))

import catalogo  # noqa: E402
import complejidad  # noqa: E402
import detectar_stack as ds  # noqa: E402
import estado  # noqa: E402
import iua  # noqa: E402
import presupuesto_build  # noqa: E402
import render_informe  # noqa: E402
import tipos  # noqa: E402
import utiles  # noqa: E402
import validar_schema as vs  # noqa: E402

SCHEMA_PERFIL = json.loads((RAIZ / "schemas" / "perfil.schema.json").read_text(encoding="utf-8"))
SCHEMA_TEC = vs.subschema(SCHEMA_PERFIL, "perfil_tecnico")
CONTROLES_SERVIDOR = ("INF-REGION", "INF-IAC-REPRO", "OPS-HEALTH", "INF-TIMEOUTS-SALIDA", "OPS-LOGS-ESTRUCTURADOS")


def mapea(regla):
    herramienta, resto = regla.split(":", 1)
    return catalogo.control_por_regla(herramienta, resto)


def cat():
    return {c["id"]: c for c in catalogo.cargar_catalogo()}


class Proyecto(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def escribir(self, rel, contenido):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contenido, bytes):
            p.write_bytes(contenido)
        else:
            p.write_text(contenido, encoding="utf-8")
        return p


# ---------------------------------------------------------------------------------------------- AUD-INF
class TestPerfilServidorBd(Proyecto):
    def test_pwa_sin_servidor_ni_bd(self):
        self.escribir("package.json", json.dumps({"dependencies": {"react": "18", "dcmjs": "1"},
                                                  "devDependencies": {"vite": "5", "vite-plugin-pwa": "1"}}))
        self.escribir("src/main.tsx", "export const a = 1;\n")
        p = ds.detectar(self.dir)
        self.assertIs(p["servidor"], False)
        self.assertIs(p["bd"], False)
        self.assertIs(p["iac"], False)
        self.assertEqual(vs.validar(p, SCHEMA_TEC), [])

    def test_express_y_pg(self):
        self.escribir("package.json", json.dumps({"dependencies": {"express": "4", "pg": "8"}}))
        p = ds.detectar(self.dir)
        self.assertIs(p["servidor"], True)
        self.assertIs(p["bd"], True)
        self.assertIn("express", p["detalle"]["servidor"])
        self.assertIn("pg", p["detalle"]["bd"])
        self.assertEqual(vs.validar(p, SCHEMA_TEC), [])

    def test_baas_y_ssr_cuentan(self):
        self.escribir("package.json", json.dumps({"dependencies": {"next": "14", "@supabase/supabase-js": "2"}}))
        p = ds.detectar(self.dir)
        self.assertIs(p["servidor"], True)  # next = SSR
        self.assertIs(p["bd"], True)        # BaaS con BD

    def test_python_fastapi_sqlalchemy_y_migraciones(self):
        self.escribir("requirements.txt", "fastapi\nsqlalchemy\n")
        p = ds.detectar(self.dir)
        self.assertIs(p["servidor"], True)
        self.assertIs(p["bd"], True)
        d = self.dir / "otro"
        d.mkdir()
        (d / "supabase" / "migrations").mkdir(parents=True)
        (d / "supabase" / "migrations" / "001.sql").write_text("create table a (id int);\n")
        self.assertIs(ds.detectar(d)["bd"], True)

    def test_docker_implica_servidor(self):
        self.escribir("Dockerfile", "FROM node:20\n")
        self.assertIs(ds.detectar(self.dir)["servidor"], True)


class TestBanderasEnPerfil(Proyecto):
    def test_banderas_archivos_incluyen_servidor_y_bd(self):
        self.assertIn("servidor", utiles.BANDERAS_ARCHIVOS)
        self.assertIn("bd", utiles.BANDERAS_ARCHIVOS)
        with open(RAIZ / "catalogo" / "perfil_riesgo.toml", "rb") as f:
            nombres = {b["nombre"]: b for b in tomllib.load(f)["bandera"]}
        for b in ("servidor", "bd"):
            self.assertEqual(nombres[b]["deteccion"], "archivos")

    def test_perfil_tecnico_alimenta_las_banderas(self):
        self.escribir("perfil_tecnico.json", json.dumps({"servidor": False, "bd": False, "iac": False}))
        b = utiles.cargar_perfil(self.dir)["banderas"]
        self.assertIs(b["servidor"], False)
        self.assertIs(b["bd"], False)

    def test_perfil_json_sin_servidor_toma_el_detectado(self):
        banderas = {k: None for k in utiles.BANDERAS_ARCHIVOS + utiles.BANDERAS_ENTREVISTA
                    if k not in ("servidor", "bd")}
        self.escribir("perfil.json", json.dumps({"version_esquema": "1", "banderas": banderas}))
        self.escribir("perfil_tecnico.json", json.dumps({"servidor": False, "bd": True}))
        p = utiles.cargar_perfil(self.dir)
        self.assertEqual(p["origen"], "perfil")
        self.assertIs(p["banderas"]["servidor"], False)
        self.assertIs(p["banderas"]["bd"], True)

    def test_perfil_json_explicito_prevalece(self):
        banderas = {k: None for k in utiles.BANDERAS_ARCHIVOS + utiles.BANDERAS_ENTREVISTA}
        banderas["servidor"] = True
        self.escribir("perfil.json", json.dumps({"version_esquema": "1", "banderas": banderas}))
        self.escribir("perfil_tecnico.json", json.dumps({"servidor": False, "bd": False}))
        self.assertIs(utiles.cargar_perfil(self.dir)["banderas"]["servidor"], True)
        self.assertEqual(vs.validar({"version_esquema": "1", "banderas": banderas}, SCHEMA_PERFIL), [])


class TestControlesCondicionados(unittest.TestCase):
    PERFIL_PWA = {"banderas": {"servidor": False, "bd": False, "iac": False, "baas": "ninguno",
                               "ssr_serverless": False}}

    def test_condiciones_dependen_del_perfil(self):
        c = cat()
        for cid in CONTROLES_SERVIDOR:
            with self.subTest(control=cid):
                nombres = catalogo.nombres_en_condicion(c[cid]["condicion"])
                self.assertTrue(nombres & {"servidor", "bd", "iac"}, c[cid]["condicion"])

    def test_pwa_sin_servidor_quedan_no_aplica(self):
        indice = utiles.indice_controles(self.PERFIL_PWA)
        r = {x["control"]: x for x in estado.calcular(indice, [], {"semgrep": "ok", "detectar_stack": "ok",
                                                                   "archivos_clave": "ok", "bearer": "ok"},
                                                      set(), "profundo", "2026-11-18")}
        for cid in CONTROLES_SERVIDOR:
            with self.subTest(control=cid):
                self.assertEqual(r[cid]["estado"], "no_aplica", r[cid])

    def test_con_servidor_no_hay_pase_vacio(self):
        perfil = {"banderas": {"servidor": True, "bd": True, "iac": True}}
        indice = {k: v for k, v in utiles.indice_controles(perfil).items() if k in CONTROLES_SERVIDOR}
        herr = {"semgrep": "ok", "detectar_stack": "ok", "archivos_clave": "ok", "bearer": "ok"}
        r = {x["control"]: x for x in estado.calcular(indice, [], herr, set(), "profundo", "2026-11-18")}
        for cid in CONTROLES_SERVIDOR:
            with self.subTest(control=cid):
                self.assertEqual(r[cid]["estado"], "no_evaluado", r[cid])
                self.assertIn("checks_pass", r[cid]["motivo"])

    def test_ops_health_pasa_solo_con_pase_explicito(self):
        perfil = {"banderas": {"servidor": True}}
        indice = {"OPS-HEALTH": utiles.indice_controles(perfil)["OPS-HEALTH"]}
        r = estado.calcular(indice, [], {"archivos_clave": "ok"}, {"check:archivos_clave.health"}, "profundo",
                            "2026-11-18")[0]
        self.assertEqual(r["estado"], "pass")

    def test_ningun_control_pasa_por_ejecucion_sin_mapeo(self):
        # Una herramienta determinista que corre ok no evalúa un control si ninguna de sus reglas mapea a él:
        # esos controles deben exigir checks_pass. Excepción declarada: INF-INVENTARIO (el inventario ES la
        # salida de detectar_stack).
        excepciones = {"INF-INVENTARIO"}
        malos = []
        for cid, c in cat().items():
            det = [h for h in c.get("herramientas", []) if not estado.es_agente_llm(h)
                   and h not in estado.COMPONENTES_ENTREVISTA and h not in estado.COMPONENTES_MANUALES]
            llm = [h for h in c.get("herramientas", []) if estado.es_agente_llm(h)]
            if c["metodo"] in ("determinista", "mixto") and det and not llm and not c["mapea_reglas"] \
                    and cid not in excepciones and not c.get("exige_checks_pass"):
                malos.append(cid)
        self.assertEqual(malos, [])

    def test_exige_checks_pass_en_estado(self):
        c = {"id": "INF-X", "titulo": "x", "dominio": "INF", "gate": "N2", "metodo": "determinista",
             "herramientas": ["semgrep"], "condicion": "siempre", "mapea_reglas": ["check:x.ok"],
             "exige_checks_pass": True, "aplicabilidad": "aplica"}
        r = estado.calcular({"INF-X": c}, [], {"semgrep": "ok"}, set(), "profundo", "2026-11-18")[0]
        self.assertEqual(r["estado"], "no_evaluado")
        r = estado.calcular({"INF-X": c}, [], {"semgrep": "ok"}, {"check:x.ok"}, "profundo", "2026-11-18")[0]
        self.assertEqual(r["estado"], "pass")


# ---------------------------------------------------------------------------------------------- IUA-BANDA
class TestIuaBanda(unittest.TestCase):
    def setUp(self):
        self.cfg = iua.cargar_config()

    def datos(self, completo):
        pw = {"teclado": {"interactivos": 10, "alcanzables_foco_visible": 10},
              "responsive": {"viewports": [{"ancho": 360, "scroll_horizontal": False}],
                             "objetivos_total": 1, "objetivos_24px": 1},
              "estados": {"llamadas": 2, "con_estados_visibles": 2},
              "limpieza": {"tipos_error": []}}
        if not completo:  # cobertura 0,6: sin accesibilidad (25) ni rendimiento (15)
            return {"axe": [], "lighthouse": [], "playwright": pw, "hallazgos": []}
        return {"axe": [{"passes": [{"id": "a", "impact": "critical", "tags": ["wcag2a"]}], "violations": [],
                         "incomplete": [], "inapplicable": []}],
                "lighthouse": [], "playwright": pw, "hallazgos": []}

    def test_umbral_en_config(self):
        with open(RAIZ / "config" / "umbrales.toml", "rb") as f:
            u = tomllib.load(f)["umbral"]["iua_cobertura_minima_banda"]
        self.assertEqual(u["valor"], 0.7)
        self.assertEqual(u["origen"], "propuesta")
        self.assertEqual(self.cfg["cobertura_minima_banda"], 0.7)

    def test_cobertura_baja_omite_banda(self):
        r = iua.calcular(self.datos(False), self.cfg)
        self.assertEqual(r["cobertura"]["fraccion"], 0.6)
        self.assertEqual(r["iua"], 100.0)
        self.assertIsNone(r["banda"])
        self.assertTrue(r["banda_omitida"])
        self.assertIn("0,70", r["banda_motivo"])

    def test_cobertura_suficiente_conserva_banda(self):
        r = iua.calcular(self.datos(True), self.cfg)
        self.assertEqual(r["cobertura"]["fraccion"], 0.85)
        self.assertEqual(r["banda"], "bueno")
        self.assertFalse(r["banda_omitida"])

    def test_informe_lo_dice(self):
        texto = render_informe._seccion_iua(iua.calcular(self.datos(False), self.cfg))
        self.assertIn("banda omitida", texto)
        self.assertIn("gris", texto)
        self.assertNotIn("(None)", texto)
        self.assertNotIn("bueno)", texto)


# ---------------------------------------------------------------------------------------------- AUD-WASM
class TestWasmGrande(Proyecto):
    def test_umbral(self):
        with open(RAIZ / "config" / "umbrales.toml", "rb") as f:
            u = tomllib.load(f)["umbral"]["binario_wasm_max_kb"]
        self.assertEqual(u["origen"], "propuesta")

    def test_wasm_y_onnx_grandes_informativos(self):
        limite = presupuesto_build.fb.umbral("binario_wasm_max_kb", 0)
        self.escribir("dist/assets/ort-wasm-simd-Ab12Cd34.wasm", b"\0" * int(limite * 1000 + 5000))
        self.escribir("dist/modelos/seg.onnx", b"\0" * int(limite * 1000 + 5000))
        self.escribir("dist/assets/chico-Ab12Cd34.wasm", b"\0" * 100)
        res = presupuesto_build.analizar(self.dir)
        w = [h for h in res["hallazgos"] if h["regla"] == "check:presupuesto_build.wasm_grande"]
        self.assertEqual(sorted(h["archivo"] for h in w), ["dist/assets/ort-wasm-simd-Ab12Cd34.wasm",
                                                         "dist/modelos/seg.onnx"])
        self.assertTrue(all(h["severidad_sugerida"] == "info" for h in w))
        # informativa: no impide el pase de presupuesto JS
        self.assertIn("check:presupuesto_build.ok_presupuesto", [p["regla"] for p in res["checks_pass"]])

    def test_wasm_grande_no_se_mapea(self):
        self.assertIsNone(mapea("check:presupuesto_build.wasm_grande"))


# ---------------------------------------------------------------------------------------------- M-01
class TestTipos(Proyecto):
    def setUp(self):
        super().setUp()
        self.bin = self.dir / "_bin"
        self.bin.mkdir()
        self.registro = self.dir / "_registro.json"
        self.proy = self.dir / "proy"
        self.proy.mkdir()

    def tsc_falso(self, salida, codigo, listar=True):
        """tsc CONFIABLE externo (fuera del proyecto; ronda 4): registra cómo se lo llamó y lista src/a.ts."""
        guion = self.bin / "tsc"
        lista = (str(self.proy / "src" / "a.ts") + "\n") if listar else ""
        guion.write_text(
            "#!/usr/bin/env python3\nimport json, os, sys\n"
            f"json.dump({{'args': sys.argv[1:], 'cwd': os.getcwd(), 'gol': os.environ.get('GIT_OPTIONAL_LOCKS')}}, "
            f"open({str(self.registro)!r}, 'w'))\n"
            f"sys.stdout.write({salida + lista!r})\nsys.exit({codigo})\n", encoding="utf-8")
        guion.chmod(guion.stat().st_mode | stat.S_IEXEC)
        return str(guion)

    def con_tsc(self):
        (self.proy / "tsconfig.json").write_text('{"compilerOptions": {"strict": true}}\n')
        (self.proy / "src").mkdir(exist_ok=True)
        (self.proy / "src" / "a.ts").write_text("export const a: number = 1;\n")

    def test_sin_tsc_confiable_no_evaluado(self):
        (self.proy / "tsconfig.json").write_text("{}\n")
        res = tipos.analizar(self.proy, tsc="")
        self.assertEqual(res["estado"], "no_evaluado")
        self.assertIn("node_modules/.bin/tsc", res["motivo"])
        self.assertFalse(self.registro.exists())  # no se ejecutó nada

    def test_sin_errores_pasa(self):
        self.con_tsc()
        antes = sorted(p.relative_to(self.proy).as_posix() for p in self.proy.rglob("*"))
        res = tipos.analizar(self.proy, tsc=self.tsc_falso("", 0))
        self.assertEqual(res["estado"], "ok")
        self.assertEqual(res["hallazgos"], [])
        self.assertEqual([p["regla"] for p in res["checks_pass"]], ["check:tipos.sin_errores"])
        reg = json.loads(self.registro.read_text())
        self.assertEqual(reg["args"][:2], ["--noEmit", "--incremental"])
        self.assertIn("--listFiles", reg["args"])
        self.assertEqual(reg["gol"], "0")
        self.assertEqual(Path(reg["cwd"]).resolve(), self.proy.resolve())
        despues = sorted(p.relative_to(self.proy).as_posix() for p in self.proy.rglob("*"))
        self.assertEqual(antes, despues)  # no escribe en el proyecto

    def test_errores_fallan(self):
        self.con_tsc()
        salida = ("src/a.ts(3,7): error TS2322: Type 'string' is not assignable to type 'number'.\n"
                  "src/b.tsx(10,1): error TS2304: Cannot find name 'x'.\n")
        res = tipos.analizar(self.proy, tsc=self.tsc_falso(salida, 2))
        self.assertEqual(res["estado"], "ok")
        self.assertEqual([(h["archivo"], h["linea"]) for h in res["hallazgos"]], [("src/a.ts", 3), ("src/b.tsx", 10)])
        self.assertTrue(all(h["regla"] == "check:tipos.error_tsc" for h in res["hallazgos"]))
        self.assertEqual(res["checks_pass"], [])

    def test_error_de_configuracion_no_evaluado(self):
        self.con_tsc()
        res = tipos.analizar(self.proy, tsc=self.tsc_falso("error TS5069: Option 'tsBuildInfoFile' cannot be "
                                                            "specified without 'incremental'.\n", 1, listar=False))
        self.assertEqual(res["estado"], "no_evaluado")

    def test_timeout(self):
        self.con_tsc()
        guion = self.bin / "tsc"
        guion.write_text("#!/bin/sh\nsleep 5\n")
        guion.chmod(guion.stat().st_mode | stat.S_IEXEC)
        res = tipos.analizar(self.proy, tsc=str(guion), timeout=0.5)
        self.assertEqual(res["estado"], "timeout")

    def test_mapeo_cod_tipos(self):
        self.assertEqual(mapea("check:tipos.error_tsc"), "COD-TIPOS")
        c = cat()["COD-TIPOS"]
        self.assertIn("tipos", c["herramientas"])
        r = estado.calcular({"COD-TIPOS": dict(c, aplicabilidad="aplica")}, [], {"tipos": "ok"},
                            {"check:tipos.sin_errores"}, "estandar", "2026-11-18")[0]
        self.assertEqual(r["estado"], "pass")

    def test_en_el_despachador(self):
        texto = (RAIZ / "scripts" / "ejecutar_scanners.sh").read_text()
        self.assertIn("tipos|check|checks/tipos.py|check_tipos|check:tipos", texto)


# ---------------------------------------------------------------------------------------------- M-02
class TestMapeoReglasInformativas(unittest.TestCase):
    def test_mapeo(self):
        esperado = {"check:complejidad.archivo_grande": "COD-COMPLEJIDAD",
                    "check:complejidad.funcion_larga": "COD-COMPLEJIDAD",
                    "check:deps_muertas.devdep_sin_uso": "COD-CICLOS-MUERTO",
                    "check:duplicacion.bloque_duplicado": "COD-DUPLICACION"}
        for regla, control in esperado.items():
            with self.subTest(regla=regla):
                self.assertEqual(mapea(regla), control)


# ---------------------------------------------------------------------------------------------- M-05
class TestCcnJsx(unittest.TestCase):
    def ccn(self, texto, nombre, jsx=True):
        fs = complejidad.funciones_js(texto, jsx=jsx)
        return next(f["ccn"] for f in fs if f["nombre"] == nombre)

    def test_condicionales_del_jsx_no_cuentan(self):
        filas = "\n".join(f"      {{p.c{i} && <span>{i}</span>}}" for i in range(20))
        texto = ("export function Panel(p) {\n  if (!p.ok) return null;\n  return (\n    <div className=\"x\">\n"
                 f"{filas}\n      {{p.a ? <A /> : <B />}}\n    </div>\n  );\n}}\n")
        self.assertEqual(self.ccn(texto, "Panel"), 2)  # 1 + if

    def test_callback_dentro_del_jsx_se_mide_aparte(self):
        texto = ("function Lista(p) {\n  return <ul>{p.xs.map(x => {\n    if (x.a) { return <li>{x.b && 'b'}</li>; }\n"
                 "    return null;\n  })}</ul>;\n}\n")
        fs = complejidad.funciones_js(texto, jsx=True)
        self.assertEqual(next(f["ccn"] for f in fs if f["nombre"] == "Lista"), 1)
        self.assertEqual(next(f["ccn"] for f in fs if f["nombre"] == "<flecha>"), 2)  # 1 + if (no el && del JSX)

    def test_comparacion_y_genericos_no_son_jsx(self):
        texto = "const f = <T,>(a: T[], n: number) => {\n  if (a.length < n && n > 0) { return 1; }\n  return 0;\n};\n"
        self.assertEqual(self.ccn(texto, "f"), 3)

    def test_ts_sin_cambios(self):
        texto = "function g(a, b) {\n  return a && b ? 1 : 2;\n}\n"
        self.assertEqual(self.ccn(texto, "g", jsx=False), 3)

    def test_analizar_aplica_a_tsx(self):
        with tempfile.TemporaryDirectory() as d:
            filas = "\n".join(f"      {{p.c{i} && <span>{i}</span>}}" for i in range(30))
            Path(d, "Panel.tsx").write_text("export function Panel(p) {\n  return (\n    <div>\n" + filas +
                                            "\n    </div>\n  );\n}\n", encoding="utf-8")
            res = complejidad.analizar(d)
        self.assertNotIn("check:complejidad.ccn_alta", [h["regla"] for h in res["hallazgos"]])


# ---------------------------------------------------------------------------------------------- AUD-REM
class TestRemediacionPorPerfil(Proyecto):
    GENERICA = "Configurar un servicio de seguimiento de errores (p. ej. Sentry) en frontend y backend."

    def test_salud_recomienda_registro_local(self):
        t = render_informe.remediacion_por_perfil("OPS-ERROR-TRACKING", self.GENERICA, {"salud": True}, False)
        self.assertNotIn("Sentry)", t)
        self.assertIn("registro local", t)
        self.assertIn("sin datos del paciente", t)

    def test_csp_connect_self(self):
        self.escribir("index.html", "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; "
                                    "connect-src 'self' blob:; img-src 'self' data:\">")
        self.assertTrue(render_informe.csp_connect_solo_self(self.dir))
        t = render_informe.remediacion_por_perfil("OPS-ERROR-TRACKING", self.GENERICA, {}, True)
        self.assertIn("registro local", t)

    def test_csp_con_origen_externo_no_es_restrictiva(self):
        self.escribir("index.html", "<meta http-equiv=\"Content-Security-Policy\" "
                                    "content=\"connect-src 'self' https://o1.ingest.sentry.io\">")
        self.assertFalse(render_informe.csp_connect_solo_self(self.dir))

    def test_sin_perfil_conserva_texto(self):
        self.assertEqual(render_informe.remediacion_por_perfil("OPS-ERROR-TRACKING", self.GENERICA, {}, False),
                         self.GENERICA)
        self.assertEqual(render_informe.remediacion_por_perfil("COD-REPRO", "x", {"salud": True}, True), "x")


# ---------------------------------------------------------------------------------------------- M-04
class TestDocumentacionViteGit(unittest.TestCase):
    def test_readme_y_doctor(self):
        for ruta in (RAIZ / "README.md", RAIZ / "scripts" / "doctor.sh"):
            with self.subTest(archivo=ruta.name):
                texto = ruta.read_text(encoding="utf-8")
                self.assertIn("vite.config", texto)
                self.assertIn(".git/index", texto)
                self.assertIn("no ejecuta vite", texto)


if __name__ == "__main__":
    unittest.main()
