"""Integración de los fallbacks estáticos (DECISIONES.md #6) en el catálogo, el despachador y doctor.

Fuente: investigacion/propuestas/fallbacks_integracion.md (§3, §4 y §5). Decisiones que la propuesta
deja al investigador y que esta integración NO toma (quedan pendientes, por eso se comprueban aquí):
  - pases ok_ explícitos en SEG-SBOM y UX-LANG: no se mapean (ningún control pasa solo por fallback);
  - check:presupuesto_build.sin_cache_hash → INF-CACHE-CDN: no se mapea (severidad info);
  - quitar radon de COD-COMPLEJIDAD: no se toca.
"""
import re
import sys
import tomllib
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))

FALLBACKS = ["duplicacion", "complejidad", "deps_muertas", "migraciones_sql", "dockerfile", "iac", "sbom",
             "workflows", "rls_estatico", "ux_estatico", "presupuesto_build"]

# control → (fallback en herramientas/herramientas_parciales o None si solo mapeo, reglas que deben estar)
ESPERADO = {
    "COD-DUPLICACION": ("duplicacion", ["check:duplicacion.porcentaje_global"]),
    "COD-COMPLEJIDAD": ("complejidad", ["check:complejidad.ccn_alta"]),
    "COD-CICLOS-MUERTO": ("deps_muertas", ["check:deps_muertas.dep_sin_uso", "check:deps_muertas.dep_no_declarada"]),
    "DAT-MIGRACIONES-SEGURAS": ("migraciones_sql", [
        "check:migraciones_sql." + s for s in (
            "index_sin_concurrently", "drop_index_sin_concurrently", "concurrently_en_transaccion",
            "not_null_sin_default", "set_not_null", "drop_column", "drop_table", "rename", "cambio_tipo",
            "fk_sin_not_valid", "check_sin_not_valid", "sin_lock_timeout")]),
    "DAT-TIPOS": ("migraciones_sql", ["check:migraciones_sql.tipo_timestamp", "check:migraciones_sql.tipo_serial_int",
                                      "check:migraciones_sql.tipo_varchar"]),
    "INF-DOCKERFILE": ("dockerfile", ["check:dockerfile." + s for s in (
        "tag_latest", "usuario_root", "sudo", "add_vs_copy", "add_url", "cmd_shell_form", "apt_sin_pin",
        "apk_sin_pin", "pip_sin_pin", "curl_pipe_sh", "sin_multistage", "copy_todo_sin_dockerignore")]),
    "SEG-SECRETO-REPO": (None, ["check:dockerfile.secreto_en_env", "check:iac.tf_secreto_literal"]),
    "INF-IAC": ("iac", ["check:iac." + s for s in (
        "tf_ingreso_abierto", "tf_bucket_publico", "tf_sin_cifrado", "tf_bd_publica", "k8s_privilegiado",
        "k8s_host", "k8s_sin_nonroot", "k8s_sin_limites", "k8s_latest", "compose_puerto_bd")]),
    "SEG-SBOM": ("sbom", ["check:sbom.sbom_no_versionado"]),
    "COD-LICENCIAS": ("sbom", ["check:sbom.licencia_copyleft", "check:sbom.licencia_desconocida",
                               "check:sbom.proyecto_sin_licencia"]),
    "SEG-CICD": ("workflows", ["check:workflows." + s for s in (
        "sin_on", "sin_jobs", "job_sin_runs_on", "tabulador", "expresion_mal_cerrada", "runner_obsoleto")]),
    "COD-CI-BASICO": ("workflows", ["check:workflows.ci_sin_calidad"]),
    "DAT-RLS-ON": ("rls_estatico", ["check:rls_estatico.rls_deshabilitado", "check:rls_estatico.vista_security_definer"]),
    "DAT-RLS-PERMISIVA": ("rls_estatico", ["check:rls_estatico.rls_sin_politica",
                                           "check:rls_estatico.politica_siempre_true"]),
    "DAT-RLS-METADATA": ("rls_estatico", ["check:rls_estatico.politica_user_metadata"]),
    "DAT-SECDEF": ("rls_estatico", ["check:rls_estatico.secdef_sin_search_path",
                                    "check:rls_estatico.secdef_ejecutable_anon"]),
    "DAT-GRANTS": ("rls_estatico", ["check:rls_estatico.auth_users_expuesto", "check:rls_estatico.grant_anon_amplio"]),
    "DAT-PK-FK": ("rls_estatico", ["check:rls_estatico.sin_pk"]),
    "DAT-FK-INDICE": ("rls_estatico", ["check:rls_estatico.fk_sin_indice"]),
    "DAT-BUCKETS": (None, ["check:rls_estatico.bucket_publico"]),
    "UX-LANG": ("ux_estatico", ["check:ux_estatico.html_sin_lang"]),
    "UX-REFLOW": ("ux_estatico", ["check:ux_estatico.sin_viewport"]),
    "UX-AXE-CRIT": ("ux_estatico", ["check:ux_estatico.img_sin_alt"]),
    "UX-FORMULARIOS": ("ux_estatico", ["check:ux_estatico.input_sin_label"]),
    "UX-TECLADO": ("ux_estatico", ["check:ux_estatico.click_en_div", "check:ux_estatico.tabindex_positivo",
                                   "check:ux_estatico.outline_none"]),
    "UX-LIGHTHOUSE": ("presupuesto_build", ["check:presupuesto_build.chunk_grande",
                                            "check:presupuesto_build.imagen_grande"]),
}

# Valores previos que la integración debe conservar.
PREVIOS = {
    "COD-COMPLEJIDAD": (["lizard", "radon"], ["lizard:*"]),
    "INF-DOCKERFILE": (["hadolint", "trivy"], ["hadolint:*"]),
    "SEG-SECRETO-REPO": (["gitleaks", "trufflehog"], ["gitleaks:*", "semgrep:generic.secrets.*"]),
    "SEG-CICD": (["zizmor", "actionlint"], ["zizmor:*", "actionlint:*", "semgrep:yaml.github-actions.*"]),
    "COD-CI-BASICO": (["archivos_clave", "actionlint"], ["check:archivos_clave.ci*"]),
    "DAT-SECDEF": (["splinter"], ["splinter:0011*", "splinter:0028*", "splinter:0029*", "splinter:0031*"]),
}


def catalogo():
    with open(RAIZ / "catalogo" / "controles.toml", "rb") as f:
        return {c["id"]: c for c in tomllib.load(f)["control"]}


class TestCatalogoFallbacks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cat = catalogo()

    def test_fallback_en_herramientas_y_parciales(self):
        for cid, (fb, _) in ESPERADO.items():
            c = self.cat[cid]
            if fb is None:
                continue
            with self.subTest(control=cid):
                self.assertIn(fb, c["herramientas"])
                self.assertIn(fb, c.get("herramientas_parciales", []))

    def test_reglas_mapeadas(self):
        for cid, (_, reglas) in ESPERADO.items():
            with self.subTest(control=cid):
                for r in reglas:
                    self.assertIn(r, self.cat[cid]["mapea_reglas"])

    def test_todo_fallback_en_herramientas_es_parcial(self):
        for cid, c in self.cat.items():
            for fb in FALLBACKS:
                if fb in c.get("herramientas", []):
                    with self.subTest(control=cid, fallback=fb):
                        self.assertIn(fb, c.get("herramientas_parciales", []))

    def test_sin_comodin_ni_pase_ok_de_fallback(self):
        # Un comodín check:<fallback>.* o un ok_ mapeado dejaría pasar un control solo por el fallback.
        # Los pases ok_ de SEG-SBOM y UX-LANG quedan como decisión pendiente del investigador.
        patron = re.compile(r"^check:(%s)\.(\*|ok_)" % "|".join(FALLBACKS))
        for cid, c in self.cat.items():
            for r in c.get("mapea_reglas", []):
                with self.subTest(control=cid, regla=r):
                    self.assertIsNone(patron.match(r))

    def test_decisiones_pendientes_no_aplicadas(self):
        self.assertNotIn("check:presupuesto_build.sin_cache_hash", self.cat["INF-CACHE-CDN"]["mapea_reglas"])
        self.assertIn("radon", self.cat["COD-COMPLEJIDAD"]["herramientas"])

    def test_conserva_valores_previos(self):
        for cid, (herrs, reglas) in PREVIOS.items():
            with self.subTest(control=cid):
                self.assertEqual(self.cat[cid]["herramientas"][:len(herrs)], herrs)
                self.assertEqual(self.cat[cid]["mapea_reglas"][:len(reglas)], reglas)

    def test_cada_regla_en_un_solo_control(self):
        for cid, (_, reglas) in ESPERADO.items():
            for r in reglas:
                duenos = [k for k, c in self.cat.items() if r in c.get("mapea_reglas", [])]
                with self.subTest(regla=r):
                    self.assertEqual(duenos, [cid])

    def test_ningun_control_pasa_solo_por_fallback(self):
        import estado
        hoy = "2026-11-18"
        for cid, (fb, _) in ESPERADO.items():
            if fb is None:
                continue
            c = dict(self.cat[cid], aplicabilidad="aplica")
            herr = {h: "ausente" for h in c["herramientas"]}
            herr[fb] = "ok"
            pases = {f"check:{fb}.ok_{s}" for s in ("tag_latest", "sbom_versionado", "html_lang", "x")}
            with self.subTest(control=cid):
                r = estado.calcular({cid: c}, [], herr, pases, "profundo", hoy)[0]
                self.assertNotEqual(r["estado"], "pass", r)


class TestRlsFkCubiertaPorPkOUnique(unittest.TestCase):
    """Regresión hallada en la corrida de integración (app sembrada, perfiles.id PK + FK a auth.users):
    PRIMARY KEY y UNIQUE crean un índice implícito en Postgres; splinter 0001 no marca esas FK."""

    def analizar(self, sql):
        import tempfile
        sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
        import rls_estatico
        with tempfile.TemporaryDirectory() as d:
            ruta = Path(d) / "supabase" / "migrations" / "20250101_a.sql"
            ruta.parent.mkdir(parents=True)
            ruta.write_text(sql, encoding="utf-8")
            res = rls_estatico.analizar(d)
        return [h["evidencia"] for h in res["hallazgos"] if h["regla"].endswith("fk_sin_indice")]

    def test_fk_que_es_pk_de_columna(self):
        self.assertEqual(self.analizar(
            "create table public.perfiles (id uuid primary key references auth.users (id), nombre text);\n"), [])

    def test_fk_primera_columna_de_pk_o_unique_de_tabla(self):
        self.assertEqual(self.analizar(
            "create table public.a (id int primary key);\n"
            "create table public.b (a_id int references public.a(id), x int, primary key (a_id, x));\n"
            "create table public.c (a_id int references public.a(id), constraint u unique (a_id));\n"
            "create table public.d (a_id int unique references public.a(id));\n"), [])

    def test_fk_sin_indice_sigue_detectandose(self):
        ev = self.analizar("create table public.a (id int primary key);\n"
                           "create table public.b (id int primary key, a_id int references public.a(id));\n")
        self.assertEqual(len(ev), 1)


class TestDespachador(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.texto = (RAIZ / "scripts" / "ejecutar_scanners.sh").read_text()
        m = re.search(r"^TAREAS='(.*?)'", cls.texto, re.S | re.M)
        cls.tareas = {l.split("|")[0]: l.split("|") for l in m.group(1).splitlines()}

    def test_fallbacks_en_tareas(self):
        for fb in FALLBACKS + ["datos_confidenciales"]:
            with self.subTest(fallback=fb):
                self.assertEqual(self.tareas[fb], [fb, "check", f"checks/{fb}.py", f"check_{fb}", f"check:{fb}"])
                self.assertTrue((RAIZ / "scripts" / "checks" / f"{fb}.py").is_file())

    def test_checks_aislados(self):
        self.assertRegex(self.texto, r'"\$PY" -I "\$RAIZ/scripts/\$script"')


class TestDoctorCatalogo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        texto = (RAIZ / "scripts" / "doctor.sh").read_text()
        m = re.search(r"^CATALOGO='(.*?)'", texto, re.S | re.M)
        cls.cat = {l.split("|")[0]: l.split("|") for l in m.group(1).splitlines()}

    def test_nuevas_herramientas(self):
        for h in ("nuclei", "syft", "zap.sh", "psql"):
            self.assertIn(h, self.cat)

    def test_lizard_advierte_brew(self):
        self.assertIn("pipx install lizard", self.cat["lizard"][2])
        self.assertIn("NO usar brew install lizard", self.cat["lizard"][2])

    def test_playwright_oficial(self):
        self.assertIn("npm install -D @playwright/test", self.cat["playwright"][2])

    def test_cada_fallback_tiene_su_herramienta_real_en_doctor(self):
        reales = {"duplicacion": "jscpd", "complejidad": "lizard", "deps_muertas": "knip",
                  "migraciones_sql": "squawk", "dockerfile": "hadolint", "iac": "checkov", "sbom": "syft",
                  "workflows": "actionlint", "ux_estatico": "playwright", "presupuesto_build": "lhci"}
        for fb, real in reales.items():
            with self.subTest(fallback=fb):
                self.assertIn(real, self.cat)


if __name__ == "__main__":
    unittest.main()
