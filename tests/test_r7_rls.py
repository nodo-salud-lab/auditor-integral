"""Ronda 7, RLS deny-all (DECISIONES.md #12, adenda 2).

En la ronda 6 rls_estatico dejó «tabla con RLS activado y sin políticas» (deny-all) solo en `informativos` del crudo: no
llegaba a hallazgos.jsonl ni al informe. Ahora también es hallazgo `rls_sin_politicas` de severidad info → control
DAT-RLS-DENY-ALL (gate N4, sin bloqueo, nunca pass). Casos negativos: no hace fallar DAT-RLS-PERMISIVA ni DAT-RLS-ON,
no bloquea el global y no abre ningún pase.
"""
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import catalogo  # noqa: E402
import estado  # noqa: E402
import gates  # noqa: E402
import rls_estatico  # noqa: E402
import utiles  # noqa: E402
from normalizar import run as norm_run  # noqa: E402
from tmp_tests import tmp_dir  # noqa: E402

FECHA = "2026-11-20"
DENY_ALL = ("create table public.a (id int primary key);\n"
            "alter table public.a enable row level security;\n")
PERFIL_TECNICO = {"version_esquema": "1", "generador": "test", "lenguajes": ["typescript"], "frameworks": ["next"],
                  "ecosistemas": {}, "baas": "supabase", "orm": [], "ssr_serverless": False, "llm": False,
                  "pagos": False, "emails": False, "docker": False, "iac": False, "k8s": False, "movil": False,
                  "pwa": False, "multi_idioma": False, "agente_ia": False, "ci": False, "carpetas_build": []}


def cat():
    return {c["id"]: c for c in catalogo.cargar_catalogo()}


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tmp_dir(self)

    def escribir(self, rel, texto):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(texto, encoding="utf-8")

    @staticmethod
    def subs(res):
        return sorted(h["regla"].split(".", 1)[1] for h in res["hallazgos"])


class TestCheck(Base):
    def test_deny_all_es_hallazgo_info_sin_pase(self):
        self.escribir("supabase/migrations/1.sql", DENY_ALL)
        res = rls_estatico.analizar(self.dir)
        self.assertEqual(self.subs(res), ["rls_sin_politicas"])
        h = res["hallazgos"][0]
        self.assertEqual(h["severidad_sugerida"], "info")
        self.assertEqual((h["archivo"], h["linea"], h["evidencia"]), ("supabase/migrations/1.sql", 1, "public.a"))
        self.assertIn("deny-all", h["mensaje"])
        self.assertEqual(res["checks_pass"], [])  # fail-closed: sin pase ok_rls_migraciones
        self.assertEqual(res["informativos"][0]["severidad"], "info")  # compatibilidad del crudo

    def test_con_politica_no_hay_deny_all(self):
        self.escribir("supabase/migrations/1.sql", DENY_ALL + "create policy p on public.a for select "
                      "using (auth.uid() = id);\n")
        res = rls_estatico.analizar(self.dir)
        self.assertNotIn("rls_sin_politicas", self.subs(res))
        self.assertNotIn("informativos", res)

    def test_sin_rls_sigue_siendo_rls_deshabilitado(self):
        self.escribir("supabase/migrations/1.sql", "create table public.a (id int primary key);\n")
        self.assertEqual(self.subs(rls_estatico.analizar(self.dir)), ["rls_deshabilitado"])

    def test_esquema_no_expuesto_no_es_deny_all(self):
        self.escribir("supabase/migrations/1.sql", "create table privado.a (id int primary key);\n"
                      "alter table privado.a enable row level security;\n")
        self.assertNotIn("rls_sin_politicas", self.subs(rls_estatico.analizar(self.dir)))


class TestCatalogo(unittest.TestCase):
    def test_regla_va_a_deny_all_y_no_a_permisiva_ni_on(self):
        c = catalogo.cargar_catalogo()
        self.assertEqual(catalogo.control_por_regla("check", "rls_estatico.rls_sin_politicas", c,
                                                    archivo="supabase/migrations/1.sql"), "DAT-RLS-DENY-ALL")
        # el patrón antiguo (crudos de corridas anteriores) sigue en PERMISIVA; no coincide con el nuevo
        self.assertEqual(catalogo.control_por_regla("check", "rls_estatico.rls_sin_politica", c), "DAT-RLS-PERMISIVA")

    def test_control_info_sin_bloqueo_y_sin_pase(self):
        d = cat()["DAT-RLS-DENY-ALL"]
        self.assertEqual(d["severidad_base"], "info")
        self.assertFalse(d["bloquea_global"])
        self.assertEqual(d["evidencia_pass"], "no_demostrable_estatico")
        self.assertEqual(d["gate"], "N4")
        self.assertNotIn("DAT-RLS-DENY-ALL", gates.CONTROLES_SECRETO)

    def test_tiene_remediacion(self):
        import tomllib
        with open(RAIZ / "plantillas" / "remediaciones.toml", "rb") as f:
            rem = tomllib.load(f)
        texto = json.dumps(rem, ensure_ascii=False)
        self.assertIn("DAT-RLS-DENY-ALL", texto)


class TestCorrida(Base):
    """Normalización real (normalizar/run.py) + estado + gates sobre un crudo generado por el check."""

    def corrida(self, sql):
        self.escribir("proyecto/supabase/migrations/1.sql", sql)
        proyecto = self.dir / "proyecto"
        corrida = self.dir / "corrida"
        (corrida / "crudo").mkdir(parents=True)
        res = rls_estatico.analizar(proyecto)
        res.update(check="rls_estatico", version="1")
        (corrida / "crudo" / "check_rls_estatico.json").write_text(json.dumps(res), encoding="utf-8")
        (corrida / "crudo" / "check_rls_estatico.meta.json").write_text(json.dumps(
            {"herramienta": "rls_estatico", "estado": "ok", "version": "1"}), encoding="utf-8")
        (corrida / "run.json").write_text(json.dumps(
            {"version_esquema": "1", "id": "2026-11-20_0000-abc1234", "proyecto": str(proyecto), "modo": "estandar",
             "commit": None, "commit7": None, "inicio": "2026-11-20T00:00:00-03:00"}), encoding="utf-8")
        (corrida / "perfil_tecnico.json").write_text(json.dumps(PERFIL_TECNICO), encoding="utf-8")
        limitados, todos, resumen = norm_run.normalizar(corrida)
        return corrida, limitados, todos, resumen

    def evaluar(self, corrida, hallazgos):
        indice = utiles.indice_controles(utiles.cargar_perfil(corrida))
        ids = ("DAT-RLS-ON", "DAT-RLS-PERMISIVA", "DAT-RLS-DENY-ALL")
        sub = {k: indice[k] for k in ids}
        herr = {"rls_estatico": "ok"}
        est = estado.calcular(sub, hallazgos, herr, set(), "estandar", FECHA)
        return {e["control"]: e for e in est}, gates.calcular(est, indice, hallazgos, {}, set())

    def test_deny_all_llega_a_hallazgos_y_no_bloquea(self):
        corrida, limitados, todos, resumen = self.corrida(DENY_ALL)
        for lista in (limitados, todos):
            dn = [h for h in lista if h["control"] == "DAT-RLS-DENY-ALL"]
            self.assertEqual(len(dn), 1, lista)
            self.assertEqual(dn[0]["severidad"], "info")
            self.assertEqual(dn[0]["ubicacion"]["archivo"], "supabase/migrations/1.sql")
        self.assertNotIn("check:rls_estatico.rls_sin_politicas", resumen["sin_mapear"])
        self.assertEqual(resumen["checks_pass"], [])
        est, g = self.evaluar(corrida, limitados)
        self.assertEqual(est["DAT-RLS-DENY-ALL"]["estado"], "fail")
        self.assertNotEqual(est["DAT-RLS-PERMISIVA"]["estado"], "fail")
        self.assertNotEqual(est["DAT-RLS-ON"]["estado"], "fail")
        self.assertNotEqual(est["DAT-RLS-PERMISIVA"]["estado"], "pass")  # fail-closed: tampoco abre pase
        self.assertNotEqual(est["DAT-RLS-ON"]["estado"], "pass")
        self.assertEqual(g["global"]["bloqueos"], [])

    def test_sin_deny_all_el_control_queda_no_evaluado_nunca_pass(self):
        corrida, limitados, _, _ = self.corrida(DENY_ALL + "create policy p on public.a for select "
                                                "using (auth.uid() = id);\n")
        est, _ = self.evaluar(corrida, limitados)
        self.assertEqual(est["DAT-RLS-DENY-ALL"]["estado"], "no_evaluado")

    def test_rls_deshabilitado_sigue_bloqueando(self):
        corrida, limitados, _, _ = self.corrida("create table public.a (id int primary key);\n")
        est, g = self.evaluar(corrida, limitados)
        self.assertEqual(est["DAT-RLS-ON"]["estado"], "fail")
        self.assertIn("DAT-RLS-ON", [b["control"] for b in g["global"]["bloqueos"]])


if __name__ == "__main__":
    unittest.main()
