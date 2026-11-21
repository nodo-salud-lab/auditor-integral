"""Ronda 7 — grupo «datos» (regresión vista en harness real: tras la ronda 6, .claude-flow/neural/patterns.json del
historial pasó de «pii_tabular, 1 email» a «no inspeccionable»).

Diagnóstico: el único valor con forma de email de ese archivo es un buzón de sistema (forma noreply@…; dominio no
reservado), así que su descarte en la ronda 6 es correcto. Pero la ronda 6 sí abrió un hueco: un JSON NO tabular con
raíz objeto se omitía entero y un correo real en él se perdía. Ronda 7:

  A  JSON/YAML no tabular (configuración, estado, memoria de agente) con email real o teléfono +56 → pii_no_tabular
     (media, DAT-PII-TEST), en el árbol y en el historial; evidencia solo con conteos por tipo; sin pase.
  B  Lo de la ronda 6 se mantiene: dominios reservados y buzones de sistema no cuentan; policy.yaml/task.yaml de
     harness no vuelven como críticos; RUT válido sigue crítico; manifiestos públicos (package.json) no cuentan por
     el correo del autor.
  C  Fail-closed: un JSON truncado sin PII sigue no inspeccionable (sin pase), ahora con nota visible (truncado y
     correos descartados); los binarios (.db) siguen no inspeccionables.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import catalogo  # noqa: E402
import datos_confidenciales as dc  # noqa: E402
from tmp_tests import TMP_BASE, tmp_dir  # noqa: E402

GIT_ID = ["-c", "user.name=prueba", "-c", "user.email=prueba@example.invalid", "-c", "commit.gpgsign=false"]
PII = "check:datos_confidenciales.pii_tabular"
NT = "check:datos_confidenciales.pii_no_tabular"
PASE = "check:datos_confidenciales.no_trackeado"
# Valores sintéticos para las pruebas (no son datos de nadie): un dominio no reservado ficticio y un móvil de relleno.
CORREO_REAL = "persona.ficticia@correo-ficticio.cl"
FONO = "+56 9 1234 5678"


def git(proy, *args):
    return subprocess.run(["git", *GIT_ID, "-C", str(proy), *args], capture_output=True, text=True, check=True,
                          env=dict(os.environ, GIT_CEILING_DIRECTORIES=str(TMP_BASE)))


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tmp_dir(self)
        git(self.dir, "init", "-q")

    def escribir(self, rel, contenido):
        p = self.dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contenido, encoding="utf-8")

    def commit(self, archivos, msg="c"):
        for rel, contenido in archivos.items():
            if contenido is None:
                git(self.dir, "rm", "-q", rel)
            else:
                self.escribir(rel, contenido)
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", msg)

    def analizar(self):
        return dc.analizar(self.dir)

    @staticmethod
    def reglas(res):
        return [h["regla"] for h in res["hallazgos"]]

    @staticmethod
    def pases(res):
        return {p["regla"] for p in res["checks_pass"]}


# ----------------------------------------------------------------------------------------------------------------- A
class TestNoTabularConPII(Base):
    def test_json_estado_raiz_objeto_con_correo_real(self):
        estado = {"version": 3, "sesiones": {"a": {"autor": CORREO_REAL, "pasos": 4}}}
        self.commit({".claude-flow/policy/state.json": json.dumps(estado)})
        r = self.analizar()
        self.assertEqual(self.reglas(r), [NT], r)
        h = r["hallazgos"][0]
        self.assertEqual(h["severidad_sugerida"], "media")
        self.assertIn("con forma de email (no reservado ni buzón de sistema): 1", h["evidencia"])
        self.assertNotIn(CORREO_REAL, json.dumps(r))  # nunca se copia el valor
        self.assertEqual(self.pases(r), set())
        self.assertIn("pii_no_tabular", r["motivo"])

    def test_json_con_telefono(self):
        self.commit({"config/contacto.json": json.dumps({"soporte": {"fono": FONO}})})
        r = self.analizar()
        self.assertEqual(self.reglas(r), [NT])
        self.assertIn("teléfono (+56): 1", r["hallazgos"][0]["evidencia"])
        self.assertNotIn("1234", json.dumps(r["hallazgos"]))

    def test_json_raiz_lista_no_registros_con_correo(self):
        self.commit({"datos/lista.json": json.dumps(["texto", CORREO_REAL])})
        self.assertEqual(self.reglas(self.analizar()), [NT])

    def test_historial_json_borrado_con_correo(self):
        self.commit({".claude-flow/neural/patterns.json": json.dumps({"p": [{"x": CORREO_REAL}]}), "a.txt": "x"})
        self.commit({".claude-flow/neural/patterns.json": None}, "borra")
        r = self.analizar()
        self.assertEqual(self.reglas(r), [NT], r)
        self.assertIn("(historial)", r["hallazgos"][0]["evidencia"])
        self.assertIsNone(r["hallazgos"][0]["linea"])
        self.assertEqual(self.pases(r), set())

    def test_historial_varias_versiones_un_solo_hallazgo(self):
        for i in range(3):
            self.commit({"estado.json": json.dumps({"i": i, "u": CORREO_REAL})}, f"v{i}")
        self.commit({"estado.json": None}, "borra")
        self.assertEqual(self.reglas(self.analizar()), [NT])

    def test_yaml_no_tabular_sospechoso_con_correo(self):
        self.commit({"datos/ajustes.yaml": f"servicio:\n  contacto: {CORREO_REAL}\n  puerto: 80\n"})
        self.assertEqual(self.reglas(self.analizar()), [NT])

    def test_json_truncado_con_telefono(self):
        relleno = [{"k": "v" * 50}] * 6000
        cuerpo = json.dumps({"datos": {"fono": FONO}, "relleno": relleno})
        self.assertGreater(len(cuerpo), dc._MAX_DATOS)
        self.commit({"cache/estado.json": cuerpo})
        self.assertEqual(self.reglas(self.analizar()), [NT])

    def test_jsonc_ilegible_con_correo(self):
        self.commit({"ajustes.json": '{\n  // comentario\n  "dueno": "' + CORREO_REAL + '"\n}\n'})
        self.assertEqual(self.reglas(self.analizar()), [NT])

    def test_mapeo_al_catalogo(self):
        self.assertEqual(catalogo.control_por_regla("check", "datos_confidenciales.pii_no_tabular"), "DAT-PII-TEST")
        self.assertEqual(catalogo.control_por_regla("check", "datos_confidenciales.pii_tabular"), "DAT-PII-REPO")

    def test_normalizador_lo_conserva_con_severidad_media(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("ncomun_r7", RAIZ / "scripts" / "normalizar" / "comun.py")
        ncomun = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ncomun)
        cat = {c["id"]: c for c in catalogo.cargar_catalogo()}
        reg = {"herramienta": "check", "regla": "datos_confidenciales.pii_no_tabular", "archivo": "estado.json",
               "evidencia": "ruta: estado.json; conteos", "severidad_herramienta": "media"}
        h = ncomun.construir(reg, cat)
        self.assertIsNotNone(h)
        self.assertEqual((h["control"], h["severidad"]), ("DAT-PII-TEST", "media"))


# ----------------------------------------------------------------------------------------------------------------- B
class TestSeMantieneRonda6(Base):
    def test_buzon_de_sistema_y_dominios_reservados_no_cuentan(self):
        estado = {"a": "Co-Authored-By: Claude <noreply@anthropic.com>", "b": "x@example.com", "c": "y@app.test",
                  "d": "z@foo.invalid", "e": "w@srv.localhost", "f": "v@mail.example.org"}
        self.commit({"estado.json": json.dumps(estado)})
        r = self.analizar()
        self.assertEqual(self.reglas(r), [], r)
        self.assertEqual(self.pases(r), {PASE})

    def test_conteo_por_tipo(self):
        c = dc.pii_en_valores(["noreply@x.com", "a@example.com", CORREO_REAL, FONO, "12.345.678-5", "56912345678"])
        self.assertEqual(c, {"rut": 1, "rut_relleno": 0, "email": 1, "telefono": 1, "email_descartado": 2})

    def test_telefono_sin_prefijo_no_cuenta(self):
        self.assertEqual(dc.pii_en_valores(["912345678", "1700000000123", "+1 555 123 4567"])["telefono"], 0)

    def test_rut_valido_en_json_raiz_lista_sigue_critico(self):
        self.commit({"conf.json": json.dumps(["x", {"rut": "12.345.678-5"}])})
        r = self.analizar()
        self.assertEqual(self.reglas(r), [PII])
        self.assertEqual(r["hallazgos"][0]["severidad_sugerida"], "critica")

    def test_rut_en_json_raiz_objeto_es_media_y_marca_relleno(self):
        # Caso harness (ejemplo_entrada.json): RUT de digitos repetidos en un ejemplo FHIR de raiz objeto. Antes de la
        # ronda 7 se omitia entero; ahora se reporta (media), no critico, con el relleno evidente contado aparte.
        self.commit({"ejemplos/ejemplo_entrada.json": json.dumps(
            {"resourceType": "Bundle", "id": {"value": "11.111.111-1"}, "b": {"value": "12.345.678-5"}})})
        r = self.analizar()
        self.assertEqual(self.reglas(r), [NT], r)
        ev = r["hallazgos"][0]["evidencia"]
        self.assertIn("con forma de RUT válido: 2 (de ellos con dígitos repetidos, relleno evidente: 1)", ev)
        self.assertNotIn("11.111", ev)
        self.assertEqual(self.pases(r), set())

    def test_policy_y_task_de_harness_no_vuelven(self):
        policy = ("version: 1\nreglas:\n  - nombre: bloquear_pii\n    condicion: contiene_rut\n    accion: bloquear\n"
                  "  - nombre: avisar\n    condicion: largo > 10\n    accion: avisar\n")
        task = ("id: resumen\nentrada:\n  - nombre: Caso sintético\n    diagnostico_principal: J18.9\n")
        self.commit({"harness/datos/policy.yaml": policy,
                     "harness/datos/ejemplos/resumen_derivacion_fhir/task.yaml": task})
        r = self.analizar()
        self.assertNotIn(PII, self.reglas(r))
        self.assertNotIn(NT, self.reglas(r))

    def test_manifiesto_publico_no_cuenta_por_correo_del_autor(self):
        self.commit({"package.json": json.dumps({"name": "x", "author": f"Autor <{CORREO_REAL}>"})})
        r = self.analizar()
        self.assertEqual(self.reglas(r), [])
        self.assertEqual(self.pases(r), {PASE})

    def test_json_config_sin_pii_sigue_con_pase(self):
        self.commit({"config/app.json": json.dumps({"nombre": "app", "condicion": "x", "tratamiento": "y"})})
        r = self.analizar()
        self.assertEqual(self.reglas(r), [])
        self.assertEqual(self.pases(r), {PASE})


# ----------------------------------------------------------------------------------------------------------------- C
class TestFailClosed(Base):
    def test_json_truncado_solo_con_buzon_de_sistema_sigue_no_inspeccionable_con_nota(self):
        relleno = [{"k": "v" * 50}] * 6000
        cuerpo = json.dumps({"meta": {"autor": "noreply@anthropic.com"}, "patrones": relleno})
        self.commit({".claude-flow/neural/patterns.json": cuerpo, "a.txt": "x"})
        self.commit({".claude-flow/neural/patterns.json": None}, "borra")
        r = self.analizar()
        self.assertEqual(self.reglas(r), [])
        self.assertEqual(self.pases(r), set())
        self.assertIn("no inspeccionable", r["motivo"])
        self.assertIn(".claude-flow/neural/patterns.json (historial; truncado", r["motivo"])
        self.assertIn("1 valor(es) con forma de email descartado(s)", r["motivo"])
        self.assertNotIn("noreply", r["motivo"])

    def test_db_binario_sigue_no_inspeccionable(self):
        p = self.dir / ".swarm" / "agentdb-memory.db"
        p.parent.mkdir(parents=True)
        p.write_bytes(b"SQLite format 3\0" + b"\0" * 64)
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", "db")
        r = self.analizar()
        self.assertEqual(self.pases(r), set())
        self.assertIn(".swarm/agentdb-memory.db", r["motivo"])

    def test_no_tabular_no_tapa_un_critico(self):
        self.commit({"estado.json": json.dumps({"u": CORREO_REAL}),
                     "data/pacientes_export.csv": "nombre,rut,diagnostico\nJuana Pérez,12.345.678-5,J18\n"})
        r = self.analizar()
        self.assertIn(PII, self.reglas(r))
        self.assertIn(NT, self.reglas(r))
        self.assertEqual(self.pases(r), set())


if __name__ == "__main__":
    unittest.main()
