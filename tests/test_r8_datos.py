"""Ronda 8 — grupo «datos» (DECISIONES.md #12, adenda 3): pases falsos de DAT-PII-REPO hallados por la crítica
adversarial (critica7: minirepos d2, d3, d4, d5, d9, d13, d16 y full). En todos, datos_confidenciales emitía el pase
no_trackeado sin haber visto la PII.

  1  Listas de registros JSON/JSONL con PII ANIDADA (meta.correo, meta.rut, contactos: [...], usuario.{correo, rut},
     p.rut): la rama tabular solo miraba los str/int de primer nivel de las columnas comunes. Ahora se recorren todos
     los escalares (anidados y claves) y se cuenta por valor. Severidad de la rama tabular: pii_tabular (crítica con RUT,
     alta sin él), pii_en_test en tests/fixtures.
  2  .json5/.jsonc (y .geojson) versionados: _clase() los ignoraba. Ahora se leen (conversión relajada sin librerías);
     si no se pueden leer y no hay PII por texto quedan no inspeccionables (sin pase). Otras extensiones: .duckdb… son
     binarias (no inspeccionables) y .vcf/.ldif/.hl7/.eml/.mbox/.ics se inspeccionan siempre como texto.
  3  Teléfonos +56 por valor en la rama tabular (CSV y listas JSON/YAML), y «contacto» (y sinónimos) como columna de
     contacto.
  4  Correos y RUT usados como CLAVES de un JSON de raíz objeto (pii_no_tabular, media).
  +  Fail-closed: un CSV/JSONL truncado (> 256 KiB) o un JSON con anidamiento excesivo sin PII detectada no queda limpio.

Los datos de prueba se GENERAN al azar (RUT con DV calculado, correos en dominios inventados no reservados, móviles
+56 aleatorios): no son de ninguna persona. Las aserciones nunca imprimen valores.
"""
import json
import os
import random
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import datos_confidenciales as dc  # noqa: E402
from tmp_tests import TMP_BASE, tmp_dir  # noqa: E402

GIT_ID = ["-c", "user.name=prueba", "-c", "user.email=prueba@example.invalid", "-c", "commit.gpgsign=false"]
PII = "check:datos_confidenciales.pii_tabular"
NT = "check:datos_confidenciales.pii_no_tabular"
TEST = "check:datos_confidenciales.pii_en_test"
PASE = "check:datos_confidenciales.no_trackeado"
AZAR = random.SystemRandom()


def dv_rut(cuerpo):
    suma, factor = 0, 2
    for d in reversed(str(cuerpo)):
        suma += int(d) * factor
        factor = 2 if factor == 7 else factor + 1
    dv = 11 - suma % 11
    return "0" if dv == 11 else "K" if dv == 10 else str(dv)


def rut(valido=True, relleno=False):
    """RUT sintético con DV calculado (o deliberadamente erróneo). relleno: un solo dígito repetido (11.111.111-1)."""
    if relleno:
        cuerpo = "11111111"
    else:
        while True:
            cuerpo = str(AZAR.randint(5_000_000, 25_999_999))
            if len(set(cuerpo)) > 1:
                break
    dv = dv_rut(cuerpo)
    if not valido:
        dv = "0" if dv != "0" else "1"
    return f"{cuerpo[:-6]}.{cuerpo[-6:-3]}.{cuerpo[-3:]}-{dv}"


def correo():
    """Correo inventado en un dominio NO reservado (no es de nadie)."""
    letras = "abcdefghijklmnopqrstuvwxyz"
    local = "".join(AZAR.choice(letras) for _ in range(8))
    dominio = "".join(AZAR.choice(letras) for _ in range(10))
    return f"{local}@{dominio}-sintetico.cl"


def fono():
    return "+56 9 " + f"{AZAR.randint(1000, 9999)} {AZAR.randint(1000, 9999)}"


def git(proy, *args):
    return subprocess.run(["git", *GIT_ID, "-C", str(proy), *args], capture_output=True, text=True, check=True,
                          env=dict(os.environ, GIT_CEILING_DIRECTORIES=str(TMP_BASE)))


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tmp_dir(self)
        git(self.dir, "init", "-q")
        self.secretos = []  # valores sintéticos que nunca deben aparecer en la salida

    def commit(self, archivos):
        for rel, contenido in archivos.items():
            p = self.dir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(contenido, encoding="utf-8")
        (self.dir / "src").mkdir(exist_ok=True)
        (self.dir / "src" / "app.js").write_text("console.log(1)\n", encoding="utf-8")
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", "c")

    def v(self, valor):
        self.secretos.append(valor)
        return valor

    def analizar(self):
        r = dc.analizar(self.dir)
        volcado = json.dumps(r, ensure_ascii=False)
        for s in self.secretos:
            self.assertNotIn(s, volcado, "la salida no debe copiar valores")
        return r

    @staticmethod
    def reglas(res):
        return sorted(h["regla"] for h in res["hallazgos"])

    @staticmethod
    def pases(res):
        return {p["regla"] for p in res["checks_pass"]}

    def assert_hallazgo(self, res, regla, severidad, archivo):
        hs = [h for h in res["hallazgos"] if h["regla"] == regla and h["archivo"] == archivo]
        self.assertEqual(len(hs), 1, res["hallazgos"])
        self.assertEqual(hs[0]["severidad_sugerida"], severidad)
        self.assertEqual(self.pases(res), set())
        return hs[0]

    def assert_pase(self, res):
        self.assertEqual(res["hallazgos"], [], res["hallazgos"])
        self.assertEqual(self.pases(res), {PASE}, res.get("motivo"))

    def assert_sin_pase_no_insp(self, res, archivo):
        self.assertEqual(self.pases(res), set())
        self.assertIn(archivo, res["motivo"])
        self.assertIn("no inspeccionable", res["motivo"])


# ---------------------------------------------------------------------------------------------- 1 PII anidada
class TestPIIAnidada(Base):
    def test_meta_correo_y_rut_anidados_es_critico(self):  # critica7/d2 y full
        regs = [{"id": i, "meta": {"correo": self.v(correo()), "rut": self.v(rut())}} for i in range(2)]
        self.commit({"data/lista.json": json.dumps(regs)})
        h = self.assert_hallazgo(self.analizar(), PII, "critica", "data/lista.json")
        self.assertIn("RUT válido: 2", h["evidencia"])
        self.assertIn("email: 2", h["evidencia"])

    def test_contactos_lista_con_correo_y_telefono(self):  # d3
        regs = [{"id": 1, "contactos": [self.v(correo()), self.v(fono())]}, {"id": 2, "contactos": [self.v(correo())]}]
        self.commit({"data/lista.json": json.dumps(regs)})
        h = self.assert_hallazgo(self.analizar(), PII, "alta", "data/lista.json")
        self.assertIn("teléfono (+56): 1", h["evidencia"])

    def test_jsonl_usuario_anidado(self):  # d4
        lineas = [json.dumps({"id": i, "usuario": {"correo": self.v(correo()), "rut": self.v(rut())}})
                  for i in range(2)]
        self.commit({"data/eventos.jsonl": "\n".join(lineas) + "\n"})
        self.assert_hallazgo(self.analizar(), PII, "critica", "data/eventos.jsonl")

    def test_ndjson_anidado(self):
        lineas = [json.dumps({"id": i, "x": {"y": [self.v(correo())]}}) for i in range(2)]
        self.commit({"data/eventos.ndjson": "\n".join(lineas) + "\n"})
        self.assert_hallazgo(self.analizar(), PII, "alta", "data/eventos.ndjson")

    def test_rut_anidado_en_p(self):  # d16
        regs = [{"id": i, "p": {"rut": self.v(rut())}} for i in range(2)]
        self.commit({"data/lista.json": json.dumps(regs)})
        self.assert_hallazgo(self.analizar(), PII, "critica", "data/lista.json")

    def test_solo_relleno_anidado_es_media_sin_pase(self):
        # Ronda 8 (visto en harness real, gold.jsonl): RUT 11.111.111-1 y móviles de dígitos repetidos, sin columnas
        # personales ni correos reales → pii_no_tabular (media), visible, sin pase ni bloqueo.
        lineas = [json.dumps({"id": i, "ref": {"rut": rut(relleno=True), "fono": "+56 9 1111 1111"}})
                  for i in range(3)]
        self.commit({"data/gold.jsonl": "\n".join(lineas) + "\n"})
        h = self.assert_hallazgo(self.analizar(), NT, "media", "data/gold.jsonl")
        self.assertIn("solo valores de relleno evidente", h["evidencia"])
        self.assertIn("RUT válido: 3 (relleno: 3)", h["evidencia"])
        self.assertIn("teléfono (+56): 3 (relleno: 3)", h["evidencia"])
        self.assertNotIn("...", h["evidencia"])

    def test_relleno_mas_un_rut_real_sigue_critico(self):
        regs = [{"id": 1, "p": {"rut": rut(relleno=True)}}, {"id": 2, "p": {"rut": self.v(rut())}}]
        self.commit({"data/lista.json": json.dumps(regs)})
        h = self.assert_hallazgo(self.analizar(), PII, "critica", "data/lista.json")
        self.assertIn("relleno evidente: 1", h["evidencia"])

    def test_relleno_con_telefono_real_sigue_en_pii_tabular(self):
        regs = [{"id": 1, "p": {"rut": rut(relleno=True)}}, {"id": 2, "p": {"fono": self.v(fono())}}]
        self.commit({"data/lista.json": json.dumps(regs)})
        self.assert_hallazgo(self.analizar(), PII, "critica", "data/lista.json")

    def test_columna_rut_con_relleno_sigue_critica(self):
        self.commit({"data/t.csv": "id,rut\n1,11.111.111-1\n2,11.111.111-1\n"})
        self.assert_hallazgo(self.analizar(), PII, "critica", "data/t.csv")

    def test_registro_mas_alla_de_la_fila_200(self):
        regs = [{"id": i, "obs": "x"} for i in range(260)]
        regs[250]["meta"] = {"c": self.v(correo())}
        self.commit({"data/lista.json": json.dumps(regs)})
        self.assert_hallazgo(self.analizar(), PII, "alta", "data/lista.json")

    def test_csv_fila_300_con_rut(self):
        filas = ["id,obs"] + [f"{i},x" for i in range(300)] + [f"301,{self.v(rut())}"]
        self.commit({"data/tabla.csv": "\n".join(filas) + "\n"})
        self.assert_hallazgo(self.analizar(), PII, "critica", "data/tabla.csv")

    def test_anidado_en_tests_es_pii_en_test(self):
        regs = [{"id": i, "meta": {"rut": self.v(rut())}} for i in range(2)]
        self.commit({"tests/fixtures/lista.json": json.dumps(regs)})
        self.assert_hallazgo(self.analizar(), TEST, "media", "tests/fixtures/lista.json")

    # negativos
    def test_anidado_con_correos_reservados_y_buzon_de_sistema_da_pase(self):
        regs = [{"id": 1, "meta": {"correo": "ana@example.com", "otro": ["x@demo.test", "y@algo.invalid"]}},
                {"id": 2, "meta": {"correo": "noreply@empresa-ficticia.cl", "host": "a@b.localhost"}}]
        self.commit({"data/lista.json": json.dumps(regs)})
        self.assert_pase(self.analizar())

    def test_anidado_con_rut_de_dv_invalido_da_pase(self):
        regs = [{"id": i, "meta": {"rut": rut(valido=False)}} for i in range(2)]
        self.commit({"data/lista.json": json.dumps(regs)})
        self.assert_pase(self.analizar())

    def test_lista_sin_pii_anidada_da_pase(self):
        regs = [{"id": i, "meta": {"tags": ["a", "b"], "n": i}} for i in range(3)]
        self.commit({"data/lista.json": json.dumps(regs)})
        self.assert_pase(self.analizar())

    def test_anidamiento_excesivo_sin_pii_no_da_pase(self):
        profundo = {"id": 1, "x": None}
        nodo = profundo
        for _ in range(dc._MAX_PROFUNDIDAD + 20):
            nodo["x"] = {"x": None}
            nodo = nodo["x"]
        self.commit({"data/lista.json": json.dumps([profundo, {"id": 2, "x": None}])})
        self.assert_sin_pase_no_insp(self.analizar(), "data/lista.json")

    def test_anidamiento_que_json_no_puede_leer_no_da_pase(self):
        self.commit({"data/raro.json": "[" * 5000 + "]" * 5000})
        self.assert_sin_pase_no_insp(self.analizar(), "data/raro.json")


# ---------------------------------------------------------------------------------------------- 2 json5/jsonc y otras
class TestJson5YExtensiones(Base):
    def test_json5_con_claves_sin_comillas_comentarios_y_comas_finales(self):  # d5
        texto = ("{ usuarios: { admin: { correo: '" + self.v(correo()) + "', rut: \"" + self.v(rut())
                 + "\", }, }, // comentario\n /* bloque */ }\n")
        self.commit({"config/estado.json5": texto})
        h = self.assert_hallazgo(self.analizar(), NT, "media", "config/estado.json5")
        self.assertIn("RUT válido: 1", h["evidencia"])

    def test_jsonc_con_comentario(self):  # d5
        self.commit({"config/memoria.jsonc": '{ "correo": "' + self.v(correo()) + '" // c\n}\n'})
        self.assert_hallazgo(self.analizar(), NT, "media", "config/memoria.jsonc")

    def test_jsonc_lista_de_registros_es_tabular(self):
        texto = "// exportación\n[\n" + ",\n".join(
            '{"id": %d, "p": {"rut": "%s"}}' % (i, self.v(rut())) for i in range(2)) + ",\n]\n"
        self.commit({"data/lista.jsonc": texto})
        self.assert_hallazgo(self.analizar(), PII, "critica", "data/lista.jsonc")

    def test_geojson_con_correo_en_properties(self):
        fc = {"type": "FeatureCollection", "features": [
            {"type": "Feature", "properties": {"correo": self.v(correo())}, "geometry": None},
            {"type": "Feature", "properties": {"correo": self.v(correo())}, "geometry": None}]}
        self.commit({"mapas/puntos.geojson": json.dumps(fc)})
        self.assert_hallazgo(self.analizar(), PII, "alta", "mapas/puntos.geojson")

    def test_vcf_sin_pii_detectable_no_da_pase(self):
        self.commit({"contactos.vcf": "BEGIN:VCARD\nVERSION:3.0\nFN:Nombre Inventado\nEND:VCARD\n"})
        self.assert_sin_pase_no_insp(self.analizar(), "contactos.vcf")

    def test_vcf_con_correo_real(self):
        self.commit({"contactos.vcf": "BEGIN:VCARD\nEMAIL:" + self.v(correo()) + "\nEND:VCARD\n"})
        self.assert_hallazgo(self.analizar(), PII, "alta", "contactos.vcf")

    def test_binarios_de_datos_no_dan_pase(self):
        for nombre in ("base.duckdb", "tabla.parquet", "hoja.xlsx", "local.sqlite"):
            with self.subTest(nombre=nombre):
                self.setUp()
                p = self.dir / "data" / nombre
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"\0\1\2binario")
                self.commit({})
                self.assert_sin_pase_no_insp(self.analizar(), f"data/{nombre}")

    # negativos
    def test_jsonc_de_configuracion_limpio_da_pase(self):
        self.commit({".vscode/ajustes.jsonc": '{\n  // tabs\n  "editor.tabSize": 2,\n  "a": [1, 2,],\n}\n'})
        self.assert_pase(self.analizar())

    def test_json5_con_correo_reservado_da_pase(self):
        self.commit({"config/estado.json5": "{ dueno: 'ana@example.com', // c\n}\n"})
        self.assert_pase(self.analizar())

    def test_json5_ilegible_sin_pii_no_da_pase(self):
        self.commit({"config/raro.json5": "{ a: 0x1F, b: +1, }\n"})
        self.assert_sin_pase_no_insp(self.analizar(), "config/raro.json5")

    def test_json_relajado_no_toca_cadenas(self):
        texto = '{"url": "http://x//y", "c": "a, }", \'s\': \'d"q\', k: 1,}'
        self.assertEqual(json.loads(dc._json_relajado(texto)),
                         {"url": "http://x//y", "c": "a, }", "s": 'd"q', "k": 1})


# ---------------------------------------------------------------------------------------------- 3 teléfonos +56
class TestTelefonosTabular(Base):
    def test_csv_columna_contacto_con_telefonos(self):  # d9
        self.commit({"data/tabla.csv": f"id,contacto,obs\n1,{self.v(fono())},x\n2,{self.v(fono())},y\n"})
        h = self.assert_hallazgo(self.analizar(), PII, "alta", "data/tabla.csv")
        self.assertIn("teléfono (+56): 2", h["evidencia"])

    def test_lista_json_columna_contacto_con_telefonos(self):  # d9
        regs = [{"id": i, "contacto": self.v(fono()), "obs": "x"} for i in range(2)]
        self.commit({"data/lista.json": json.dumps(regs)})
        self.assert_hallazgo(self.analizar(), PII, "alta", "data/lista.json")

    def test_csv_columna_neutra_con_telefono_por_valor(self):
        self.commit({"data/t.tsv": f"id\tobs\n1\t{self.v(fono())}\n2\tz\n"})
        self.assert_hallazgo(self.analizar(), PII, "alta", "data/t.tsv")

    def test_yaml_lista_de_registros_con_telefono(self):
        self.commit({"datos/seed.yaml": f"- id: 1\n  obs: '{self.v(fono())}'\n- id: 2\n  obs: z\n"})
        self.assert_hallazgo(self.analizar(), PII, "alta", "datos/seed.yaml")

    def test_csv_telefono_en_tests_es_pii_en_test(self):
        self.commit({"tests/fixtures/t.csv": f"id,contacto\n1,{self.v(fono())}\n"})
        self.assert_hallazgo(self.analizar(), TEST, "media", "tests/fixtures/t.csv")

    def test_columnas_sinonimas_de_contacto(self):
        for col in ("contacto", "celular", "movil", "fono", "whatsapp"):
            self.assertTrue(dc._tokens_columna(col) & dc.COL_CONTACTO, col)

    # negativos
    def test_digitos_sin_prefijo_no_son_telefono(self):
        self.commit({"data/t.csv": "id,codigo\n1,56912345678\n2,912345678\n"})
        self.assert_pase(self.analizar())

    def test_columna_contacto_con_solo_correos_reservados_da_pase(self):
        self.commit({"data/t.csv": "id,contacto\n1,ana@example.com\n2,luis@demo.test\n"})
        self.assert_pase(self.analizar())


# ---------------------------------------------------------------------------------------------- 4 claves
class TestClavesJSON(Base):
    def test_correos_como_claves(self):  # d13
        estado = {self.v(correo()): {"visto": True}, self.v(correo()): {"visto": False}}
        self.commit({"config/estado.json": json.dumps(estado)})
        h = self.assert_hallazgo(self.analizar(), NT, "media", "config/estado.json")
        self.assertIn("email (no reservado ni buzón de sistema): 2", h["evidencia"])

    def test_rut_como_clave(self):
        self.commit({"config/estado.json": json.dumps({self.v(rut()): {"visto": True}})})
        h = self.assert_hallazgo(self.analizar(), NT, "media", "config/estado.json")
        self.assertIn("RUT válido: 1", h["evidencia"])

    def test_correo_como_clave_anidada(self):
        self.commit({"config/estado.json": json.dumps({"vistos": {"a": {self.v(correo()): 1}}})})
        self.assert_hallazgo(self.analizar(), NT, "media", "config/estado.json")

    # negativos
    def test_claves_con_correos_reservados_dan_pase(self):
        self.commit({"config/estado.json": json.dumps({"ana@example.com": 1, "noreply@x-ficticia.cl": 2})})
        self.assert_pase(self.analizar())

    def test_manifiesto_publico_no_cuenta_por_correo_del_autor(self):
        pkg = {"name": "x", "author": {"email": self.v(correo())}, "maintainers": {self.v(correo()): "x"}}
        self.commit({"package.json": json.dumps(pkg)})
        self.assert_pase(self.analizar())


# ---------------------------------------------------------------------------------------------- truncado
class TestTruncado(Base):
    def test_csv_mayor_que_el_limite_sin_pii_no_da_pase(self):
        filas = ["id,obs"] + [f"{i},{'x' * 60}" for i in range(5000)]
        cuerpo = "\n".join(filas) + "\n"
        self.assertGreater(len(cuerpo), dc._MAX_DATOS)
        self.commit({"data/grande.csv": cuerpo})
        r = self.analizar()
        self.assert_sin_pase_no_insp(r, "data/grande.csv")
        self.assertIn("truncado", r["motivo"])

    def test_jsonl_mayor_que_el_limite_sin_pii_no_da_pase(self):
        cuerpo = "\n".join(json.dumps({"id": i, "obs": "x" * 60}) for i in range(5000)) + "\n"
        self.assertGreater(len(cuerpo), dc._MAX_DATOS)
        self.commit({"data/grande.jsonl": cuerpo})
        self.assert_sin_pase_no_insp(self.analizar(), "data/grande.jsonl")

    def test_csv_con_campo_enorme_sin_pii_no_da_pase(self):
        # Integración ronda 8: un campo > 128 KiB hace fallar el módulo csv; antes el archivo se revisaba solo como
        # texto y, sin PII por valor, quedaba limpio (pase).
        cuerpo = 'id,obs\n1,"' + "x" * 140_000 + '"\n'
        self.assertLess(len(cuerpo), dc._MAX_DATOS)
        self.commit({"data/campo.csv": cuerpo})
        r = self.analizar()
        self.assert_sin_pase_no_insp(r, "data/campo.csv")
        self.assertIn("csv", r["motivo"])

    def test_csv_con_campo_enorme_conserva_columnas_personales(self):
        cuerpo = 'nombre,diagnostico\nA,"' + "x" * 140_000 + '"\n'
        self.commit({"data/campo.csv": cuerpo})
        self.assert_hallazgo(self.analizar(), PII, "critica", "data/campo.csv")

    def test_csv_pequeno_sin_pii_da_pase(self):
        self.commit({"data/chico.csv": "id,obs\n1,x\n2,y\n"})
        self.assert_pase(self.analizar())


if __name__ == "__main__":
    unittest.main()
