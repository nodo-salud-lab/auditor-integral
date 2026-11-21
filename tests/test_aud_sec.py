"""AUD-SEC (Anexo C del brazo C, kine us): generic-api-key de gitleaks en un bundle minificado y sin
prefijo de proveedor reconocido → confianza baja, sin secreto_vivo ni bloqueo hasta el triage.
Los secretos con prefijo de proveedor (sk_live_, ghp_, AKIA, JWT service_role, xox…) siguen bloqueando.
Todos los valores son FALSOS (fabricados para la prueba)."""
import base64
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import gates  # noqa: E402
import utiles  # noqa: E402
from normalizar import comun  # noqa: E402
from normalizar import gitleaks as n_gitleaks  # noqa: E402


def _jwt(payload):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64(payload)}.firmaFalsaDePrueba0123456789"


def _leer(registros, archivo_por_defecto="dist/assets/leerDicom-Cn.js"):
    tmp = Path(ap.tmp_dir())
    try:
        datos = []
        for i, (regla, secreto, archivo) in enumerate(registros, 1):
            datos.append({"RuleID": regla, "File": archivo or archivo_por_defecto, "StartLine": i,
                          "Secret": secreto, "Match": f"x={secreto}", "Description": "d"})
        ruta = tmp / "gitleaks.json"
        ruta.write_text(json.dumps(datos), encoding="utf-8")
        return n_gitleaks.leer(ruta, {"proyecto": None, "metas": {}})
    finally:
        ap.limpiar(tmp)


class TestConfianzaGitleaks(unittest.TestCase):
    def test_generica_sin_prefijo_en_bundle_es_baja(self):
        reg = _leer([("generic-api-key", "a7Fq9ZkP2m" "Lw8XcV3nBt", None)])
        self.assertEqual(reg[0]["confianza"], "baja")
        self.assertIn("triage", reg[0]["mensaje"])

    def test_generica_sin_prefijo_en_min_js_es_baja(self):
        reg = _leer([("generic-api-key", "a7Fq9ZkP2m" "Lw8XcV3nBt", "public/vendor/pako.min.js")])
        self.assertEqual(reg[0]["confianza"], "baja")

    def test_generica_fuera_de_bundle_sigue_media(self):
        reg = _leer([("generic-api-key", "a7Fq9ZkP2m" "Lw8XcV3nBt", "server/almacenamiento.js")])
        self.assertEqual(reg[0]["confianza"], "media")

    def test_generica_con_prefijo_de_proveedor_en_bundle_no_baja(self):
        falsos = ["sk_live_FALSOab" "cdefghijklmnop12", "ghp_FALSOabcdefghij" "klmnopqrstuvwxyz0123",
                  "AKIA" "FALSOFALSOFALSO1", "xoxb-" "0000000000-FALSOfalsofalso", "sk-ant-" "FALSOabcdefghijk",
                  _jwt({"iss": "supabase", "role": "service_role"})]
        reg = _leer([("generic-api-key", s, None) for s in falsos])
        self.assertEqual([r["confianza"] for r in reg], ["media"] * len(falsos))

    def test_jwt_anon_en_bundle_es_baja(self):
        reg = _leer([("generic-api-key", _jwt({"iss": "supabase", "role": "anon"}), None)])
        self.assertEqual(reg[0]["confianza"], "baja")

    def test_regla_de_proveedor_no_cambia(self):
        reg = _leer([("stripe-access-token", "sk_live_FALSOab" "cdefghijklmnop12", None)])
        self.assertEqual(reg[0]["confianza"], "alta")

    def test_hallazgo_construido_conserva_confianza_baja(self):
        reg = _leer([("generic-api-key", "a7Fq9ZkP2m" "Lw8XcV3nBt", None)])
        h = comun.construir(reg[0], utiles.indice_controles({"banderas": {}}), ["a7Fq9ZkP2mLw8XcV3nBt"])
        self.assertEqual(h["control"], "SEG-SECRETO-BUNDLE")
        self.assertEqual(h["confianza"], "baja")
        self.assertNotIn("a7Fq9ZkP2mLw8XcV3nBt", json.dumps(h))


def _indice():
    return {"SEG-SECRETO-BUNDLE": {"id": "SEG-SECRETO-BUNDLE", "dominio": "SEG", "gate": "N1",
                                   "severidad_base": "critica", "bloquea_global": True},
            "SEG-OTRO": {"id": "SEG-OTRO", "dominio": "SEG", "gate": "N1", "severidad_base": "media",
                         "bloquea_global": False}}


def _calc(confianzas, triage=None):
    ids = [f"H-{i:012d}" for i in range(len(confianzas))]
    hs = [{"id": i, "control": "SEG-SECRETO-BUNDLE", "severidad": "critica", "confianza": c,
           "estado_hallazgo": "abierto", "triage": triage} for i, c in zip(ids, confianzas)]
    est = [{"control": "SEG-SECRETO-BUNDLE", "estado": "fail", "hallazgos": ids},
           {"control": "SEG-OTRO", "estado": "pass", "hallazgos": []}]
    return gates.calcular(est, _indice(), hs, {}, set())


class TestGatesTriagePendiente(unittest.TestCase):
    def test_solo_confianza_baja_no_bloquea(self):
        g = _calc(["baja", "baja", "baja"])
        self.assertEqual(g["global"]["bloqueos"], [])
        # El control sigue en fail: el dominio no pasa N1 hasta el triage.
        self.assertEqual(g["dominios"]["SEG"]["nivel_demostrado"], "N0")
        self.assertEqual(g["dominios"]["SEG"]["niveles"]["N1"]["fallidos"], ["SEG-SECRETO-BUNDLE"])

    def test_una_media_mantiene_secreto_vivo(self):
        g = _calc(["baja", "media"])
        tipos = {b["tipo"] for b in g["global"]["bloqueos"]}
        self.assertIn("secreto_vivo", tipos)
        self.assertEqual(g["global"]["nivel_demostrado"], "N0")

    def test_triage_verdadero_vuelve_a_bloquear(self):
        g = _calc(["baja"], triage={"veredicto": "verdadero", "razon": "r", "modelo": "m"})
        self.assertIn("secreto_vivo", {b["tipo"] for b in g["global"]["bloqueos"]})

    def test_sin_detalle_de_hallazgos_sigue_bloqueando(self):
        est = [{"control": "SEG-SECRETO-BUNDLE", "estado": "fail", "hallazgos": []}]
        g = gates.calcular(est, _indice(), [], {}, set())
        self.assertIn("secreto_vivo", {b["tipo"] for b in g["global"]["bloqueos"]})


if __name__ == "__main__":
    unittest.main()
