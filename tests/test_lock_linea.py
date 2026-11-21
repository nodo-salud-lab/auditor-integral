"""LOCK-LINEA (Anexo C del brazo C): la línea del lockfile que cita osv es la de la clave
"node_modules/<paquete>" (package-lock v2/v3), con la versión afectada; no una mención del paquete
como dependencia de otro ni una copia anidada de otra versión."""
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
from normalizar import osv as n_osv  # noqa: E402

LOCK = {
    "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
    "packages": {
        "": {"name": "app", "dependencies": {"micromatch": "^4.0.8"}},
        "node_modules/micromatch": {"version": "4.0.8", "dependencies": {"picomatch": "^2.3.1"}},
        "node_modules/micromatch/node_modules/picomatch": {"version": "2.3.1", "dev": True},
        "node_modules/otro": {"version": "1.0.0", "dependencies": {"picomatch": "^4.0.0"}},
        "node_modules/picomatch": {"version": "4.0.7", "dev": True},
    },
}


class TestLineaLockfile(unittest.TestCase):
    def setUp(self):
        self.dir = Path(ap.tmp_dir(self))
        self.addCleanup(ap.limpiar, self.dir)
        self.texto = json.dumps(LOCK, indent=2)
        (self.dir / "package-lock.json").write_text(self.texto, encoding="utf-8")
        self.lineas = self.texto.splitlines()

    def _num(self, clave):
        return next(i for i, l in enumerate(self.lineas, 1) if l.strip().startswith(f'"{clave}": {{'))

    def test_clave_de_nivel_superior_con_version(self):
        n = n_osv._linea_en_lockfile(self.dir, "package-lock.json", "picomatch", "4.0.7")
        self.assertEqual(n, self._num("node_modules/picomatch"))

    def test_version_anidada(self):
        n = n_osv._linea_en_lockfile(self.dir, "package-lock.json", "picomatch", "2.3.1")
        self.assertEqual(n, self._num("node_modules/micromatch/node_modules/picomatch"))

    def test_sin_version_prefiere_nivel_superior(self):
        n = n_osv._linea_en_lockfile(self.dir, "package-lock.json", "picomatch")
        self.assertEqual(n, self._num("node_modules/picomatch"))

    def test_no_confunde_prefijo_de_nombre(self):
        n = n_osv._linea_en_lockfile(self.dir, "package-lock.json", "micromatch", "4.0.8")
        self.assertEqual(n, self._num("node_modules/micromatch"))

    def test_leer_usa_la_linea_correcta(self):
        osv = {"results": [{"source": {"path": str(self.dir / "package-lock.json"), "type": "lockfile"},
                            "packages": [{"package": {"name": "picomatch", "version": "4.0.7", "ecosystem": "npm"},
                                          "groups": [{"ids": ["GHSA-fc5q-39xc-vjpf"], "aliases": [],
                                                      "max_severity": "7.5"}],
                                          "vulnerabilities": [{"id": "GHSA-fc5q-39xc-vjpf"}]}]}]}
        ruta = self.dir / "osv.json"
        ruta.write_text(json.dumps(osv), encoding="utf-8")
        reg = n_osv.leer(ruta, {"proyecto": self.dir, "metas": {}})
        self.assertEqual(reg[0]["linea"], self._num("node_modules/picomatch"))

    def test_otros_lockfiles_sin_cambio(self):
        (self.dir / "requirements.txt").write_text("flask==2.0.0\nrequests==2.0.0\n", encoding="utf-8")
        self.assertEqual(n_osv._linea_en_lockfile(self.dir, "requirements.txt", "requests", "2.0.0"), 2)


if __name__ == "__main__":
    unittest.main()
