"""Carpeta base de los temporales de la batería de tests (sin efectos al importar).

Los temporales van FUERA del árbol del proyecto: dentro de tests/ dejaban restos con canarios (forma de secreto) cuando
una corrida se cortaba, y ensuciaban cualquier auditoría del propio repo (gitleaks, perfil técnico, SAST).
Por defecto: <tempdir del sistema>/auditor-integral-tests (respeta TMPDIR). AUDITOR_TESTS_TMP fija otra carpeta.
"""
import os
import shutil
import tempfile
from pathlib import Path

TMP_BASE = Path(os.environ.get("AUDITOR_TESTS_TMP") or Path(tempfile.gettempdir()) / "auditor-integral-tests").resolve()


def tmp_dir(caso=None):
    """Carpeta temporal nueva bajo TMP_BASE. Con `caso` (TestCase o su clase) registra el borrado como cleanup, que
    unittest ejecuta aunque setUp/setUpClass fallen después de crearla (tearDown/tearDownClass no se ejecutan)."""
    TMP_BASE.mkdir(parents=True, exist_ok=True)
    ruta = Path(tempfile.mkdtemp(dir=TMP_BASE))
    if isinstance(caso, type):
        caso.addClassCleanup(shutil.rmtree, ruta, True)
    elif caso is not None:
        caso.addCleanup(shutil.rmtree, ruta, True)
    return ruta
