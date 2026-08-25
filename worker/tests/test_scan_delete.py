"""Tests de F9a: borrado de la evidencia cruda de un scan eliminado.

El volumen `scandata` solo está montado en el worker, así que el backend
delega el borrado del disco en esta tarea. Lo que importa probar es la
guarda de path: un id manipulado no puede sacar el `rmtree` fuera de la
raíz de scandata.
"""
import os
import tempfile

from worker.tasks import delete_scan_data_task


def _root(monkeypatch):
    root = tempfile.mkdtemp()
    monkeypatch.setenv("SCAN_DATA_ROOT", root)
    return root


def test_borra_solo_el_directorio_del_scan(monkeypatch):
    root = _root(monkeypatch)
    os.makedirs(os.path.join(root, "7", "6_cms"))
    with open(os.path.join(root, "7", "6_cms", "wpscan.json"), "w") as fh:
        fh.write("{}")
    os.makedirs(os.path.join(root, "8"))

    assert delete_scan_data_task(7) == {"scan_id": 7, "deleted": True}
    assert not os.path.exists(os.path.join(root, "7"))
    # El vecino queda intacto.
    assert os.path.isdir(os.path.join(root, "8"))


def test_directorio_inexistente_no_falla(monkeypatch):
    _root(monkeypatch)
    out = delete_scan_data_task(999)
    assert out["deleted"] is False and out["reason"] == "no existe"


def test_rechaza_ids_no_numericos(monkeypatch):
    root = _root(monkeypatch)
    out = delete_scan_data_task("../etc")
    assert out["deleted"] is False and out["reason"] == "id invalido"
    assert os.path.isdir(root)


def test_rechaza_id_negativo_y_none(monkeypatch):
    root = _root(monkeypatch)
    assert delete_scan_data_task(-1)["deleted"] is False
    assert delete_scan_data_task(None)["deleted"] is False
    assert os.path.isdir(root)


def test_no_borra_si_el_path_no_es_hijo_directo(monkeypatch):
    """Un symlink dentro de la raíz que apunte afuera no debe borrarse."""
    root = _root(monkeypatch)
    afuera = tempfile.mkdtemp()
    os.makedirs(os.path.join(afuera, "importante"))
    os.symlink(afuera, os.path.join(root, "5"))

    out = delete_scan_data_task(5)
    assert out["deleted"] is False
    assert os.path.isdir(os.path.join(afuera, "importante"))
