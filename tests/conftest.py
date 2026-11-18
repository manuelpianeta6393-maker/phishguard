import pytest

from app.reputacion import VARIABLE_CLAVE


@pytest.fixture(autouse=True)
def sin_clave_real(monkeypatch):
    monkeypatch.delenv(VARIABLE_CLAVE, raising=False)
