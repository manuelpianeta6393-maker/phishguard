import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def cliente():
    return TestClient(app)


def test_pagina_principal_responde(cliente):
    r = cliente.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "PhishGuard" in r.text
    assert "Desarrollado por el Ing. Manuel Pianeta" in r.text


def test_formulario_muestra_resultado(cliente):
    r = cliente.post("/analizar", data={"url": "http://paypa1-seguro-login.tk/verify/account"})
    assert r.status_code == 200
    assert "Crítico" in r.text
    assert "Suplantación de marca" in r.text


def test_formulario_con_url_invalida_muestra_error(cliente):
    r = cliente.post("/analizar", data={"url": "ftp://archivos.com"})
    assert r.status_code == 400
    assert "Solo se analizan URLs con protocolo http o https." in r.text
    assert 'value="ftp://archivos.com"' in r.text


def test_formulario_vacio(cliente):
    r = cliente.post("/analizar", data={})
    assert r.status_code == 400
    assert "Debes ingresar una URL." in r.text


def test_lote_muestra_resumen(cliente):
    r = cliente.post("/lote", data={"urls": "https://github.com\nhttp://192.168.0.1/login\nnoesurl"})
    assert r.status_code == 200
    assert "URLs analizadas" in r.text
    assert "Entradas no procesadas" in r.text


def test_api_devuelve_json(cliente):
    r = cliente.post("/api/analizar", json={"url": "https://www.google.com"})
    assert r.status_code == 200
    datos = r.json()
    assert datos["puntaje"] == 0
    assert datos["nivel"] == "Bajo"
    assert datos["dominio_registrado"] == "google.com"


def test_api_con_url_invalida_devuelve_422(cliente):
    r = cliente.post("/api/analizar", json={"url": ""})
    assert r.status_code == 422
    assert r.json() == {"error": "Debes ingresar una URL."}


def test_api_sin_campo_url(cliente):
    r = cliente.post("/api/analizar", json={})
    assert r.status_code == 422


def test_criterios_y_salud(cliente):
    assert cliente.get("/criterios").status_code == 200
    assert cliente.get("/salud").json() == {"estado": "ok"}
    assert cliente.get("/static/styles.css").status_code == 200
