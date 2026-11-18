import httpx
import pytest
from fastapi.testclient import TestClient

from app import reputacion
from app.analizador import analizar_url
from app.main import app
from app.reputacion import VARIABLE_CLAVE, aplicar_reputacion, consultar_safe_browsing, interpretar_respuesta

URL_REPORTADA = "http://malware.testing.google.test/testing/malware/"


class RespuestaFalsa:
    def __init__(self, datos, estado=200):
        self.datos = datos
        self.status_code = estado

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=None)

    def json(self):
        return self.datos


def simular_google(monkeypatch, datos=None, estado=200, excepcion=None):
    llamadas = []

    def post_falso(url, params=None, json=None, timeout=None):
        llamadas.append({"url": url, "params": params, "json": json})
        if excepcion:
            raise excepcion
        return RespuestaFalsa(datos if datos is not None else {}, estado)

    monkeypatch.setattr(reputacion.httpx, "post", post_falso)
    return llamadas


def coincidencia(url, tipo="SOCIAL_ENGINEERING"):
    return {"threatType": tipo, "platformType": "ANY_PLATFORM", "threat": {"url": url}}


def test_sin_clave_no_consulta_google(monkeypatch):
    llamadas = simular_google(monkeypatch)
    r = consultar_safe_browsing(["https://www.google.com"])
    assert r.disponible is False
    assert llamadas == []


def test_solicitud_enviada_a_google(monkeypatch):
    llamadas = simular_google(monkeypatch)
    r = consultar_safe_browsing(["https://a.com", "https://b.com"], clave="CLAVE")
    assert r.disponible is True and r.amenazas == {}
    assert llamadas[0]["params"] == {"key": "CLAVE"}
    entradas = llamadas[0]["json"]["threatInfo"]["threatEntries"]
    assert entradas == [{"url": "https://a.com"}, {"url": "https://b.com"}]


def test_interpretar_respuesta_traduce_amenazas():
    datos = {"matches": [coincidencia("http://x.com/", "MALWARE"), coincidencia("http://x.com/"), coincidencia("http://x.com/")]}
    assert interpretar_respuesta(datos) == {"http://x.com/": ["Malware", "Phishing / ingeniería social"]}


def test_url_reportada_queda_critica(monkeypatch):
    simular_google(monkeypatch, {"matches": [coincidencia(URL_REPORTADA)]})
    resultado = analizar_url(URL_REPORTADA)
    previo = resultado.puntaje
    rep = consultar_safe_browsing([resultado.url], clave="CLAVE")
    aplicar_reputacion(resultado, rep.de(resultado.url))
    assert previo < 75
    assert resultado.puntaje == 100
    assert resultado.nivel == "Crítico"
    assert resultado.reportada is True
    assert resultado.hallazgos[0].criterio == "Reportada en Google Safe Browsing"


@pytest.mark.parametrize(
    "estado, excepcion",
    [(403, None), (500, None), (200, httpx.ConnectTimeout("tiempo agotado"))],
    ids=["clave-invalida", "error-servidor", "sin-conexion"],
)
def test_fallo_de_google_no_rompe_el_analisis(monkeypatch, estado, excepcion):
    simular_google(monkeypatch, estado=estado, excepcion=excepcion)
    r = consultar_safe_browsing(["https://www.google.com"], clave="CLAVE")
    assert r.disponible is False
    assert "solo el análisis heurístico" in r.mensaje


def test_ruta_muestra_enlace_reportado(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "CLAVE")
    simular_google(monkeypatch, {"matches": [coincidencia(URL_REPORTADA)]})
    r = TestClient(app).post("/analizar", data={"url": URL_REPORTADA})
    assert r.status_code == 200
    assert "REPORTADO como peligroso" in r.text
    assert "Phishing / ingeniería social" in r.text


def test_api_y_lote_con_reputacion(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "CLAVE")
    simular_google(monkeypatch, {"matches": [coincidencia(URL_REPORTADA)]})
    cliente = TestClient(app)
    datos = cliente.post("/api/analizar", json={"url": URL_REPORTADA}).json()
    assert datos["reportada"] is True and datos["puntaje"] == 100
    assert datos["reputacion"]["disponible"] is True
    lote = cliente.post("/lote", data={"urls": f"https://github.com\n{URL_REPORTADA}"})
    assert lote.status_code == 200
    assert "Reportadas por Google" in lote.text
