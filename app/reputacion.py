import os
from dataclasses import dataclass, field

import httpx

from app.analizador import Hallazgo, ResultadoAnalisis, _clasificar

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
VARIABLE_CLAVE = "GOOGLE_SAFE_BROWSING_KEY"
TIEMPO_ESPERA = 5.0

AMENAZAS = {
    "SOCIAL_ENGINEERING": "Phishing / ingeniería social",
    "MALWARE": "Malware",
    "UNWANTED_SOFTWARE": "Software no deseado",
    "POTENTIALLY_HARMFUL_APPLICATION": "Aplicación potencialmente dañina",
}


@dataclass
class Reputacion:
    disponible: bool
    mensaje: str
    amenazas: dict[str, list[str]] = field(default_factory=dict)

    def de(self, url: str) -> list[str]:
        return self.amenazas.get(url, [])


def obtener_clave() -> str:
    return os.getenv(VARIABLE_CLAVE, "").strip()


def construir_solicitud(urls: list[str]) -> dict:
    return {
        "client": {"clientId": "phishguard", "clientVersion": "1.1.0"},
        "threatInfo": {
            "threatTypes": list(AMENAZAS),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }


def interpretar_respuesta(datos: dict) -> dict[str, list[str]]:
    amenazas: dict[str, list[str]] = {}
    for coincidencia in datos.get("matches", []):
        url = coincidencia.get("threat", {}).get("url")
        tipo = AMENAZAS.get(coincidencia.get("threatType"), coincidencia.get("threatType", "Desconocida"))
        if url and tipo not in amenazas.setdefault(url, []):
            amenazas[url].append(tipo)
    return amenazas


def consultar_safe_browsing(urls: list[str], clave: str | None = None) -> Reputacion:
    clave = obtener_clave() if clave is None else clave
    if not clave:
        return Reputacion(False, "Consulta de reputación no configurada.")
    if not urls:
        return Reputacion(True, "Sin URLs para consultar.")
    try:
        respuesta = httpx.post(ENDPOINT, params={"key": clave}, json=construir_solicitud(urls), timeout=TIEMPO_ESPERA)
        respuesta.raise_for_status()
        return Reputacion(True, "Consultado en Google Safe Browsing.", interpretar_respuesta(respuesta.json()))
    except (httpx.HTTPError, ValueError):
        return Reputacion(False, "Google Safe Browsing no respondió; se muestra solo el análisis heurístico.")


def aplicar_reputacion(resultado: ResultadoAnalisis, amenazas: list[str]) -> ResultadoAnalisis:
    if amenazas:
        resultado.hallazgos.insert(
            0,
            Hallazgo(
                "Reportada en Google Safe Browsing",
                "Lista negra de Google: " + ", ".join(amenazas) + ".",
                100 - resultado.puntaje,
            ),
        )
        resultado.puntaje = 100
        resultado.nivel, resultado.clase, resultado.recomendacion = _clasificar(100)
        resultado.reportada = True
    return resultado
