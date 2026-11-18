from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.analizador import (
    ACORTADORES,
    MARCAS,
    MAX_URLS_LOTE,
    TLD_SOSPECHOSOS,
    UrlInvalidaError,
    analizar_lote,
    analizar_url,
)
from app.reputacion import aplicar_reputacion, consultar_safe_browsing

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
router = APIRouter()

EJEMPLOS = [
    "https://www.google.com",
    "http://paypa1-seguro-login.tk/verify/account",
    "http://192.168.10.5:8080/bancolombia/clave",
    "https://bit.ly/3xYz9Ab",
]


class SolicitudApi(BaseModel):
    url: str


@router.get("/", response_class=HTMLResponse)
def inicio(request: Request):
    return templates.TemplateResponse(request, "index.html", {"ejemplos": EJEMPLOS, "max_lote": MAX_URLS_LOTE})


@router.post("/analizar", response_class=HTMLResponse)
def analizar(request: Request, url: str = Form("")):
    try:
        resultado = analizar_url(url)
    except UrlInvalidaError as e:
        return templates.TemplateResponse(
            request,
            "index.html",
            {"error": str(e), "valor": url, "ejemplos": EJEMPLOS, "max_lote": MAX_URLS_LOTE},
            status_code=400,
        )
    reputacion = consultar_safe_browsing([resultado.url])
    aplicar_reputacion(resultado, reputacion.de(resultado.url))
    return templates.TemplateResponse(request, "resultado.html", {"r": resultado, "reputacion": reputacion})


@router.post("/lote", response_class=HTMLResponse)
def lote(request: Request, urls: str = Form("")):
    try:
        resultados, errores = analizar_lote(urls)
    except UrlInvalidaError as e:
        return templates.TemplateResponse(
            request,
            "index.html",
            {"error_lote": str(e), "valor_lote": urls, "ejemplos": EJEMPLOS, "max_lote": MAX_URLS_LOTE},
            status_code=400,
        )
    reputacion = consultar_safe_browsing([r.url for r in resultados])
    for r in resultados:
        aplicar_reputacion(r, reputacion.de(r.url))
    resultados.sort(key=lambda r: r.puntaje, reverse=True)
    resumen = {
        "total": len(resultados),
        "riesgosas": sum(1 for r in resultados if r.puntaje >= 50),
        "promedio": round(sum(r.puntaje for r in resultados) / len(resultados)) if resultados else 0,
        "reportadas": sum(1 for r in resultados if r.reportada),
    }
    return templates.TemplateResponse(
        request,
        "lote.html",
        {"resultados": resultados, "errores": errores, "resumen": resumen, "reputacion": reputacion},
    )


@router.get("/criterios", response_class=HTMLResponse)
def criterios(request: Request):
    return templates.TemplateResponse(
        request,
        "criterios.html",
        {"tlds": sorted(TLD_SOSPECHOSOS), "acortadores": sorted(ACORTADORES), "marcas": sorted(MARCAS)},
    )


@router.post("/api/analizar")
def api_analizar(datos: SolicitudApi):
    try:
        resultado = analizar_url(datos.url)
    except UrlInvalidaError as e:
        return JSONResponse(status_code=422, content={"error": str(e)})
    reputacion = consultar_safe_browsing([resultado.url])
    aplicar_reputacion(resultado, reputacion.de(resultado.url))
    respuesta = resultado.a_dict()
    respuesta["reputacion"] = {"disponible": reputacion.disponible, "mensaje": reputacion.mensaje}
    return respuesta


@router.get("/salud")
def salud():
    return {"estado": "ok"}
