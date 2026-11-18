import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

LONGITUD_MAXIMA = 2048
MAX_URLS_LOTE = 20

TLD_SOSPECHOSOS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "click",
    "work", "country", "kim", "loan", "rest", "support", "cam", "icu", "buzz",
}

ACORTADORES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

PALABRAS_SENSIBLES = {
    "login", "signin", "verify", "verificar", "secure", "seguro", "account",
    "cuenta", "update", "actualizar", "confirm", "confirmar", "banco", "bank",
    "clave", "password", "suspend", "suspendida", "wallet", "pago", "premio",
}

MARCAS = {
    "google", "facebook", "paypal", "bancolombia", "davivienda", "nequi",
    "daviplata", "microsoft", "apple", "amazon", "netflix", "instagram",
    "whatsapp", "outlook", "mercadolibre",
}

SUFIJOS_COMPUESTOS = {
    "com.co", "gov.co", "edu.co", "org.co", "net.co", "co.uk",
    "com.ar", "com.mx", "com.br", "com.es",
}

NIVELES = [
    (75, "Crítico", "critico", "No abras este enlace ni ingreses datos. Tiene múltiples señales típicas de phishing."),
    (50, "Alto", "alto", "Muy probablemente es fraudulento. Verifica la dirección oficial por otro medio."),
    (25, "Medio", "medio", "Presenta señales sospechosas. Revisa el remitente y el dominio antes de continuar."),
    (0, "Bajo", "bajo", "No se detectaron señales relevantes, pero mantén las precauciones habituales."),
]


class UrlInvalidaError(ValueError):
    pass


@dataclass
class Hallazgo:
    criterio: str
    descripcion: str
    puntos: int


@dataclass
class ResultadoAnalisis:
    url: str
    dominio: str
    dominio_registrado: str
    puntaje: int
    nivel: str
    clase: str
    recomendacion: str
    hallazgos: list[Hallazgo] = field(default_factory=list)

    def a_dict(self) -> dict:
        return {
            "url": self.url,
            "dominio": self.dominio,
            "dominio_registrado": self.dominio_registrado,
            "puntaje": self.puntaje,
            "nivel": self.nivel,
            "recomendacion": self.recomendacion,
            "hallazgos": [h.__dict__ for h in self.hallazgos],
        }


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previa = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        actual = [i]
        for j, cb in enumerate(b, 1):
            actual.append(min(previa[j] + 1, actual[j - 1] + 1, previa[j - 1] + (ca != cb)))
        previa = actual
    return previa[-1]


def normalizar_url(texto: str) -> str:
    if texto is None:
        raise UrlInvalidaError("Debes ingresar una URL.")
    url = texto.strip()
    if not url:
        raise UrlInvalidaError("Debes ingresar una URL.")
    if len(url) > LONGITUD_MAXIMA:
        raise UrlInvalidaError(f"La URL supera el máximo de {LONGITUD_MAXIMA} caracteres.")
    if re.search(r"\s", url):
        raise UrlInvalidaError("La URL no puede contener espacios.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    partes = urlsplit(url)
    if partes.scheme.lower() not in ("http", "https"):
        raise UrlInvalidaError("Solo se analizan URLs con protocolo http o https.")
    host = partes.hostname or ""
    if not host or "." not in host and not _es_ip(host):
        raise UrlInvalidaError("La URL no tiene un dominio válido.")
    if not re.fullmatch(r"[a-zA-Z0-9.\-\[\]:]+", host):
        raise UrlInvalidaError("El dominio contiene caracteres no permitidos.")
    try:
        partes.port
    except ValueError:
        raise UrlInvalidaError("El puerto de la URL no es válido.")
    return url


def _es_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def dominio_registrado(host: str) -> str:
    etiquetas = host.lower().strip(".").split(".")
    if len(etiquetas) >= 3 and ".".join(etiquetas[-2:]) in SUFIJOS_COMPUESTOS:
        return ".".join(etiquetas[-3:])
    return ".".join(etiquetas[-2:])


def _nombre_base(registrado: str) -> str:
    return registrado.split(".")[0]


def _clasificar(puntaje: int) -> tuple[str, str, str]:
    for minimo, nivel, clase, recomendacion in NIVELES:
        if puntaje >= minimo:
            return nivel, clase, recomendacion
    return NIVELES[-1][1:]


def analizar_url(texto: str) -> ResultadoAnalisis:
    url = normalizar_url(texto)
    partes = urlsplit(url)
    host = (partes.hostname or "").lower()
    hallazgos: list[Hallazgo] = []

    def agregar(criterio: str, descripcion: str, puntos: int) -> None:
        hallazgos.append(Hallazgo(criterio, descripcion, puntos))

    es_ip = _es_ip(host)
    registrado = host if es_ip else dominio_registrado(host)
    base = _nombre_base(registrado)
    tld = host.rsplit(".", 1)[-1]
    subdominios = [] if es_ip else host.split(".")[: -len(registrado.split("."))]
    resto = (partes.path + "?" + partes.query).lower()

    if partes.scheme.lower() != "https":
        agregar("Sin HTTPS", "La conexión no está cifrada (http).", 10)

    if es_ip:
        agregar("Dirección IP", "Usa una IP en lugar de un nombre de dominio.", 25)

    if "@" in partes.netloc:
        agregar("Símbolo @", "El '@' oculta el destino real de la URL.", 20)

    if len(url) > 100:
        agregar("URL muy larga", f"Tiene {len(url)} caracteres; las URLs largas suelen ocultar el destino.", 15)
    elif len(url) > 75:
        agregar("URL larga", f"Tiene {len(url)} caracteres.", 8)

    if len(subdominios) >= 3:
        agregar("Exceso de subdominios", f"Tiene {len(subdominios)} niveles de subdominio.", 15)

    if not es_ip and tld in TLD_SOSPECHOSOS:
        agregar("Dominio de alto riesgo", f"La extensión .{tld} es muy usada en campañas de fraude.", 15)

    if "xn--" in host:
        agregar("Punycode", "El dominio usa caracteres internacionales que pueden imitar letras.", 20)

    if registrado in ACORTADORES:
        agregar("Acortador de enlaces", f"{registrado} oculta la dirección de destino.", 15)

    if not es_ip and base.removeprefix("xn--").count("-") >= 2:
        agregar("Guiones en el dominio", "Varios guiones son típicos de dominios falsos.", 10)

    if not es_ip and sum(c.isdigit() for c in base) >= 3:
        agregar("Números en el dominio", "El dominio mezcla muchos números.", 5)

    if partes.port and partes.port not in (80, 443):
        agregar("Puerto no estándar", f"Usa el puerto {partes.port}.", 10)

    if "//" in partes.path:
        agregar("Redirección oculta", "La ruta contiene '//', posible redirección.", 10)

    host_revisable = "" if base in MARCAS else host
    palabras = sorted(p for p in PALABRAS_SENSIBLES if p in host_revisable or p in resto)
    if palabras:
        agregar("Palabras de cebo", "Contiene: " + ", ".join(palabras) + ".", min(5 * len(palabras), 20))

    if not es_ip:
        fragmentos = {base, *[f for f in base.split("-") if len(f) >= 4]}
        imitada = next(
            ((m, f) for m in sorted(MARCAS) for f in sorted(fragmentos) if f != m and 0 < levenshtein(f, m) <= 2),
            None,
        )
        if imitada:
            agregar("Suplantación de marca", f"'{imitada[1]}' se parece a '{imitada[0]}' (typosquatting).", 30)
        else:
            en_sub = next((m for m in sorted(MARCAS) if m != base and (m in ".".join(subdominios) or m in base or m in (partes.username or "").lower())), None)
            if en_sub:
                agregar("Marca fuera de su dominio", f"Menciona '{en_sub}' pero el dominio real es {registrado}.", 25)

    puntaje = min(sum(h.puntos for h in hallazgos), 100)
    nivel, clase, recomendacion = _clasificar(puntaje)
    return ResultadoAnalisis(url, host, registrado, puntaje, nivel, clase, recomendacion, hallazgos)


def analizar_lote(texto: str) -> tuple[list[ResultadoAnalisis], list[dict]]:
    lineas = [l.strip() for l in (texto or "").splitlines() if l.strip()]
    if not lineas:
        raise UrlInvalidaError("Ingresa al menos una URL, una por línea.")
    if len(lineas) > MAX_URLS_LOTE:
        raise UrlInvalidaError(f"Máximo {MAX_URLS_LOTE} URLs por lote.")
    resultados, errores = [], []
    for linea in lineas:
        try:
            resultados.append(analizar_url(linea))
        except UrlInvalidaError as e:
            errores.append({"url": linea, "error": str(e)})
    resultados.sort(key=lambda r: r.puntaje, reverse=True)
    return resultados, errores
