import pytest

from app.analizador import (
    MAX_URLS_LOTE,
    UrlInvalidaError,
    analizar_lote,
    analizar_url,
    dominio_registrado,
    levenshtein,
)


def criterios(resultado):
    return {h.criterio for h in resultado.hallazgos}


def test_url_legitima_tiene_riesgo_bajo():
    r = analizar_url("https://www.google.com")
    assert r.puntaje == 0
    assert r.nivel == "Bajo"
    assert r.hallazgos == []


def test_url_de_phishing_es_critica():
    r = analizar_url("http://paypa1-seguro-login.tk/verify/account")
    assert r.nivel == "Crítico"
    assert r.puntaje >= 75
    assert {"Sin HTTPS", "Dominio de alto riesgo", "Suplantación de marca"} <= criterios(r)


def test_puntaje_esperado_para_ip_con_puerto():
    r = analizar_url("http://192.168.10.5:8080/bancolombia/clave")
    assert r.puntaje == 10 + 25 + 10 + 10
    assert r.nivel == "Alto"
    assert "Dirección IP" in criterios(r)


def test_marca_en_subdominio_de_otro_dominio():
    r = analizar_url("http://bancolombia.seguridad-clientes.xyz/login")
    assert r.dominio_registrado == "seguridad-clientes.xyz"
    assert "Marca fuera de su dominio" in criterios(r)


def test_arroba_oculta_destino_real():
    r = analizar_url("https://facebook.com@evil.com/login")
    assert r.dominio == "evil.com"
    assert {"Símbolo @", "Marca fuera de su dominio"} <= criterios(r)


def test_url_sin_protocolo_se_normaliza():
    r = analizar_url("bit.ly/3xYz9Ab")
    assert r.url == "http://bit.ly/3xYz9Ab"
    assert "Acortador de enlaces" in criterios(r)


def test_dominio_colombiano_compuesto():
    assert dominio_registrado("www.bancolombia.com.co") == "bancolombia.com.co"
    assert analizar_url("https://www.bancolombia.com.co").puntaje == 0


def test_puntaje_nunca_supera_100():
    url = "http://xn--pypal-4ve.secure.login.verify.account-update-banco.tk:8080//redir?clave=premio&pago=1" + "a" * 60
    assert analizar_url(url).puntaje == 100


@pytest.mark.parametrize(
    "a, b, esperado",
    [("paypal", "paypal", 0), ("paypa1", "paypal", 1), ("nequl", "nequi", 1), ("", "abc", 3)],
)
def test_levenshtein(a, b, esperado):
    assert levenshtein(a, b) == esperado


@pytest.mark.parametrize(
    "entrada, mensaje",
    [
        ("", "Debes ingresar"),
        ("   ", "Debes ingresar"),
        ("ftp://archivos.com", "http o https"),
        ("http://sin-punto", "dominio válido"),
        ("http://ejemplo .com", "espacios"),
        ("http://ejemplo.com:99999", "puerto"),
        ("http://" + "a" * 2050 + ".com", "máximo"),
    ],
    ids=["vacia", "solo-espacios", "protocolo-ftp", "sin-dominio", "con-espacios", "puerto-invalido", "muy-larga"],
)
def test_entradas_invalidas_lanzan_error(entrada, mensaje):
    with pytest.raises(UrlInvalidaError, match=mensaje):
        analizar_url(entrada)


def test_lote_ordena_y_separa_errores():
    resultados, errores = analizar_lote("https://github.com\nftp://malo.com\nhttp://nequl-pagos.xyz/premio\n\n")
    assert [r.dominio_registrado for r in resultados] == ["nequl-pagos.xyz", "github.com"]
    assert len(errores) == 1 and errores[0]["url"] == "ftp://malo.com"


def test_lote_vacio_o_excedido():
    with pytest.raises(UrlInvalidaError):
        analizar_lote("\n \n")
    with pytest.raises(UrlInvalidaError, match="Máximo"):
        analizar_lote("\n".join(f"https://sitio{i}.com" for i in range(MAX_URLS_LOTE + 1)))
