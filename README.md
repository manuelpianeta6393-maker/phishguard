# 🛡️ PhishGuard — Analizador de URLs sospechosas de phishing

> Aplicación web desarrollada con **FastAPI**, **Jinja2** y **pytest** que evalúa enlaces y estima su riesgo de ser fraudulentos antes de que el usuario haga clic.

**Autor:** Manuel Julián Pianeta Calvo — Ingeniería de Sistemas, Institución Universitaria Americana
**Modalidad:** Individual · Proyecto práctico de desarrollo de software

---

## 1. Presentación del proyecto

### Nombre
**PhishGuard**

### Propósito
Ayudar a cualquier persona a decidir si un enlace recibido por correo, SMS o WhatsApp es confiable. El usuario pega la URL y la aplicación devuelve un **puntaje de riesgo de 0 a 100**, un **nivel** (Bajo, Medio, Alto o Crítico), una **recomendación** y la **lista de señales** que encontró.

### Problema que resuelve
El phishing es una de las formas de fraude más comunes en Colombia: mensajes que imitan a bancos (Bancolombia, Davivienda, Nequi, Daviplata) o plataformas (PayPal, Netflix, Microsoft) con enlaces falsos que roban credenciales. La mayoría de usuarios no sabe leer una URL ni detectar trucos como `paypa1.com`, `bancolombia.seguridad-clientes.xyz` o `facebook.com@evil.com`. PhishGuard automatiza esa revisión con dos capas: **reglas heurísticas propias** que detectan trucos nuevos que aún nadie ha reportado, y la **lista negra de Google Safe Browsing**, que confirma enlaces ya reportados como phishing o malware. El resultado se explica en lenguaje sencillo.

### Funcionalidad principal
1. **Análisis individual:** recibe una URL, la valida, la descompone, aplica 15 reglas heurísticas de ciberseguridad y consulta la API de Google Safe Browsing.
2. **Análisis por lote:** recibe hasta 20 URLs (una por línea), las analiza, las consulta todas en una sola petición a Google, las ordena de mayor a menor riesgo y muestra un resumen con indicadores.
3. **API JSON:** endpoint `POST /api/analizar` para integrar el analizador con otros sistemas.
4. **Página de criterios:** explica cómo se calcula el puntaje.

No es un CRUD: no se guardan registros. La aplicación **procesa información** (análisis de texto, distancia de edición entre cadenas, clasificación por puntaje) y **genera un resultado nuevo** en cada solicitud.

---

## 2. Tecnologías utilizadas

| Tecnología | Función en el proyecto | Por qué se eligió |
|---|---|---|
| **Python 3.11+** | Lenguaje de toda la aplicación | Exigido por el curso; tiene librería estándar fuerte para manejo de URLs |
| **FastAPI** | Framework backend: define rutas, recibe formularios y JSON, devuelve HTML y JSON | Rápido, moderno, valida datos con Pydantic y genera documentación automática en `/docs` |
| **Jinja2** | Motor de plantillas HTML dinámicas | Integrado con FastAPI; permite herencia de plantillas (`base.html`), ciclos, condicionales y filtros |
| **Uvicorn** | Servidor ASGI que ejecuta la aplicación | Servidor recomendado oficialmente para FastAPI |
| **python-multipart** | Lectura de formularios HTML (`Form`) | FastAPI lo requiere para procesar `application/x-www-form-urlencoded` |
| **Pydantic** | Validación del cuerpo JSON de la API | Viene con FastAPI; rechaza automáticamente peticiones mal formadas (422) |
| **pytest** | Pruebas automatizadas | Exigido por el curso; sintaxis simple, fixtures y `parametrize` |
| **httpx** | Cliente HTTP para consultar la API de Google Safe Browsing y base de `TestClient` | Moderno, con tiempo de espera configurable y excepciones claras |
| **Google Safe Browsing API v4** | Lista negra de Google con millones de URLs de phishing y malware | Gratuita, es la misma que usan Chrome y Firefox para mostrar advertencias |
| **python-dotenv** | Carga la clave de la API desde el archivo `.env` | Evita escribir la clave en el código o subirla a GitHub |
| **urllib.parse / ipaddress / re** (estándar) | Descomponer la URL, detectar IPs y validar con expresiones regulares | No requieren instalación y son confiables |

---

## 3. Arquitectura y organización

```
phishguard/
├── app/
│   ├── __init__.py
│   ├── main.py              ← Crea la app FastAPI, monta /static e incluye las rutas
│   ├── routes.py            ← Rutas de FastAPI (controladores)
│   ├── analizador.py        ← Lógica de negocio: validación, reglas, puntaje
│   ├── reputacion.py        ← Consulta a Google Safe Browsing
│   ├── templates/           ← Plantillas Jinja2
│   │   ├── base.html        ← Plantilla padre (barra, pie de página)
│   │   ├── index.html       ← Formularios de análisis individual y por lote
│   │   ├── resultado.html   ← Medidor de riesgo y señales detectadas
│   │   ├── lote.html        ← Tabla de resultados y KPIs del lote
│   │   └── criterios.html   ← Explicación de las reglas
│   └── static/
│       └── styles.css       ← Estilos de la interfaz
├── tests/
│   ├── conftest.py          ← Garantiza que las pruebas no usen la clave real
│   ├── test_analizador.py   ← Pruebas unitarias de la lógica
│   ├── test_reputacion.py   ← Pruebas de la API externa con mocks
│   └── test_rutas.py        ← Pruebas de rutas con TestClient
├── evidencias/              ← Capturas de pantalla
├── .env.example             ← Plantilla para la clave de la API
├── pytest.ini
├── requirements.txt
└── README.md
```

La separación sigue tres capas:

- **Rutas (`app/routes.py`)**: reciben la petición, llaman a la lógica y eligen qué plantilla mostrar. No contienen reglas de análisis.
- **Integración externa (`app/reputacion.py`)**: arma la petición a Google, interpreta la respuesta y, si el enlace está reportado, ajusta el resultado. Si no hay clave o Google no responde, la app sigue funcionando solo con las reglas.
- **Lógica (`app/analizador.py`)**: funciones puras (`analizar_url`, `analizar_lote`, `normalizar_url`, `levenshtein`, `dominio_registrado`) que no dependen de FastAPI. Por eso se pueden probar de forma aislada.
- **Presentación (`app/templates/`)**: Jinja2 recibe objetos `ResultadoAnalisis` y los convierte en HTML.

### Rutas de FastAPI

| Método | Ruta | Descripción | Respuesta |
|---|---|---|---|
| GET | `/` | Página principal con formularios | HTML |
| POST | `/analizar` | Analiza una URL enviada por formulario | HTML (200) o error (400) |
| POST | `/lote` | Analiza varias URLs | HTML (200) o error (400) |
| GET | `/criterios` | Explica las reglas | HTML |
| POST | `/api/analizar` | Analiza una URL enviada como JSON `{"url": "..."}` | JSON (200) o error (422) |
| GET | `/salud` | Verificación de estado | JSON |
| GET | `/docs` | Documentación interactiva generada por FastAPI | HTML |

### Uso de Jinja2
- `base.html` define la estructura común con `{% block contenido %}`; las demás plantillas usan `{% extends "base.html" %}`.
- `resultado.html` usa la variable `r.puntaje` dentro de un estilo CSS (`--valor`) para dibujar el medidor circular, y el filtro `sort(attribute='puntos', reverse=true)` para ordenar las señales.
- `lote.html` usa `{% for %}`, `map(attribute='criterio') | join(', ')` y clases CSS dinámicas (`{{ r.clase }}`) para colorear cada nivel.
- `index.html` muestra mensajes de error con `{% if error %}` y conserva lo que escribió el usuario con `value="{{ valor }}"`.
- Jinja2 escapa automáticamente el contenido, evitando que una URL maliciosa inyecte HTML (XSS).

---

## 4. Funcionamiento de la aplicación

```mermaid
flowchart LR
    U[Usuario] -->|Escribe URL y envía formulario| F[POST /analizar]
    F --> R[routes.py]
    R -->|analizar_url texto| A[analizador.py]
    A --> V{¿URL válida?}
    V -- No --> E[UrlInvalidaError]
    E --> R2[index.html con mensaje de error · HTTP 400]
    V -- Sí --> P[Descomponer URL<br/>aplicar 15 reglas<br/>sumar puntos]
    P --> C[Clasificar nivel<br/>Bajo / Medio / Alto / Crítico]
    C --> G[reputacion.py<br/>consulta Google Safe Browsing]
    G -- Reportada --> X[Puntaje 100 · Crítico]
    G -- Sin reportes / sin conexión --> O
    X --> O[ResultadoAnalisis]
    O --> J[resultado.html · Jinja2]
    J --> U
```

### ¿Qué datos recibe?
- **Formulario individual:** campo `url` (texto).
- **Formulario por lote:** campo `urls` (texto con una URL por línea).
- **API:** JSON `{"url": "..."}`.

### ¿Cómo se procesan?
1. **Normalización y validación** (`normalizar_url`): elimina espacios, agrega `http://` si falta el protocolo, rechaza protocolos distintos de http/https, dominios sin punto, puertos inválidos, espacios internos y URLs de más de 2048 caracteres.
2. **Descomposición** con `urllib.parse.urlsplit`: protocolo, host, puerto, usuario (lo que va antes de `@`), ruta y parámetros.
3. **Dominio registrado**: identifica el dominio real considerando sufijos compuestos como `.com.co` o `.gov.co` (`www.bancolombia.com.co` → `bancolombia.com.co`).
4. **Reglas heurísticas** — cada una suma puntos:

| Señal | Puntos |
|---|---|
| Sin HTTPS | 10 |
| Host es una dirección IP | 25 |
| Símbolo `@` en la dirección | 20 |
| URL larga (>75) / muy larga (>100) | 8 / 15 |
| 3 o más subdominios | 15 |
| Extensión de alto riesgo (`.tk`, `.xyz`, `.top`, …) | 15 |
| Punycode (`xn--`) | 20 |
| Acortador (`bit.ly`, `tinyurl.com`, …) | 15 |
| 2 o más guiones en el dominio | 10 |
| 3 o más dígitos en el dominio | 5 |
| Puerto no estándar | 10 |
| `//` dentro de la ruta | 10 |
| Palabras de cebo (`login`, `clave`, `verificar`, `premio`…) | 5 c/u, máx. 20 |
| **Suplantación de marca** (distancia de Levenshtein ≤ 2, ej. `paypa1` ≈ `paypal`) | 30 |
| Marca mencionada fuera de su dominio real | 25 |

5. **Clasificación**: el total se limita a 100 y se asigna el nivel: **Bajo** (0–24), **Medio** (25–49), **Alto** (50–74), **Crítico** (75–100), con una recomendación para cada uno.

6. **Reputación externa** (`reputacion.py`): se envía la URL a `https://safebrowsing.googleapis.com/v4/threatMatches:find` con la clave guardada en `.env`. Si Google la tiene registrada como phishing, malware, software no deseado o aplicación dañina, se agrega la señal "Reportada en Google Safe Browsing" y el puntaje pasa a **100 (Crítico)**. Si no hay clave, la clave es inválida o Google no responde en 5 segundos, se muestra un aviso y el resultado queda con el análisis heurístico.

El algoritmo de **distancia de Levenshtein** está implementado desde cero con programación dinámica: calcula cuántas inserciones, borrados o sustituciones separan dos palabras. Así se detecta `nequl` (1 cambio respecto a `nequi`) o `paypa1` (1 cambio respecto a `paypal`).

### ¿Qué función cumple FastAPI?
Recibe la petición HTTP, extrae los datos del formulario (`Form`) o del JSON (modelo Pydantic `SolicitudApi`), invoca la lógica, captura las excepciones de validación y devuelve la respuesta con el código HTTP correcto (200, 400 o 422). También sirve los archivos estáticos y genera la documentación en `/docs`.

### ¿Cómo presenta Jinja2 los resultados?
`TemplateResponse` entrega a la plantilla el objeto `ResultadoAnalisis` y el estado de la consulta a Google, que se muestra con un indicador verde (sin reportes), rojo (reportado) o gris (no consultado). Jinja2 dibuja el medidor con el color del nivel, la URL, el host, el dominio real y una tarjeta por cada señal detectada ordenada por gravedad. En el lote muestra 4 indicadores (total, riesgosas, promedio, inválidas) y una tabla con barras de riesgo.

### ¿Qué ocurre si el usuario introduce información incorrecta?
- La lógica lanza `UrlInvalidaError` con un mensaje claro en español.
- La ruta la captura y vuelve a mostrar el formulario con el mensaje en rojo, **conservando lo que escribió** y respondiendo **HTTP 400**.
- En la API se devuelve **HTTP 422** con `{"error": "..."}`; si falta el campo `url`, Pydantic responde 422 automáticamente.
- En el lote, las líneas inválidas no detienen el proceso: se listan aparte en “Entradas no procesadas”.

---

## 5. Instalación y ejecución

### Requisitos
- Python 3.11 o superior
- pip
- Git (para clonar)

### Pasos

```bash
git clone https://github.com/manuelpianeta6393-maker/phishguard.git
cd phishguard

python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

### Configurar la clave de Google Safe Browsing (opcional pero recomendado)
1. Entra a <https://console.cloud.google.com>, crea un proyecto y habilita **Safe Browsing API**.
2. En **APIs y servicios → Credenciales**, crea una **clave de API**.
3. Copia `.env.example` como `.env` y pega la clave:

```
GOOGLE_SAFE_BROWSING_KEY=tu_clave
```

Sin clave la aplicación funciona igual, solo con las reglas heurísticas. El archivo `.env` está en `.gitignore`, así que la clave nunca se sube a GitHub.

### Iniciar el servidor

```bash
uvicorn app.main:app --reload
```

### Acceder desde el navegador
- Aplicación: <http://127.0.0.1:8000>
- Documentación de la API: <http://127.0.0.1:8000/docs>

### Cómo usarla
1. Pega una URL en **Análisis individual** y pulsa **Analizar URL** (o haz clic en un ejemplo).
2. Revisa el puntaje, el nivel, la recomendación y las señales detectadas.
3. Para comprobar la integración con Google usa la URL de prueba oficial `http://malware.testing.google.test/testing/malware/`: debe aparecer como **REPORTADA**.
4. Para varias URLs, pégalas una por línea en **Análisis por lote** y pulsa **Analizar lote**.
5. Desde otro programa:

```bash
curl -X POST http://127.0.0.1:8000/api/analizar \
     -H "Content-Type: application/json" \
     -d "{\"url\": \"http://paypa1-seguro-login.tk/verify/account\"}"
```

---

## 6. Pruebas automatizadas

### Ejecutar

```bash
pytest
```

`pytest.ini` ya configura la carpeta `tests` y el modo detallado (`-v`). Se implementaron **28 funciones de prueba** que, con `parametrize`, generan **39 casos**. Todos pasan.

Las pruebas **nunca llaman a Google de verdad**: `conftest.py` elimina la clave real y `test_reputacion.py` reemplaza `httpx.post` por una función falsa (*mock* con `monkeypatch`) que devuelve respuestas controladas. Así se prueba la lógica propia sin depender de internet ni de que Google responda siempre lo mismo, tal como recomienda el enunciado.

### Pruebas de la lógica (`tests/test_analizador.py`)

| # | Prueba | Qué comprueba | Datos | Resultado esperado | Obtenido | ¿Éxito? |
|---|---|---|---|---|---|---|
| 1 | `test_url_legitima_tiene_riesgo_bajo` | Funcionalidad principal con URL segura | `https://www.google.com` | Puntaje 0, nivel Bajo, sin señales | Igual | ✅ |
| 2 | `test_url_de_phishing_es_critica` | Funcionalidad principal con phishing | `http://paypa1-seguro-login.tk/verify/account` | Nivel Crítico, ≥ 75, detecta Sin HTTPS, TLD de riesgo y suplantación | 85, Crítico | ✅ |
| 3 | `test_puntaje_esperado_para_ip_con_puerto` | Resultado exacto esperado | `http://192.168.10.5:8080/bancolombia/clave` | 55 puntos (10+25+10+10), Alto | 55, Alto | ✅ |
| 4 | `test_marca_en_subdominio_de_otro_dominio` | Detección de marca fuera de su dominio | `http://bancolombia.seguridad-clientes.xyz/login` | Dominio real `seguridad-clientes.xyz` y señal de marca | Igual | ✅ |
| 5 | `test_arroba_oculta_destino_real` | Truco del `@` | `https://facebook.com@evil.com/login` | Host `evil.com`, señales `@` y marca | Igual | ✅ |
| 6 | `test_url_sin_protocolo_se_normaliza` | Normalización | `bit.ly/3xYz9Ab` | Se convierte a `http://…` y detecta acortador | Igual | ✅ |
| 7 | `test_dominio_colombiano_compuesto` | Sufijos `.com.co` | `www.bancolombia.com.co` | Dominio `bancolombia.com.co`, puntaje 0 | Igual | ✅ |
| 8 | `test_puntaje_nunca_supera_100` | Caso límite | URL con todas las señales | Puntaje exactamente 100 | 100 | ✅ |
| 9–12 | `test_levenshtein` (4 casos) | Algoritmo de distancia | `paypal/paypal`, `paypa1/paypal`, `nequl/nequi`, `""/abc` | 0, 1, 1, 3 | Igual | ✅ |
| 13–19 | `test_entradas_invalidas_lanzan_error` (7 casos) | Datos inválidos | vacía, solo espacios, `ftp://`, sin dominio, con espacios, puerto 99999, >2048 caracteres | `UrlInvalidaError` con mensaje correcto | Igual | ✅ |
| 20 | `test_lote_ordena_y_separa_errores` | Lote: orden y errores | 3 URLs, una inválida y una línea vacía | 2 resultados ordenados por riesgo, 1 error | Igual | ✅ |
| 21 | `test_lote_vacio_o_excedido` | Casos límite del lote | Lote vacío y 21 URLs | `UrlInvalidaError` en ambos | Igual | ✅ |

### Pruebas de rutas FastAPI (`tests/test_rutas.py`, con `TestClient`)

| # | Prueba | Qué comprueba | Datos | Resultado esperado | Obtenido | ¿Éxito? |
|---|---|---|---|---|---|---|
| 22 | `test_pagina_principal_responde` | `GET /` responde | — | 200, HTML, título y pie de autor | Igual | ✅ |
| 23 | `test_formulario_muestra_resultado` | `POST /analizar` muestra el resultado | URL de phishing | 200 y textos “Crítico” y “Suplantación de marca” | Igual | ✅ |
| 24 | `test_formulario_con_url_invalida_muestra_error` | Error controlado en la ruta | `ftp://archivos.com` | 400, mensaje de error y valor conservado | Igual | ✅ |
| 25 | `test_formulario_vacio` | Formulario sin datos | `{}` | 400 y “Debes ingresar una URL.” | Igual | ✅ |
| 26 | `test_lote_muestra_resumen` | `POST /lote` | 2 válidas y 1 inválida | 200, resumen y sección de no procesadas | Igual | ✅ |
| 27 | `test_api_devuelve_json` | `POST /api/analizar` | `https://www.google.com` | 200, JSON con puntaje 0 y nivel Bajo | Igual | ✅ |
| 28 | `test_api_con_url_invalida_devuelve_422` | API con dato inválido | `{"url": ""}` | 422 y JSON de error | Igual | ✅ |
| 29 | `test_api_sin_campo_url` | Validación Pydantic | `{}` | 422 | 422 | ✅ |
| 30 | `test_criterios_y_salud` | Rutas auxiliares y estáticos | — | 200 en `/criterios`, `/salud` y CSS | Igual | ✅ |

### Pruebas de la integración con Google Safe Browsing (`tests/test_reputacion.py`, con mocks)

| # | Prueba | Qué comprueba | Datos | Resultado esperado | Obtenido | ¿Éxito? |
|---|---|---|---|---|---|---|
| 31 | `test_sin_clave_no_consulta_google` | Sin clave no se hace petición | Sin `GOOGLE_SAFE_BROWSING_KEY` | `disponible = False`, 0 llamadas | Igual | ✅ |
| 32 | `test_solicitud_enviada_a_google` | Formato de la petición | 2 URLs, clave `CLAVE` | Clave en parámetros y ambas URLs en `threatEntries` | Igual | ✅ |
| 33 | `test_interpretar_respuesta_traduce_amenazas` | Traducción y duplicados | Respuesta con MALWARE y 2× SOCIAL_ENGINEERING | `["Malware", "Phishing / ingeniería social"]` | Igual | ✅ |
| 34 | `test_url_reportada_queda_critica` | Efecto de un reporte | URL de prueba de Google, respuesta simulada con coincidencia | Puntaje heurístico < 75 pasa a 100, Crítico | Igual | ✅ |
| 35–37 | `test_fallo_de_google_no_rompe_el_analisis` (3 casos) | Errores externos | HTTP 403, HTTP 500, tiempo agotado | `disponible = False` y aviso, sin excepción | Igual | ✅ |
| 38 | `test_ruta_muestra_enlace_reportado` | Ruta `/analizar` con reporte | URL de prueba con mock | 200 y texto "REPORTADO como peligroso" | Igual | ✅ |
| 39 | `test_api_y_lote_con_reputacion` | API JSON y lote | URL de prueba con mock | `reportada: true`, puntaje 100 y KPI de reportadas | Igual | ✅ |

**Resultado:** `39 passed` ✅ (ver evidencia 8).

---

## 7. Evidencias de funcionamiento

### Interfaz principal
![Interfaz principal](evidencias/01_interfaz_principal.png)

### Ingreso de una URL sospechosa
![Ingreso de URL](evidencias/02_ingreso_url.png)

### Resultado del procesamiento — URL de phishing (Crítico)
![Resultado crítico](evidencias/03_resultado_critico.png)

### Resultado del procesamiento — URL legítima (Bajo)
![Resultado seguro](evidencias/04_resultado_seguro.png)

### Análisis por lote
![Análisis por lote](evidencias/05_analisis_por_lote.png)

### Validación de entrada incorrecta
![Validación](evidencias/06_validacion_error.png)

### Página de criterios
![Criterios](evidencias/07_criterios.png)

### Integración con Google Safe Browsing: enlace reportado
![Enlace reportado](evidencias/09_reportada_google.png)

### Ejecución de las pruebas con pytest
![Pytest](evidencias/08_pytest_resultados.png)

---

## 8. Conclusiones

**Desafíos y soluciones**

- **Identificar el dominio real.** Tomar las dos últimas partes del host fallaba con dominios colombianos (`bancolombia.com.co` quedaba como `com.co`). Se resolvió con un conjunto de sufijos compuestos.
- **Detectar suplantación sin falsos positivos.** Comparar el dominio completo con la marca no detectaba `paypa1-seguro-login`. Se dividió el dominio por guiones y se compara cada fragmento con la distancia de Levenshtein. También se quitaron marcas muy cortas que generaban coincidencias accidentales, y las palabras de cebo no se evalúan en el host cuando el dominio es el oficial de la marca (`accounts.google.com`).
- **Errores amigables.** En lugar de dejar que una excepción rompa la página, se creó `UrlInvalidaError`; las rutas la capturan y devuelven el formulario con el mensaje y el código HTTP adecuado.
- **Depender de un servicio externo.** Una API puede fallar, tardar o no tener clave configurada. Se puso un tiempo de espera de 5 segundos y se capturan todos los errores de `httpx` para que la app siga funcionando solo con las reglas. Para probarlo sin internet se usaron *mocks* con `monkeypatch`.
- **Proteger la clave.** La clave se lee de una variable de entorno cargada desde `.env`, que está excluido de Git.
- **Pruebas mantenibles.** Separar la lógica de las rutas permitió probar las reglas como funciones normales, y con `parametrize` se cubrieron 7 tipos de entradas inválidas en una sola función.

**Aprendizajes**

- FastAPI permite atender en la misma aplicación una interfaz HTML (formularios + Jinja2) y una API JSON validada con Pydantic, reutilizando la misma lógica.
- Jinja2 con herencia de plantillas evita repetir código y su autoescape protege contra inyección de HTML, algo importante en una aplicación que muestra URLs maliciosas.
- `TestClient` simula peticiones reales sin levantar el servidor, lo que hace que las pruebas sean rápidas (menos de 1 segundo) y confiables.
- Combinar dos fuentes da un mejor resultado: Google Safe Browsing confirma enlaces ya reportados, y las heurísticas detectan enlaces nuevos que todavía no están en ninguna lista negra. Además, la app le explica al usuario **por qué** un enlace es peligroso, que es la mejor defensa contra el phishing.

---

<p align="center"><strong>Desarrollado por el Ing. Manuel Pianeta</strong></p>
