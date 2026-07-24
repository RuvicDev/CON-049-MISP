---
name: misp
description: >
  Usa la librería ruvic_misp_connector para intercambiar indicadores de
  amenaza (threat intel) en MISP - buscar un indicador de compromiso
  por su valor (search_ioc), crear un evento (create_event), y agregar
  un atributo/IOC a un evento existente (add_attribute). Úsala cuando
  el usuario pida investigar un IOC, registrar un evento de amenaza o
  enriquecer un evento con indicadores.
triggers:
- misp
- threat intel
- threat intelligence
- indicador de compromiso
- ioc
- evento de amenaza
---

# Conector MISP (ruvic_misp_connector)

Librería Python de intercambio de indicadores de amenaza para MISP.
Está **preinstalada en el runtime** cuando el conector está configurado
(si no, instálala con `pip install git+https://github.com/Dgirto/MISP.git#subdirectory=lib`).

## Regla crítica de credenciales

El código generado **NUNCA hardcodea credenciales**. Siempre se leen de
variables de entorno, disponibles cuando el conector `misp` está
configurado:

| Variable | Contenido |
|----------|-----------|
| `RUVIC_MISP_BASE_URL` | URL base de la instancia de MISP |
| `RUVIC_MISP_API_KEY` | Auth Key del usuario de servicio |
| `RUVIC_MISP_VERIFY_SSL` | (opcional) verificar certificado TLS |
| `RUVIC_MISP_CONNECT_TIMEOUT` | (opcional) timeout en segundos |

Si estas variables NO existen, el conector no está configurado: no
generes código que lo use; indica al usuario que lo configure en
**Settings → Conectores**.

## Este conector SÍ escribe

A diferencia de los conectores de solo consulta, `misp` crea eventos y
atributos reales en la plataforma de threat intel. Confirma con el
usuario antes de crear un evento o agregar un atributo si la acción no
fue explícitamente solicitada.

## Conexión (siempre igual)

```python
from ruvic_misp_connector import MispClient

client = MispClient()  # lee RUVIC_MISP_* del entorno automáticamente
```

## Capacidad 1 — Buscar un indicador de compromiso

```python
resultados = client.search_ioc("45.33.22.11")
# también podés acotar por tipo:
resultados = client.search_ioc("evil.com", type_filter="domain")
```

## Capacidad 2 — Crear un evento

```python
evento = client.create_event(
    info="Campaña de phishing detectada en finanzas",
    threat_level_id=2,  # 1=alto, 2=medio, 3=bajo, 4=indefinido
    distribution=0,      # 0=solo tu organización (default, más restrictivo)
    analysis=0,           # 0=inicial, 1=en curso, 2=completado
)
event_id = evento["Event"]["id"]
```

## Capacidad 3 — Agregar un atributo (IOC) al evento

```python
client.add_attribute(event_id, "ip-dst", "45.33.22.11", category="Network activity", to_ids=True)
```

Tipos de dato comunes: `ip-dst`, `ip-src`, `domain`, `hostname`, `url`,
`md5`, `sha1`, `sha256`, `email-src`.

## Manejo de errores

```python
from ruvic_misp_connector import (
    MispAuthError, MispDataError, MispNetworkError,
)

try:
    client.add_attribute(event_id, "ip-dst", "45.33.22.11")
except MispAuthError:
    print("Auth Key inválida o sin permiso suficiente")
except MispNetworkError:
    print("No se pudo alcanzar MISP — reintenta en unos segundos")
except MispDataError as e:
    print(f"Error de datos: {e}")  # ej. el evento no existe o el tipo es inválido
```

## Buenas prácticas al generar código

1. Lee credenciales SOLO de las variables `RUVIC_MISP_*` (el constructor de `MispClient` ya lo hace).
2. Nunca imprimas `RUVIC_MISP_API_KEY` en logs ni en la salida.
3. Este conector modifica datos reales: no crees eventos ni agregues atributos sin que el usuario lo haya pedido explícitamente.
4. Guarda siempre el `id` retornado por `create_event` — se necesita para `add_attribute` posteriores sobre el mismo evento.
5. Usa `distribution=0` (solo tu organización) salvo que el usuario indique explícitamente compartir el evento más ampliamente.
