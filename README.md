# Conector MISP (CON-049)

Conector Ruvic de intercambio de indicadores de amenaza (threat intel)
para MISP (REST API). Permite buscar un indicador de compromiso (IOC),
crear un evento, y agregar un atributo (IOC) a un evento existente.

## Instalación

```bash
pip install git+https://github.com/Dgirto/MISP.git#subdirectory=lib
```

Python 3.10+. Dependencia única: `requests>=2.31,<3.0`.

## Permisos requeridos en MISP

Crea un rol personalizado en **Administration → Roles** con únicamente:

- `Perm: Auth`: permite autenticarse vía API con una Auth Key.
- `Perm: Add`: permite crear eventos y agregar atributos.

No otorgues `Perm: Site Admin`, `Perm: Sync`, `Perm: Audit` ni
`Perm: Delegate` — el conector no necesita administrar la plataforma
ni sincronizar con otras instancias. Asigna ese rol a un **usuario de
servicio dedicado** (no reutilices tu propio usuario) y genera su Auth
Key desde su perfil (**Event Actions → Auth keys → Add authentication
key**).

## Variables de entorno (`RUVIC_MISP_*`)

| Variable | Obligatoria | Descripción |
|----------|-------------|-------------|
| `RUVIC_MISP_BASE_URL` | Sí | URL base de la instancia (ej. `https://misp.empresa.com`) |
| `RUVIC_MISP_API_KEY` | Sí | Auth Key del usuario de servicio |
| `RUVIC_MISP_VERIFY_SSL` | No (default `true`) | Verificar certificado TLS |
| `RUVIC_MISP_CONNECT_TIMEOUT` | No (default `15`) | Timeout de conexión en segundos |

## Pruebas locales

Con una instancia MISP de prueba (imagen oficial `misp/misp-docker` o
una instancia existente):

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ./lib

export RUVIC_MISP_BASE_URL=https://tu-instancia-misp.com
export RUVIC_MISP_API_KEY=tu-auth-key

python test_connection.py
python validate_local.py
```

Prueba también los casos de error (Auth Key inválida, evento
inexistente, tipo de atributo inválido) y verifica que los mensajes
sean claros.

## Notas de integración

- Este conector **SÍ escribe**: crea eventos y atributos reales en
  MISP. No es de solo lectura.
- `create_event` usa `distribution=0` (solo tu organización) por
  defecto — el valor más restrictivo. Súbelo explícitamente solo si el
  usuario lo pide.
- `create_event` retorna el `id` del evento creado, necesario para
  `add_attribute` posteriores sobre el mismo evento.
- Los tipos de atributo (`type_`) y categorías (`category`) deben
  coincidir con el vocabulario controlado de MISP (ej. tipos `ip-dst`,
  `domain`, `md5`, `sha256`, `url`; categorías `Network activity`,
  `Payload delivery`, `Artifacts dropped`, entre otras).
- `to_ids=True` marca el atributo para exportar a herramientas de
  detección (IDS/IPS); úsalo solo si el usuario quiere que el atributo
  dispare detecciones automáticas.
