"""Cliente de intercambio de indicadores de amenaza para MISP (REST API).

Capacidades:
- search_ioc():      buscar un indicador de compromiso por su valor.
- create_event():     crear un nuevo evento.
- add_attribute():    agregar un atributo (IOC) a un evento existente.

Las credenciales SIEMPRE provienen de variables de entorno RUVIC_MISP_*
(ver config.MispConfig.from_env). Prohibido hardcodearlas.
"""

from __future__ import annotations

from typing import Any

import requests

from .config import MispConfig
from .exceptions import MispAuthError, MispDataError, MispNetworkError
from .logging_utils import get_logger

_VALID_ANALYSIS = {0, 1, 2}
_VALID_DISTRIBUTION = {0, 1, 2, 3, 4, 5}


class MispClient:
    """Cliente de intercambio de indicadores de amenaza en MISP.

    Args:
        config: configuración de conexión. Si se omite, se lee de las
            variables de entorno RUVIC_MISP_* (comportamiento estándar
            en el runtime de la plataforma).

    Ejemplo:
        >>> client = MispClient()  # lee RUVIC_MISP_* del entorno
        >>> client.search_ioc("45.33.22.11")
        [{'type': 'ip-dst', 'value': '45.33.22.11', ...}]
    """

    def __init__(self, config: MispConfig | None = None) -> None:
        self.config = config or MispConfig.from_env()
        self._logger = get_logger()
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": self.config.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        self._session.verify = self.config.verify_ssl

    # ------------------------------------------------------------------ #
    # Conexión
    # ------------------------------------------------------------------ #

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = f"{self.config.base_url}{path}"
        try:
            response = self._session.request(
                method, url, timeout=self.config.connect_timeout, **kwargs
            )
        except requests.exceptions.RequestException as exc:
            raise MispNetworkError(
                f"No se pudo alcanzar MISP en {self.config.base_url!r}: {exc}"
            ) from exc

        if response.status_code in (401, 403):
            raise MispAuthError(
                "Auth Key inválida o sin permiso suficiente para esta operación."
            )
        if response.status_code >= 400:
            raise MispDataError(
                f"MISP respondió {response.status_code}: {response.text[:300]}"
            )
        return response.json() if response.content else None

    def ping(self) -> bool:
        """Verifica la conexión consultando la versión del servidor.

        Returns:
            True si la conexión funciona.

        Raises:
            MispAuthError / MispNetworkError / MispDataError según el
            fallo.
        """
        self._request("GET", "/servers/getVersion")
        self._logger.info("Ping exitoso a MISP %s", self.config.base_url)
        return True

    # ------------------------------------------------------------------ #
    # Capacidad 1: buscar un indicador de compromiso
    # ------------------------------------------------------------------ #

    def search_ioc(self, value: str, type_filter: str | None = None) -> list[dict[str, Any]]:
        """Busca un indicador de compromiso (IOC) por su valor.

        Args:
            value: valor del indicador (ej. "45.33.22.11", "evil.com",
                un hash de archivo).
            type_filter: tipo de atributo MISP opcional para acotar la
                búsqueda (ej. "ip-dst", "domain", "md5", "sha256").

        Returns:
            Lista de dicts, uno por atributo encontrado (incluye type,
            value, category, event_id, to_ids).

        Ejemplo:
            >>> client.search_ioc("45.33.22.11")
            [{'type': 'ip-dst', 'value': '45.33.22.11', 'event_id': '123', ...}]
        """
        value = (value or "").strip()
        if not value:
            raise MispDataError("value no puede estar vacío.")
        body: dict[str, Any] = {"returnFormat": "json", "value": value}
        if type_filter:
            body["type"] = type_filter
        data = self._request("POST", "/attributes/restSearch", json=body)
        attributes = (data or {}).get("response", {}).get("Attribute", [])
        self._logger.info('Búsqueda de IOC "%s": %d resultado(s)', value, len(attributes))
        return attributes

    # ------------------------------------------------------------------ #
    # Capacidad 2: crear un evento
    # ------------------------------------------------------------------ #

    def create_event(
        self,
        info: str,
        threat_level_id: int = 4,
        distribution: int = 0,
        analysis: int = 0,
    ) -> dict[str, Any]:
        """Crea un nuevo evento en MISP.

        Args:
            info: descripción/título del evento.
            threat_level_id: 1 (alto) a 4 (indefinido). Default 4.
            distribution: nivel de distribución MISP, 0 (organización
                propia) a 4 (Sharing Group) o 5 (heredado). Default 0
                (solo tu organización — el valor más restrictivo).
            analysis: 0 (inicial), 1 (en curso), 2 (completado). Default 0.

        Returns:
            Dict con el evento creado (incluye "id" y "uuid").

        Ejemplo:
            >>> client.create_event("Campaña de phishing detectada")
            {'Event': {'id': '123', 'info': 'Campaña de phishing detectada', ...}}
        """
        info = (info or "").strip()
        if not info:
            raise MispDataError("info no puede estar vacío.")
        if distribution not in _VALID_DISTRIBUTION:
            raise MispDataError(
                f"distribution {distribution!r} inválido. Valores permitidos: {sorted(_VALID_DISTRIBUTION)}"
            )
        if analysis not in _VALID_ANALYSIS:
            raise MispDataError(
                f"analysis {analysis!r} inválido. Valores permitidos: {sorted(_VALID_ANALYSIS)}"
            )
        body = {
            "Event": {
                "info": info,
                "threat_level_id": str(threat_level_id),
                "distribution": str(distribution),
                "analysis": str(analysis),
            }
        }
        result = self._request("POST", "/events/add", json=body)
        event_id = (result or {}).get("Event", {}).get("id")
        self._logger.info('Evento creado: "%s" (id=%s)', info, event_id)
        return result

    # ------------------------------------------------------------------ #
    # Capacidad 3: agregar atributo (IOC) a un evento
    # ------------------------------------------------------------------ #

    def add_attribute(
        self,
        event_id: str,
        type_: str,
        value: str,
        category: str = "Network activity",
        to_ids: bool = True,
    ) -> dict[str, Any]:
        """Agrega un atributo (IOC) a un evento existente.

        Args:
            event_id: ID del evento (retornado por create_event).
            type_: tipo de atributo MISP (ej. "ip-dst", "domain", "md5",
                "sha256", "url").
            value: valor del atributo.
            category: categoría MISP. Default "Network activity".
            to_ids: si True, marca el atributo para exportar a
                herramientas de detección (IDS/IPS).

        Returns:
            Dict con el atributo creado.

        Ejemplo:
            >>> client.add_attribute("123", "ip-dst", "45.33.22.11", to_ids=True)
            {'Attribute': {'id': '456', 'type': 'ip-dst', 'value': '45.33.22.11', ...}}
        """
        event_id = (event_id or "").strip()
        type_ = (type_ or "").strip()
        value = (value or "").strip()
        if not event_id or not type_ or not value:
            raise MispDataError("event_id, type_ y value no pueden estar vacíos.")
        body = {
            "Attribute": {
                "type": type_,
                "category": category,
                "value": value,
                "to_ids": to_ids,
            }
        }
        result = self._request("POST", f"/attributes/add/{event_id}", json=body)
        self._logger.info('Atributo agregado a evento %s: %s="%s"', event_id, type_, value)
        return result
