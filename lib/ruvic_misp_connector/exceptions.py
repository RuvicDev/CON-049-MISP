"""Excepciones propias del conector MISP.

Separan los tres tipos de fallo que el usuario debe distinguir:
autenticación, red/servidor y datos. Nunca exponemos excepciones
crípticas del cliente HTTP subyacente.
"""


class MispConnectorError(Exception):
    """Error base del conector."""


class MispAuthError(MispConnectorError):
    """Auth Key inválida o permisos insuficientes."""


class MispNetworkError(MispConnectorError):
    """No se pudo alcanzar la instancia de MISP (red/timeout)."""


class MispDataError(MispConnectorError):
    """La operación es válida pero el evento/atributo/valor es inválido."""
