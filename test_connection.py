"""Prueba de conexión estándar del conector misp.

Firma estándar Ruvic: def test_connection() -> tuple[bool, str]
- Lee la configuración EXCLUSIVAMENTE de las env vars RUVIC_MISP_*.
- Nunca lanza excepciones; retorna (ok, mensaje).

Ejecutable también como script para pruebas locales:
    python test_connection.py
"""

from __future__ import annotations


def test_connection() -> tuple[bool, str]:
    """Conecta a MISP y consulta la versión del servidor usando las
    env vars RUVIC_MISP_*."""
    try:
        from ruvic_misp_connector import (
            MispAuthError,
            MispClient,
            MispDataError,
            MispNetworkError,
        )
    except ImportError:
        return (
            False,
            "La librería ruvic-misp-connector no está instalada. "
            "Instala con: pip install git+https://github.com/Dgirto/"
            "MISP.git#subdirectory=lib",
        )

    try:
        client = MispClient()  # valida que existan las env vars
    except ValueError as exc:
        return False, str(exc)

    try:
        client.ping()
    except MispAuthError as exc:
        return False, f"Autenticación fallida: {exc}"
    except MispNetworkError as exc:
        return False, f"Error de red: {exc}"
    except MispDataError as exc:
        return False, f"Error de datos: {exc}"
    except Exception as exc:  # red de seguridad: jamás propagar
        return False, f"Error inesperado: {exc}"

    return (
        True,
        f"Conexión exitosa a MISP ({client.config.base_url})",
    )


if __name__ == "__main__":
    ok, message = test_connection()
    print(f"{'OK' if ok else 'FALLO'}: {message}")
    raise SystemExit(0 if ok else 1)
