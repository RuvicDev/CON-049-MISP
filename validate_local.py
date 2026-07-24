"""Validación local del conector misp: ejercita las 3 capacidades.

Uso:
    python validate_local.py

Requiere las variables RUVIC_MISP_* exportadas en el entorno, con una
Auth Key de un usuario de servicio con los permisos del README ('Perm:
Auth' + 'Perm: Add').

ADVERTENCIA: este script crea un evento y un atributo REALES en la
instancia de MISP configurada. Ejecútalo solo contra un entorno de
pruebas.
"""

from ruvic_misp_connector import MispClient, setup_logging

setup_logging("INFO")
client = MispClient()

print("== 1. Buscar un IOC ==")
results = client.search_ioc("1.2.3.4")
print(f"  {len(results)} coincidencia(s)")

print("== 2. Crear evento ==")
event = client.create_event("Prueba de validación local Ruvic", distribution=0)
event_id = event["Event"]["id"]
print(f"  event_id={event_id}")

print("== 3. Agregar atributo (IOC) al evento ==")
attribute = client.add_attribute(event_id, "ip-dst", "203.0.113.10", to_ids=False)
print(f"  {attribute}")

print("\nTodo OK: search_ioc, create_event y add_attribute funcionan.")
