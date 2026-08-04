"""Validación local del conector FortiRecon contra una instancia real.

Requiere RUVIC_FORTIRECON_* apuntando a una API FortiRecon de prueba o cliente
autorizado. No usa mocks.
"""
from __future__ import annotations
from ruvic_fortirecon_connector import FortireconClient, setup_logging
setup_logging("INFO")
client = FortireconClient()
print("== Ping =="); print(client.ping())
print("== Activos expuestos =="); assets = client.get_exposed_assets(limit=5); print(f"Activos: {len(assets)}"); [print(f"  {a}") for a in assets[:3]]
print("== Riesgos =="); risks = client.get_risks(limit=5); print(f"Riesgos: {len(risks)}"); [print(f"  {r}") for r in risks[:3]]
print("== Credenciales comprometidas =="); creds = client.get_compromised_credentials(limit=5); print(f"Credenciales/reportes: {len(creds)}"); [print(f"  {c}") for c in creds[:3]]
print("== Hallazgos =="); findings = client.get_findings(limit=5); print(f"Hallazgos: {len(findings)}"); [print(f"  {f}") for f in findings[:3]]
print("Validación FortiRecon completa.")
