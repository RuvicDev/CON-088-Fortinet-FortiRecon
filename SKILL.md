---
name: fortirecon
description: "Usa la librería ruvic_fortirecon_connector para consultar Fortinet FortiRecon ASM/EASM: activos expuestos, riesgos, credenciales comprometidas y hallazgos. Úsala cuando el usuario pida analizar superficie de ataque externa, exposición de activos o filtraciones de credenciales monitoreadas por FortiRecon."
triggers:
- fortirecon
- fortinet fortirecon
- asm
- easm
- superficie de ataque
- activos expuestos
- credenciales comprometidas
- hallazgos
---

# Conector Fortinet FortiRecon (ruvic_fortirecon_connector)

## Regla crítica de credenciales

El código generado NUNCA hardcodea credenciales. Siempre se leen de variables de entorno:

| Variable | Contenido |
|---|---|
| `RUVIC_FORTIRECON_BASE_URL` | URL base HTTPS de la API FortiRecon |
| `RUVIC_FORTIRECON_API_KEY` | API Key para Authorization |
| `RUVIC_FORTIRECON_ORG_ID` | ID de organización FortiRecon |
| `RUVIC_FORTIRECON_VERIFY_SSL` | Verificación SSL opcional |
| `RUVIC_FORTIRECON_TIMEOUT` | Timeout opcional |
| `RUVIC_FORTIRECON_MAX_RESULTS` | Máximo de resultados |
| `RUVIC_FORTIRECON_EXPOSED_ASSETS_PATH_TEMPLATE` | Path opcional para activos expuestos |
| `RUVIC_FORTIRECON_RISKS_PATH_TEMPLATE` | Path opcional para riesgos |
| `RUVIC_FORTIRECON_CREDENTIALS_PATH_TEMPLATE` | Path opcional para credenciales |
| `RUVIC_FORTIRECON_FINDINGS_PATH_TEMPLATE` | Path opcional para hallazgos |

Si estas variables NO existen, el conector no está configurado: no generes código que lo use; indica al usuario que lo configure en Settings → Conectores. Nunca uses variables con alias `_DEFAULT_`, `_TEST_` o `_PRODUCCION_`.

## Conexión

```python
from ruvic_fortirecon_connector import FortireconClient
client = FortireconClient()
```

## Capacidad 1 — Consultar activos expuestos

```python
assets = client.get_exposed_assets(limit=20)
for asset in assets:
    print(asset)
```

## Capacidad 2 — Consultar riesgos

```python
risks = client.get_risks(severity="high", limit=20)
for risk in risks:
    print(risk)
```

## Capacidad 3 — Consultar credenciales comprometidas

```python
credentials = client.get_compromised_credentials(domain="example.com", limit=20)
for credential in credentials:
    print(credential)
```

## Capacidad 4 — Consultar hallazgos

```python
findings = client.get_findings(severity="critical", status="active", limit=20)
for finding in findings:
    print(finding)
```

## Manejo de errores

```python
from ruvic_fortirecon_connector import FortireconAuthError, FortireconConfigError, FortireconDataError, FortireconNetworkError
try:
    findings = client.get_findings(limit=10)
except FortireconConfigError as exc:
    print(f"Configuración inválida: {exc}")
except FortireconAuthError:
    print("API Key o permisos FortiRecon inválidos")
except FortireconNetworkError:
    print("No se pudo alcanzar FortiRecon")
except FortireconDataError as exc:
    print(f"FortiRecon rechazó la solicitud: {exc}")
```

## Buenas prácticas al generar código

1. Lee credenciales SOLO de `RUVIC_FORTIRECON_*`.
2. Nunca imprimas API Keys ni headers Authorization.
3. Usa límites razonables en consultas.
4. Si la versión del tenant usa rutas diferentes, ajusta los path templates en la configuración del conector.
5. Trata credenciales comprometidas como información sensible; no las expongas innecesariamente en logs.
