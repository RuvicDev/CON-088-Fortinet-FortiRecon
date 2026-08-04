# Conector Fortinet FortiRecon para Ruvic

Conector Ruvic para gestión de superficie de ataque externa con Fortinet FortiRecon ASM/EASM. Permite consultar activos expuestos, riesgos, credenciales comprometidas y hallazgos.

## Capacidades

1. `get_exposed_assets(...)`.
2. `get_risks(...)`.
3. `get_compromised_credentials(...)`.
4. `get_findings(...)`.

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ./lib
```

Desde Git:

```bash
pip install git+https://github.com/tu-org/conector-fortirecon.git#subdirectory=lib
```

## Variables de entorno

| Variable | Obligatoria | Descripción | Default |
|---|---:|---|---|
| `RUVIC_FORTIRECON_BASE_URL` | Sí | URL base HTTPS de la API | — |
| `RUVIC_FORTIRECON_API_KEY` | Sí | API Key para header Authorization | — |
| `RUVIC_FORTIRECON_ORG_ID` | Sí | ID de organización | — |
| `RUVIC_FORTIRECON_VERIFY_SSL` | No | Verificar certificado SSL | `true` |
| `RUVIC_FORTIRECON_TIMEOUT` | No | Timeout de red | `20` |
| `RUVIC_FORTIRECON_MAX_RESULTS` | No | Máximo de resultados | `100` |
| `RUVIC_FORTIRECON_EXPOSED_ASSETS_PATH_TEMPLATE` | No | Path de activos expuestos | `/easm/{org_id}/exposed_services` |
| `RUVIC_FORTIRECON_RISKS_PATH_TEMPLATE` | No | Path de riesgos | `/easm/{org_id}/issues` |
| `RUVIC_FORTIRECON_CREDENTIALS_PATH_TEMPLATE` | No | Path de credenciales | `/asm/{org_id}/leaked_credentials` |
| `RUVIC_FORTIRECON_FINDINGS_PATH_TEMPLATE` | No | Path de hallazgos | `/easm/{org_id}/issues` |

## Notas de API

La documentación pública de FortiRecon es limitada y algunos endpoints pueden variar por versión/tenant. Por eso los path templates son configurables. Referencias de integraciones públicas mencionan endpoints como `/easm/{org_id}/exposed_services`, `/easm/{org_id}/issues` y `/easm/{org_id}/assets/domains`.

## Pruebas

```bash
python test_connection.py
python validate_local.py
```

## Seguridad

- Nunca subas API Keys al repositorio.
- No imprimas headers Authorization.
- Trata datos de credenciales comprometidas como información sensible.
- Usa API Keys de solo lectura y mínimo privilegio.
