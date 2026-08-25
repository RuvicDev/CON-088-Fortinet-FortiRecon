"""Configuración del conector leída desde variables de entorno.

Prefijo: RUVIC_FORTIRECON_
"""
from __future__ import annotations
import os
from dataclasses import dataclass
from .exceptions import FortireconConfigError

ENV_PREFIX = "RUVIC_FORTIRECON_"

def _to_bool(value: str, default: bool) -> bool:
    raw = (value or "").strip().lower()
    if raw == "":
        return default
    if raw in {"true", "1", "yes", "y", "on"}:
        return True
    if raw in {"false", "0", "no", "n", "off"}:
        return False
    raise FortireconConfigError("Configuración inválida: VERIFY_SSL debe ser true/false.")

@dataclass(frozen=True)
class FortireconConfig:
    """Parámetros para autenticar y consultar la API FortiRecon."""
    base_url: str
    api_key: str
    org_id: str
    auth_scheme: str = "Bearer"
    verify_ssl: bool = True
    timeout: int = 20
    max_results: int = 100
    exposed_assets_path_template: str = "/easm/{org_id}/exposed_services"
    risks_path_template: str = "/easm/{org_id}/issues"
    credentials_path_template: str = "/asm/{org_id}/leaked_credentials"
    findings_path_template: str = "/easm/{org_id}/issues"

    @classmethod
    def from_env(cls) -> "FortireconConfig":
        """Construye la configuración desde variables RUVIC_FORTIRECON_*.

        Raises:
            ValueError: si faltan variables requeridas.
            FortireconConfigError: si un valor opcional es inválido.

        Ejemplo:
            >>> config = FortireconConfig.from_env()
            >>> config.org_id
            'mi-organizacion'
        """
        base_url = os.environ.get(f"{ENV_PREFIX}BASE_URL", "").strip().rstrip("/")
        api_key = os.environ.get(f"{ENV_PREFIX}API_KEY", "").strip()
        org_id = os.environ.get(f"{ENV_PREFIX}ORG_ID", "").strip()
        missing = [n for n, v in ((f"{ENV_PREFIX}BASE_URL", base_url), (f"{ENV_PREFIX}API_KEY", api_key), (f"{ENV_PREFIX}ORG_ID", org_id)) if not v]
        if missing:
            raise ValueError("Faltan variables de entorno del conector fortirecon: " + ", ".join(missing) + ". Configura el conector en Settings → Conectores.")
        if not base_url.startswith("https://"):
            raise FortireconConfigError("RUVIC_FORTIRECON_BASE_URL debe iniciar por https://.")
        try:
            timeout = int(os.environ.get(f"{ENV_PREFIX}TIMEOUT", "20").strip() or "20")
            max_results = int(os.environ.get(f"{ENV_PREFIX}MAX_RESULTS", "100").strip() or "100")
            verify_ssl = _to_bool(os.environ.get(f"{ENV_PREFIX}VERIFY_SSL", "true"), default=True)
        except ValueError as exc:
            raise FortireconConfigError("RUVIC_FORTIRECON_TIMEOUT y RUVIC_FORTIRECON_MAX_RESULTS deben ser enteros.") from exc
        if timeout <= 0 or timeout > 120:
            raise FortireconConfigError("RUVIC_FORTIRECON_TIMEOUT debe estar entre 1 y 120 segundos.")
        if max_results <= 0 or max_results > 1000:
            raise FortireconConfigError("RUVIC_FORTIRECON_MAX_RESULTS debe estar entre 1 y 1000.")
        auth_scheme_raw = os.environ.get(f"{ENV_PREFIX}AUTH_SCHEME")
        auth_scheme = "Bearer" if auth_scheme_raw is None else auth_scheme_raw.strip()
        return cls(
            base_url=base_url,
            api_key=api_key,
            org_id=org_id,
            auth_scheme=auth_scheme,
            verify_ssl=verify_ssl,
            timeout=timeout,
            max_results=max_results,
            exposed_assets_path_template=os.environ.get(f"{ENV_PREFIX}EXPOSED_ASSETS_PATH_TEMPLATE", "").strip() or "/easm/{org_id}/exposed_services",
            risks_path_template=os.environ.get(f"{ENV_PREFIX}RISKS_PATH_TEMPLATE", "").strip() or "/easm/{org_id}/issues",
            credentials_path_template=os.environ.get(f"{ENV_PREFIX}CREDENTIALS_PATH_TEMPLATE", "").strip() or "/asm/{org_id}/leaked_credentials",
            findings_path_template=os.environ.get(f"{ENV_PREFIX}FINDINGS_PATH_TEMPLATE", "").strip() or "/easm/{org_id}/issues",
        )
