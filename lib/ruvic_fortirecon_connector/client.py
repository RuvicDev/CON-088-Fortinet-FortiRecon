"""Cliente para Fortinet FortiRecon ASM.

Capacidades:
- get_exposed_assets(): consultar activos/servicios expuestos.
- get_risks(): consultar riesgos de exposición.
- get_compromised_credentials(): consultar credenciales comprometidas/leaked credentials.
- get_findings(): consultar hallazgos/issues ASM.

FortiRecon usa API Key en header Authorization. Algunos tenants/versiones exponen
rutas diferentes; por eso las plantillas de path son configurables por env vars.
"""
from __future__ import annotations
from typing import Any
import requests
from requests import Response
from .config import FortireconConfig
from .exceptions import FortireconAuthError, FortireconDataError, FortireconNetworkError
from .logging_utils import get_logger

class FortireconClient:
    """Cliente para consultar superficie de ataque externa en FortiRecon.

    Args:
        config: configuración opcional. Si se omite, lee RUVIC_FORTIRECON_*.

    Ejemplo:
        >>> client = FortireconClient()
        >>> client.get_exposed_assets(limit=10)
        [{'asset': 'example.com', 'type': 'domain'}]
    """
    def __init__(self, config: FortireconConfig | None = None) -> None:
        self.config = config or FortireconConfig.from_env()
        self._logger = get_logger()
        self._session = requests.Session()

    def _path(self, template: str) -> str:
        path = template.format(org_id=self.config.org_id)
        return path if path.startswith("/") else f"/{path}"

    def _headers(self) -> dict[str, str]:
        scheme = f"{self.config.auth_scheme} " if self.config.auth_scheme else ""
        return {"Authorization": f"{scheme}{self.config.api_key}".strip(), "Accept": "application/json", "Content-Type": "application/json"}

    def _handle_response(self, response: Response) -> Any:
        if response.status_code in {401, 403}:
            raise FortireconAuthError(f"FortiRecon rechazó autenticación o permisos ({response.status_code}). Revisa API key, organización y permisos.")
        if response.status_code == 404:
            raise FortireconDataError("Endpoint o recurso FortiRecon no encontrado. Verifica URL base, org_id y path template configurado.")
        if response.status_code == 429:
            raise FortireconDataError("FortiRecon aplicó rate limiting (429). Reduce frecuencia o tamaño de consulta.")
        if response.status_code >= 400:
            raise FortireconDataError(f"FortiRecon retornó HTTP {response.status_code}: {response.text[:500]}")
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise FortireconDataError("FortiRecon respondió contenido no JSON cuando se esperaba JSON.") from exc

    def _request(self, path: str, params: dict[str, Any] | None = None) -> Any:
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        url = self.config.base_url + path
        try:
            response = self._session.get(url, headers=self._headers(), params=clean_params, timeout=self.config.timeout, verify=self.config.verify_ssl)
        except requests.exceptions.SSLError as exc:
            raise FortireconNetworkError("Error SSL conectando con FortiRecon. Verifica certificado o RUVIC_FORTIRECON_VERIFY_SSL.") from exc
        except requests.exceptions.Timeout as exc:
            raise FortireconNetworkError(f"Timeout conectando con FortiRecon ({self.config.timeout}s).") from exc
        except requests.exceptions.RequestException as exc:
            raise FortireconNetworkError(f"No se pudo conectar con FortiRecon: {exc}.") from exc
        return self._handle_response(response)

    def _extract_items(self, data: Any, limit: int | None) -> list[dict[str, Any]]:
        if isinstance(data, dict):
            for key in ("data", "items", "results", "assets", "issues", "findings", "credentials", "records"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
        if not isinstance(data, list):
            raise FortireconDataError("La respuesta FortiRecon no tiene formato de lista esperado.")
        effective_limit = self.config.max_results if limit is None else int(limit)
        resolved_limit = max(1, min(effective_limit, self.config.max_results))
        return [dict(item) if isinstance(item, dict) else {"value": item} for item in data[:resolved_limit]]

    def ping(self) -> bool:
        """Verifica conexión consultando un hallazgo/issue como máximo.

        Returns:
            True si FortiRecon responde correctamente.
        Ejemplo:
            >>> client.ping()
            True
        """
        self.get_findings(limit=1)
        self._logger.info("Ping exitoso a FortiRecon")
        return True

    def get_exposed_assets(self, limit: int | None = None, asset_type: str | None = None) -> list[dict[str, Any]]:
        """Consulta activos o servicios expuestos en FortiRecon ASM.

        Args:
            limit: máximo de resultados a retornar.
            asset_type: filtro opcional si la API lo soporta.
        Returns:
            Lista de activos expuestos.
        Ejemplo:
            >>> client.get_exposed_assets(limit=20)
            [{'host': 'vpn.example.com', 'port': 443}]
        """
        effective_limit = self.config.max_results if limit is None else int(limit)
        resolved_limit = max(1, min(effective_limit, self.config.max_results))
        data = self._request(self._path(self.config.exposed_assets_path_template), {"type": asset_type, "limit": resolved_limit})
        rows = self._extract_items(data, resolved_limit)
        self._logger.info("Consultados %d activos expuestos FortiRecon", len(rows))
        return rows

    def get_risks(self, severity: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        """Consulta riesgos de exposición en FortiRecon.

        Nota: por defecto usa el mismo endpoint que get_findings()
        (`/easm/{org_id}/issues`). Salvo que el tenant tenga configurado
        RUVIC_FORTIRECON_RISKS_PATH_TEMPLATE con una ruta distinta a
        RUVIC_FORTIRECON_FINDINGS_PATH_TEMPLATE, ambos métodos devuelven
        los mismos datos base; solo se diferencian por los filtros que
        aplica el cliente (severity aquí vs. severity+status en
        get_findings()).

        Args:
            severity: severidad opcional si la API lo soporta.
            limit: máximo de resultados.
        Returns:
            Lista de riesgos.
        Ejemplo:
            >>> client.get_risks(severity="high", limit=10)
            [{'severity': 'high', 'title': 'Exposed admin service'}]
        """
        effective_limit = self.config.max_results if limit is None else int(limit)
        resolved_limit = max(1, min(effective_limit, self.config.max_results))
        data = self._request(self._path(self.config.risks_path_template), {"severity": severity, "limit": resolved_limit})
        rows = self._extract_items(data, resolved_limit)
        self._logger.info("Consultados %d riesgos FortiRecon", len(rows))
        return rows

    def get_compromised_credentials(self, domain: str | None = None, start_date: str | None = None, end_date: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        """Consulta credenciales comprometidas/leaked credentials.

        Args:
            domain: dominio opcional para filtrar.
            start_date: fecha inicial opcional.
            end_date: fecha final opcional.
            limit: máximo de resultados.
        Returns:
            Lista de credenciales comprometidas o reportes asociados.
        Ejemplo:
            >>> client.get_compromised_credentials(domain="example.com", limit=10)
            [{'email': 'usuario@example.com', 'source': 'breach'}]
        """
        effective_limit = self.config.max_results if limit is None else int(limit)
        resolved_limit = max(1, min(effective_limit, self.config.max_results))
        data = self._request(self._path(self.config.credentials_path_template), {"domain": domain, "from": start_date, "to": end_date, "limit": resolved_limit})
        rows = self._extract_items(data, resolved_limit)
        self._logger.info("Consultados %d registros de credenciales FortiRecon", len(rows))
        return rows

    def get_findings(self, severity: str | None = None, status: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        """Consulta hallazgos/issues de FortiRecon ASM.

        Nota: por defecto usa el mismo endpoint que get_risks()
        (`/easm/{org_id}/issues`). Salvo que el tenant tenga configurado
        RUVIC_FORTIRECON_FINDINGS_PATH_TEMPLATE con una ruta distinta a
        RUVIC_FORTIRECON_RISKS_PATH_TEMPLATE, ambos métodos devuelven
        los mismos datos base; solo se diferencian por los filtros que
        aplica el cliente (severity+status aquí vs. severity en
        get_risks()).

        Args:
            severity: severidad opcional.
            status: estado opcional.
            limit: máximo de resultados.
        Returns:
            Lista de hallazgos.
        Ejemplo:
            >>> client.get_findings(severity="critical", status="active")
            [{'id': '...', 'severity': 'critical'}]
        """
        effective_limit = self.config.max_results if limit is None else int(limit)
        resolved_limit = max(1, min(effective_limit, self.config.max_results))
        data = self._request(self._path(self.config.findings_path_template), {"severity": severity, "status": status, "limit": resolved_limit})
        rows = self._extract_items(data, resolved_limit)
        self._logger.info("Consultados %d hallazgos FortiRecon", len(rows))
        return rows
