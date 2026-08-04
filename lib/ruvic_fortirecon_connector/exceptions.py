"""Excepciones propias del conector FortiRecon."""

class FortireconConnectorError(Exception):
    """Error base del conector FortiRecon."""

class FortireconConfigError(FortireconConnectorError):
    """Falta configuración requerida o algún valor de configuración es inválido."""

class FortireconAuthError(FortireconConnectorError):
    """API key FortiRecon inválida, expirada o con permisos insuficientes."""

class FortireconNetworkError(FortireconConnectorError):
    """Error de red, DNS, SSL, timeout o API FortiRecon no alcanzable."""

class FortireconDataError(FortireconConnectorError):
    """Solicitud inválida, recurso inexistente o respuesta inesperada de FortiRecon."""

class FortireconSecurityError(FortireconConnectorError):
    """Operación bloqueada por reglas de seguridad del conector."""
