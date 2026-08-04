"""Prueba de conexión estándar del conector FortiRecon."""
from __future__ import annotations

def test_connection() -> tuple[bool, str]:
    """Prueba API key y acceso consultando hallazgos FortiRecon."""
    try:
        from ruvic_fortirecon_connector import FortireconAuthError, FortireconClient, FortireconConfigError, FortireconDataError, FortireconNetworkError, FortireconSecurityError
    except ImportError:
        return False, "La librería ruvic-fortirecon-connector no está instalada. Instala con: pip install git+https://github.com/tu-org/conector-fortirecon.git#subdirectory=lib"
    try:
        client = FortireconClient(); client.ping()
    except ValueError as exc:
        return False, str(exc)
    except FortireconConfigError as exc:
        return False, f"Configuración inválida: {exc}"
    except FortireconAuthError as exc:
        return False, f"Autenticación o permisos FortiRecon inválidos: {exc}"
    except FortireconNetworkError as exc:
        return False, f"Error de red hacia FortiRecon: {exc}"
    except FortireconSecurityError as exc:
        return False, f"Bloqueo de seguridad: {exc}"
    except FortireconDataError as exc:
        return False, f"FortiRecon rechazó la solicitud: {exc}"
    except Exception as exc:
        return False, f"Error inesperado probando FortiRecon: {exc}"
    return True, f"Conexión exitosa a FortiRecon para organización {client.config.org_id}."

if __name__ == "__main__":
    ok, message = test_connection(); print(f"{'OK' if ok else 'FALLO'}: {message}"); raise SystemExit(0 if ok else 1)
