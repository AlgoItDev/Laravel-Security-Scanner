"""
Check registry — central list of all available checks.
New checks only need to be added here; the ScannerService discovers them automatically.
"""
from app.services.checks.env_exposed import EnvExposedCheck
from app.services.checks.debug_mode import DebugModeCheck
from app.services.checks.security_headers import SecurityHeadersCheck
from app.services.checks.sensitive_files import SensitiveFilesCheck
from app.services.checks.insecure_config import InsecureConfigCheck
from app.services.checks.laravel_version import LaravelVersionCheck
from app.services.checks.telescope_exposed import TelescopeExposedCheck
from app.services.checks.debugbar_exposed import DebugbarExposedCheck
from app.services.checks.mix_manifest_exposed import MixManifestExposedCheck
from app.services.checks.horizon_exposed import HorizonExposedCheck
from app.services.checks.nova_exposed import NovaExposedCheck
from app.services.checks.csrf_protection import CSRFProtectionCheck
from app.services.checks.session_security import SessionSecurityCheck
from app.services.checks.rate_limiting import RateLimitingCheck
from app.services.checks.http_methods import HTTPMethodsCheck
from app.services.checks.composer_lock_cve import ComposerLockCVEScanCheck
from app.services.checks.sql_injection_blind import SQLInjectionBlindCheck
from app.services.checks.xss_reflected import XSSReflectedCheck
from app.services.checks.jwt_analysis import JWTAnalysisCheck
from app.services.checks.cors_misconfig import CORSMisconfigCheck
from app.services.checks.open_redirect import OpenRedirectCheck
from app.services.checks.subdomain_enum import SubdomainEnumCheck
from app.services.checks.base import BaseCheck


# Ordered list — critical checks run first
ALL_CHECKS: list[type[BaseCheck]] = [
    EnvExposedCheck,
    DebugModeCheck,
    SensitiveFilesCheck,
    SecurityHeadersCheck,
    InsecureConfigCheck,
    LaravelVersionCheck,
    TelescopeExposedCheck,
    DebugbarExposedCheck,
    MixManifestExposedCheck,
    HorizonExposedCheck,
    NovaExposedCheck,
    CSRFProtectionCheck,
    SessionSecurityCheck,
    RateLimitingCheck,
    HTTPMethodsCheck,
    ComposerLockCVEScanCheck,
    SQLInjectionBlindCheck,
    XSSReflectedCheck,
    JWTAnalysisCheck,
    CORSMisconfigCheck,
    OpenRedirectCheck,
    SubdomainEnumCheck,
]

__all__ = ["ALL_CHECKS", "BaseCheck"]
