"""Vérification d'enveloppes de capture attestée — spécification ac/0.1."""

from .errors import VerificationError
from .model import Grade, Level, Property, VerificationResult
from .verifier import Verifier

__version__ = "0.1.0.dev0"
__all__ = [
    "Grade",
    "Level",
    "Property",
    "VerificationError",
    "VerificationResult",
    "Verifier",
]
