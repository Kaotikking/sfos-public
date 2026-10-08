"""Minimum, profile-neutral SFOS Stage-1 runtime."""

from .kernel import classify_request, respond

__all__ = ["classify_request", "respond"]
