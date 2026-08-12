"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Deprecated alias.

AWSSessionManager has moved to core.providers.aws_provider.AWSProvider as
part of the CSAO cloud-provider abstraction (AWS today, GCP/Azure later
through the same interface). This alias exists only so nothing importing
the old name breaks; new code should import AWSProvider directly.
===============================================================================
"""

from core.providers.aws_provider import AWSProvider as AWSSessionManager  # noqa: F401
