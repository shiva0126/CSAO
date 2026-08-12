"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Cloud Provider Registry

Purpose
-------
Maps a `platform` config value to a CloudProvider implementation. AWS is the
only implemented provider today; GCP and Azure are registered as explicit
"not yet implemented" placeholders so the orchestrator's provider-selection
logic never has to change when they're added - only this file does.
===============================================================================
"""

from core.providers.aws_provider import AWSProvider


class UnimplementedProvider:
    """
    Placeholder for platforms that are planned but not yet built.
    Raised lazily (on instantiation) rather than hidden, so a misconfigured
    `platform:` value fails loudly instead of silently falling back to AWS.
    """

    platform_name = "unimplemented"

    def __init__(self, config):

        raise NotImplementedError(
            "This cloud provider is not yet implemented. "
            "AWS is the only supported platform today."
        )


PROVIDERS = {

    "aws": AWSProvider,

    "gcp": UnimplementedProvider,

    "azure": UnimplementedProvider,

}


def get_provider(config):

    platform = config.get("platform", "aws")

    provider_class = PROVIDERS.get(platform)

    if provider_class is None:

        raise ValueError(
            f"Unknown platform '{platform}'. "
            f"Supported platforms: {', '.join(PROVIDERS.keys())}"
        )

    return provider_class(config)
