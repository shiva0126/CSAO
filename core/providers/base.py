"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Cloud Provider Base Interface

Purpose
-------
Every cloud platform the orchestrator supports (AWS today, GCP/Azure planned)
implements this interface. The rest of the framework (Discovery Engine,
Evidence Collection Engine, modules) talks to `CloudProvider`, never to a
platform SDK directly, so adding GCP/Azure later does not require touching
orchestration code - only a new provider implementation + registry entry.

Security Model
--------------
READ ONLY. Implementations must only ever call read/describe/list/get APIs.
===============================================================================
"""

from abc import ABC, abstractmethod


class CloudProvider(ABC):

    platform_name = "unknown"

    def __init__(self, config):

        self.config = config

        self.available = False

    ###########################################################################
    # Authentication / session establishment
    ###########################################################################

    @abstractmethod
    def authenticate(self):
        """
        Establish a session / validate credentials.
        Returns True on success, False otherwise. Must never raise for
        expected failure modes (missing creds, invalid profile) - those are
        reported through the return value so the orchestrator can degrade
        gracefully, matching existing framework behavior.
        """
        raise NotImplementedError

    ###########################################################################
    # Identity
    ###########################################################################

    @abstractmethod
    def account_id(self):
        """Primary account / project / subscription identifier."""
        raise NotImplementedError

    @abstractmethod
    def regions(self):
        """List of regions/locations in scope for this assessment."""
        raise NotImplementedError

    ###########################################################################
    # Client factory
    ###########################################################################

    @abstractmethod
    def client(self, service, region=None):
        """Return a read-only capable SDK client for the given service."""
        raise NotImplementedError

    ###########################################################################
    # Status
    ###########################################################################

    def status(self):

        return {
            "platform": self.platform_name,
            "available": self.available,
            "account": self.account_id() if self.available else None,
            "regions": self.regions() if self.available else [],
        }
