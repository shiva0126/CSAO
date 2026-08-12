"""
===============================================================================
Cloud Security Assessment Framework (CSAF)

Configuration Loader

Author  : D Praveen
Version : 1.1

Features
--------
✔ Loads config.yaml
✔ Loads tools.yaml
✔ Validates configuration
✔ Creates required directories
✔ Supports environment variable overrides
✔ Provides global configuration object
✔ Enterprise-ready configuration loading
===============================================================================
"""

import os
from pathlib import Path
import yaml
from rich.console import Console

console = Console()
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class ConfigLoader:

    REQUIRED_SECTIONS = [
        "framework",
        "aws",
        "modules",
        "execution",
        "output",
        "reports",
        "logging",
        "risk_scoring"
    ]

    def __init__(self, config_path="config/config.yaml"):
        candidate = Path(config_path)
        if not candidate.is_absolute() and not candidate.exists():
            candidate = PROJECT_ROOT / config_path
        self.config_path = candidate
        self.config = {}

    ###########################################################################
    # Load YAML Files
    ###########################################################################

    def load(self):

        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found : {self.config_path}"
            )

        try:

            with open(self.config_path, "r", encoding="utf-8") as file:
                self.config = yaml.safe_load(file) or {}

        except Exception as e:

            raise RuntimeError(
                f"Unable to load configuration file : {e}"
            )

        #######################################################################
        # Load tools.yaml
        #######################################################################

        tools_file = self.config_path.parent / "tools.yaml"

        if tools_file.exists():

            try:

                with open(tools_file, "r", encoding="utf-8") as file:

                    tools = yaml.safe_load(file) or {}

                    self.config["tools"] = tools.get("tools", {})

            except Exception as e:

                console.print(
                    f"[yellow]Warning : Unable to load tools.yaml ({e})"
                )

                self.config["tools"] = {}

        else:

            console.print(
                "[yellow]Warning : tools.yaml not found"
            )

            self.config["tools"] = {}

        #######################################################################

        self.validate()

        self.apply_environment_variables()

        self.create_directories()

        return self.config

    ###########################################################################
    # Validate Configuration
    ###########################################################################

    def validate(self):

        missing = []

        for section in self.REQUIRED_SECTIONS:

            if section not in self.config:

                missing.append(section)

        if missing:

            raise ValueError(
                "Missing configuration sections : "
                + ", ".join(missing)
            )

        console.print(
            "[green]✓ Configuration Loaded Successfully"
        )

    ###########################################################################
    # Environment Variable Overrides
    ###########################################################################

    def apply_environment_variables(self):

        if os.getenv("AWS_PROFILE"):

            self.config["aws"]["profile"] = os.getenv("AWS_PROFILE")

        if os.getenv("AWS_REGION"):

            self.config["aws"]["regions"] = [
                os.getenv("AWS_REGION")
            ]

        if os.getenv("MAX_THREADS"):

            self.config["execution"]["max_threads"] = int(
                os.getenv("MAX_THREADS")
            )

        if os.getenv("LOG_LEVEL"):

            self.config["logging"]["level"] = os.getenv(
                "LOG_LEVEL"
            )

    ###########################################################################
    # Create Output Directories
    ###########################################################################

    def create_directories(self):

        output = self.config["output"]

        directories = [

            output["root_directory"],

            output["raw_directory"],

            output["discovery_directory"],

            output["normalized_directory"],

            output["checklist_directory"],

            output["mitre_directory"],

            output["crown_jewel_directory"],

            output.get("assessment_register_directory", "output/assessment_register"),

            output.get("threat_directory", "output/threats"),

            output["attack_path_directory"],

            output["risk_directory"],

            output["reports_directory"],

            self.config["logging"]["log_directory"],

            "cache",

            "inventory",

            "temp"

        ]

        for directory in directories:

            Path(directory).mkdir(
                parents=True,
                exist_ok=True
            )

    ###########################################################################
    # Display Configuration Summary
    ###########################################################################

    def summary(self):

        framework = self.config["framework"]

        aws = self.config["aws"]

        execution = self.config["execution"]

        console.print()

        console.rule("[bold cyan]Configuration Summary")

        console.print(
            f"[cyan]Framework        :[/] {framework['name']}"
        )

        console.print(
            f"[cyan]Version          :[/] {framework['version']}"
        )

        console.print(
            f"[cyan]AWS Profile      :[/] {aws['profile']}"
        )

        console.print(
            f"[cyan]Regions          :[/] {len(aws['regions'])}"
        )

        console.print(
            f"[cyan]Parallel         :[/] {execution['parallel_execution']}"
        )

        console.print(
            f"[cyan]Max Threads      :[/] {execution['max_threads']}"
        )

        console.print(
            f"[cyan]Registered Tools :[/] {len(self.config.get('tools', {}))}"
        )

        console.rule()

        console.print()


###############################################################################
# Helper Function
###############################################################################

def load_config():

    loader = ConfigLoader()

    config = loader.load()

    loader.summary()

    return config
