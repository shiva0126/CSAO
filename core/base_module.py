"""
===============================================================================
Cloud Security Assessment Framework (CSAF)

Base Module

Author : D Praveen
Version : 1.0

Description
-----------
Base class inherited by every assessment module.

Features
--------
✔ Automatic Logging
✔ Execution Timer
✔ Error Handling
✔ Output Directory Creation
✔ Status Tracking
✔ Success/Failure Metrics
✔ Common Helper Functions
===============================================================================
"""

from abc import ABC, abstractmethod
import os
from pathlib import Path
import subprocess
import time

from rich.console import Console
from rich.panel import Panel

from core.file_utils import atomic_write_json
from loguru import logger

console = Console()


class BaseModule(ABC):

    ###########################################################################
    # Constructor
    ###########################################################################

    def __init__(self, config):

        self.config = config

        self.name = self.__class__.__name__

        self.start_time = None

        self.end_time = None

        self.execution_time = 0

        self.status = "Pending"

        self.output_directory = None
        self.command_timeout = int(
            config.get("execution", {}).get("timeout", 3600) or 3600
        )
        self.command_retries = int(
            config.get("execution", {}).get("retry_count", 1) or 1
        )
        self.cancel_check = config.get("_cancel_check")
        self.command_env = {**os.environ, **dict(config.get("_aws_cli_env", {}) or {})}

    ###########################################################################
    # Banner
    ###########################################################################

    def before_run(self):

        self.start_time = time.time()

        self.status = "Running"

        console.print(
            Panel.fit(
                f"Starting {self.name}",
                border_style="cyan"
            )
        )

        logger.info(f"{self.name} Started")

    ###########################################################################
    # Finish
    ###########################################################################

    def after_run(self):

        self.end_time = time.time()

        self.execution_time = round(
            self.end_time - self.start_time,
            2
        )

        self.status = "Completed"

        logger.success(
            f"{self.name} Completed ({self.execution_time} sec)"
        )

        console.print(
            f"[green]{self.name} Completed in "
            f"{self.execution_time} seconds[/green]"
        )

    ###########################################################################
    # Exception Handler
    ###########################################################################

    def handle_exception(self, exception):

        self.status = "Failed"

        logger.exception(exception)

        console.print(
            f"[red]{self.name} Failed[/red]"
        )

    ###########################################################################
    # Output Folder
    ###########################################################################

    def create_output_directory(self, module):

        directory = Path("output/raw") / module

        directory.mkdir(
            parents=True,
            exist_ok=True
        )

        self.output_directory = directory

        return directory

    ###########################################################################
    # Save JSON
    ###########################################################################

    def save_json(self, filename, data):
        file = self.output_directory / filename
        atomic_write_json(file, data)

        logger.info(f"Saved {filename}")

    ###########################################################################
    # Execute Command
    ###########################################################################

    def execute_command(self, command, *, env=None, timeout=None):
        logger.info("Executing : " + " ".join(command))
        effective_timeout = int(timeout or self.command_timeout)
        attempts = max(1, self.command_retries)
        last_error = None
        for attempt in range(1, attempts + 1):
            if callable(self.cancel_check) and self.cancel_check():
                raise RuntimeError(f"{self.name} cancelled before command start")
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env or self.command_env,
            )
            try:
                deadline = time.time() + effective_timeout
                while True:
                    if callable(self.cancel_check) and self.cancel_check():
                        process.kill()
                        process.communicate()
                        raise RuntimeError(
                            f"{self.name} cancelled during command execution"
                        )
                    if process.poll() is not None:
                        stdout, stderr = process.communicate()
                        break
                    if time.time() >= deadline:
                        raise subprocess.TimeoutExpired(command, effective_timeout)
                    time.sleep(0.5)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                stdout, stderr = process.communicate()
                last_error = RuntimeError(
                    f"{self.name} command timed out after {effective_timeout}s: {' '.join(command)}"
                )
                logger.error(stderr.strip() or str(last_error))
            else:
                if process.returncode == 0:
                    if stdout.strip():
                        logger.debug(stdout.strip())
                    if stderr.strip():
                        logger.warning(stderr.strip())
                    return stdout
                last_error = subprocess.CalledProcessError(
                    process.returncode,
                    command,
                    output=stdout,
                    stderr=stderr,
                )
                logger.error(stderr.strip() or stdout.strip() or str(last_error))
            if attempt < attempts:
                logger.warning(
                    f"{self.name} retrying command ({attempt}/{attempts}) after failure."
                )
                time.sleep(min(attempt, 5))
        if last_error:
            raise last_error
        raise RuntimeError(f"{self.name} command failed without error details")

    ###########################################################################
    # Module Life Cycle
    ###########################################################################

    @abstractmethod
    def execute(self):
        """
        Every child class implements this.
        """
        pass

    ###########################################################################
    # Common Run Method
    ###########################################################################

    def run(self):

        try:

            self.before_run()

            self.execute()

            self.after_run()

        except Exception as e:

            self.handle_exception(e)
