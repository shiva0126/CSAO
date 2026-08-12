"""
===============================================================================
Cloud Security Assessment Framework (CSAF)

Dependency Checker v2.2

Responsibilities:

✔ Detect Operating System
✔ Verify Python Version
✔ Load tools.yaml
✔ Verify Tools
✔ Auto Install Missing Tools
✔ Verify Tool Versions
✔ Verify Python Packages
✔ Verify AWS Credentials
✔ Return Structured Dependency Status

===============================================================================
"""


import os
import sys
import socket
import shutil
import subprocess

import yaml

from rich.console import Console
from rich.table import Table

from core.installer import Installer


console = Console()


class DependencyChecker:


    def __init__(self, config=None):

        self.config = config


        self.base_dir = os.path.dirname(
            os.path.dirname(
                os.path.abspath(__file__)
            )
        )


        self.tools_file = os.path.join(
            self.base_dir,
            "config",
            "tools.yaml"
        )


        self.installer = Installer()


        self.tools = self.load_tools()


        self.required_packages = [

            "boto3",
            "botocore",
            "yaml",
            "pandas",
            "jinja2",
            "requests",
            "rich",
            "plotly",
            "networkx",
            "loguru"

        ]



    def load_tools(self):

        with open(self.tools_file) as file:

            data = yaml.safe_load(file)


        return data.get(
            "tools",
            {}
        )



    def detect_os(self):

        try:

            with open("/etc/os-release") as f:

                for line in f:

                    if line.startswith("PRETTY_NAME"):

                        os_name = (
                            line.split("=")[1]
                            .replace('"',"")
                            .strip()
                        )

                        console.print(
                            f"[cyan]Operating System : {os_name}"
                        )

                        return os_name


        except Exception:

            return "Unknown"



    def internet(self):

        console.print(
            "Checking Internet Connectivity..."
        )

        try:

            socket.create_connection(
                ("8.8.8.8",53),
                timeout=3
            )


            console.print(
                "[green]Internet Available"
            )

            return True


        except Exception:


            console.print(
                "[red]Internet Not Available"
            )

            return False



    def python_version(self):

        version=sys.version_info


        console.print(
            f"[cyan]Python Version : {version.major}.{version.minor}.{version.micro}"
        )


        return (
            version.major >= 3
        )



    def check_tools(self):


        table = Table(
            title="Tool Dependency Status"
        )


        table.add_column("Tool")
        table.add_column("Status")
        table.add_column("Version")


        failed=[]


        for tool,details in self.tools.items():


            command = details.get(
                "command",
                tool
            )


            path = self.resolve_tool_path(command)


            if path:


                version = self.installer.get_version(
                    command
                )


                table.add_row(

                    tool,
                    "[green]Installed",
                    version

                )


            else:


                console.print(
                    f"[yellow]Missing {tool}"
                )
                table.add_row(
                    tool,
                    "[yellow]Missing",
                    "not installed"
                )
                failed.append(tool)


        console.print(table)


        return failed

    def resolve_tool_path(self, command):

        if command == "python3":
            return sys.executable

        if command == "pip3":
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "--version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )
                return f"{sys.executable} -m pip"
            except Exception:
                return shutil.which(command)

        return shutil.which(command)



    def check_python_packages(self):


        console.print(
            "\n[cyan]Checking Python Packages..."
        )


        missing=[]


        for package in self.required_packages:


            try:

                __import__(package)

                console.print(
                    f"[green]✓ {package}"
                )


            except Exception:


                console.print(
                    f"[red]✗ {package}"
                )


                missing.append(package)



        return missing



    def aws_credentials(self):


        console.print(
            "\n[cyan]Checking AWS Credentials..."
        )


        try:


            subprocess.run(

                [
                    "aws",
                    "sts",
                    "get-caller-identity"
                ],

                stdout=subprocess.PIPE,

                stderr=subprocess.PIPE,

                check=True

            )


            console.print(
                "[green]AWS Credentials Valid"
            )


            return True



        except Exception:


            console.print(
                "[yellow]AWS Credentials Not Configured"
            )


            return False



    def run(self):


        console.rule(
            "[bold cyan]Dependency Checker v2.2"
        )


        result={

            "status":True,

            "failed_tools":[],

            "missing_packages":[],

            "aws_credentials":False

        }



        self.detect_os()


        if not self.internet():

            result["status"]=False



        if not self.python_version():

            result["status"]=False



        result["failed_tools"]=self.check_tools()



        result["missing_packages"]=self.check_python_packages()



        result["aws_credentials"]=self.aws_credentials()



        if result["failed_tools"]:

            result["status"]=False



        console.rule(
            "[bold green]Dependency Check Completed"
        )


        if result["status"]:

            console.print(
                "[green]Environment READY"
            )


        return result



if __name__=="__main__":


    checker=DependencyChecker()

    print(
        checker.run()
    )
