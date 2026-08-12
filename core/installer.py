#!/usr/bin/env python3

"""
Cloud Security Assessment Framework

Enterprise Installer Engine v1.0

Responsibilities:
- Read tool installation configuration
- Install missing dependencies
- Verify installation
- Return installation status
"""

import os
import subprocess
import shutil
import sys
import yaml


class Installer:

    def __init__(self):

        self.base_dir = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )

        self.config_file = os.path.join(
            self.base_dir,
            "config",
            "tools.yaml"
        )

        self.tools = self.load_tools()


    def load_tools(self):

        if not os.path.exists(self.config_file):
            raise FileNotFoundError(
                "tools.yaml not found"
            )

        with open(self.config_file) as file:
            data = yaml.safe_load(file)

        return data.get("tools", {})


    def install(self, tool):

        if tool not in self.tools:
            return {
                "tool": tool,
                "status": "unknown"
            }


        config = self.tools[tool]

        installer = config.get(
            "installer",
            {}
        )

        method = installer.get(
            "type"
        )


        print(f"[+] Installing {tool}")
        print(f"[+] Method: {method}")


        if method == "apt":

            package = installer.get(
                "package",
                tool
            )

            return self.apt_install(package)


        elif method == "pip":

            package = installer.get(
                "package",
                tool
            )

            return self.pip_install(package)


        elif method == "script":

            url = installer.get(
                "url"
            )

            return self.script_install(url)


        elif method == "awscli":

            return self.aws_install()


        else:

            return {
                "tool": tool,
                "status": "unsupported installer"
            }



    def apt_install(self, package):

        cmd = [
            "sudo",
            "apt-get",
            "install",
            "-y",
            package
        ]

        return self.run_command(
            cmd,
            package
        )



    def pip_install(self, package):

        cmd = [
            sys.executable,
            "-m",
            "pip",
            "install",
            package
        ]

        return self.run_command(
            cmd,
            package
        )



    def aws_install(self):

        cmd = [
            "bash",
            "-c",
            "curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip && unzip awscliv2.zip && sudo ./aws/install"
        ]

        return self.run_command(
            cmd,
            "aws"
        )



    def script_install(self, url):

        cmd = [
            "bash",
            "-c",
            f"curl -fsSL {url} | sh"
        ]

        return self.run_command(
            cmd,
            url
        )



    def run_command(self, cmd, name):

        try:

            subprocess.run(
                cmd,
                check=True
            )

            return {
                "tool": name,
                "status": "installed"
            }


        except (subprocess.CalledProcessError, FileNotFoundError, PermissionError, OSError):

            return {
                "tool": name,
                "status": "failed"
            }



    def verify(self, tool):

        if tool == "python3":
            path = sys.executable
        elif tool == "pip3":
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "--version"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                path = f"{sys.executable} -m pip"
            except Exception:
                path = shutil.which(tool)
        else:
            path = shutil.which(tool)


        if path:

            version = self.get_version(tool)

            return {
                "tool": tool,
                "installed": True,
                "path": path,
                "version": version
            }


        return {
            "tool": tool,
            "installed": False
        }



    def get_version(self, tool):

        try:
            if tool == "python3":
                result = subprocess.run(
                    [sys.executable, "--version"],
                    capture_output=True,
                    text=True
                )
                return result.stdout.strip() or result.stderr.strip()

            if tool == "pip3":
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "--version"],
                    capture_output=True,
                    text=True
                )
                return result.stdout.strip() or result.stderr.strip()

            result = subprocess.run(
                [
                    tool,
                    "--version"
                ],
                capture_output=True,
                text=True
            )

            return result.stdout.strip() or result.stderr.strip()


        except Exception:

            return "unknown"



if __name__ == "__main__":

    installer = Installer()

    print(
        "Enterprise Installer Engine v1.0 Ready"
    )
