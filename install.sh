#!/bin/bash

###############################################################################
# Cloud Security Assessment Framework
# Auto Dependency Installer
###############################################################################

set -e

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

print_header() {
    echo -e "${BLUE}"
    echo "========================================================"
    echo " Cloud Security Assessment Framework Installer"
    echo "========================================================"
    echo -e "${NC}"
}

success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

error() {
    echo -e "${RED}[✗] $1${NC}"
}

install_package() {

    PACKAGE=$1

    if command -v $PACKAGE &>/dev/null
    then
        success "$PACKAGE already installed."
    else
        warning "$PACKAGE not found."

        sudo apt-get install -y $PACKAGE

        success "$PACKAGE installed."
    fi
}

print_header

sudo apt update

###############################################################################
# Basic Packages
###############################################################################

install_package git
install_package curl
install_package wget
install_package unzip
install_package jq
install_package python3
install_package python3-pip
install_package python3-venv

###############################################################################
# AWS CLI
###############################################################################

if ! command -v aws &>/dev/null
then
    warning "Installing AWS CLI..."

    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip

    unzip awscliv2.zip

    sudo ./aws/install

    rm -rf aws awscliv2.zip

    success "AWS CLI Installed"
else
    success "AWS CLI Already Installed"
fi

###############################################################################
# Prowler
###############################################################################

if ! command -v prowler &>/dev/null
then
    warning "Installing Prowler..."

    pip3 install prowler

    success "Prowler Installed"
else
    success "Prowler Already Installed"
fi

###############################################################################
# Cloudsplaining
###############################################################################

if ! command -v cloudsplaining &>/dev/null
then
    warning "Installing Cloudsplaining..."

    pip3 install cloudsplaining

    success "Cloudsplaining Installed"
else
    success "Cloudsplaining Already Installed"
fi

###############################################################################
# Steampipe
###############################################################################

if ! command -v steampipe &>/dev/null
then
    warning "Installing Steampipe..."

    sudo /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"

    success "Steampipe Installed"
else
    success "Steampipe Already Installed"
fi

###############################################################################
# Cartography
###############################################################################

if ! command -v cartography &>/dev/null
then
    warning "Installing Cartography..."

    pip3 install cartography

    success "Cartography Installed"
else
    success "Cartography Already Installed"
fi

###############################################################################
# Neo4j
###############################################################################

if ! command -v neo4j &>/dev/null
then
    warning "Neo4j not detected."
    warning "Please install Neo4j manually if Cartography graph mode is required."
else
    success "Neo4j Installed"
fi

###############################################################################
# Python Libraries
###############################################################################

pip3 install \
boto3 \
botocore \
pandas \
jinja2 \
rich \
pyyaml \
requests \
networkx \
matplotlib \
plotly \
tabulate \
weasyprint \
loguru \
tqdm

###############################################################################
# AWS CLI Check
###############################################################################

echo
echo "Checking AWS Credentials..."

if aws sts get-caller-identity >/dev/null 2>&1
then
    success "AWS Credentials Valid."
else
    warning "AWS Credentials Not Configured."
    warning "Run:"
    echo ""
    echo "aws configure"
    echo ""
fi

###############################################################################
# Create Project Structure
###############################################################################

mkdir -p logs
mkdir -p output/raw
mkdir -p output/normalized
mkdir -p output/correlated
mkdir -p output/reports

success "Directories Created"

###############################################################################
# Finish
###############################################################################

echo
echo "====================================================="
echo "Installation Completed Successfully"
echo "====================================================="

echo

echo "Next Step"

echo "./main.py"

echo
