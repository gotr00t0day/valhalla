#!/bin/bash

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Go is not installed. Installing..."
    # Install Go
    # Add your installation commands here
fi

# Check if Nuclei is installed
if ! command -v nuclei &> /dev/null; then
    echo "Nuclei is not installed. Installing..."
    # Install Nuclei
    # Add your installation commands here
fi

# Change directory to root
cd /

# Clone Nuclei templates repository
if [ ! -d nuclei-templates ]; then
    echo "Cloning Nuclei templates repository..."
    git clone https://github.com/projectdiscovery/nuclei-templates.git
else
    echo "Nuclei templates repository already exists."
fi
