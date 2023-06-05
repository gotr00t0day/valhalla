#!/bin/bash

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Go is not installed. Installing..."
    sudo apt install golang-go 
fi

# Check if Nuclei is installed
if ! command -v nuclei &> /dev/null; then
    echo "Nuclei is not installed. Installing..."
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
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
