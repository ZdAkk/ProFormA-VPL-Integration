#!/bin/bash

# Update the package list
sudo apt-get update

# Install pugixml library
sudo apt-get install -y libpugixml-dev

# Install libzip library
sudo apt-get install -y libzip-dev

# Install curl library
sudo apt-get install -y libcurl4-openssl-dev

# Install magic library (part of the libmagic package)
sudo apt-get install -y libmagic-dev

echo "All dependencies have been installed."
