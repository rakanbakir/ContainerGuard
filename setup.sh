#!/bin/bash

# Create directories if they don't exist
mkdir -p grype trivy

# Set permissions
chmod -R 755 grype trivy

# Create empty report directories in case they don't exist
mkdir -p grype/grype trivy/trivy