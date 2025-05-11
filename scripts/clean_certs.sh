#!/bin/bash
# Script to clean all certificates

set -e  # Exit immediately if a command exits with a non-zero status

# Set directory
CERTS_DIR="certs"

# Confirm operation
echo "Warning: This will delete all certificates in the ${CERTS_DIR} directory."
echo "Are you sure you want to continue? (y/n)"
read -r confirm

if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "Operation cancelled."
    exit 0
fi

# Clean all certificates
echo "Cleaning all certificates..."
rm -rf ${CERTS_DIR}
echo "Cleaning completed."
