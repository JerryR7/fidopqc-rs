#!/bin/bash
set -e

# If AUTO_GENERATE_CERTS is set to true, generate certificates
if [ "$AUTO_GENERATE_CERTS" = "true" ]; then
    echo "Automatically generating certificates..."
    /app/scripts/generate_certs.sh
fi

# Execute quantum-safe-proxy command
exec "$@"
