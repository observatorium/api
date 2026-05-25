#!/bin/bash

set -e

echo "🧹 Cleaning up Observatorium Demo Environment..."

# Delete the KinD cluster
echo "🗑️ Deleting KinD cluster..."
kind delete cluster --name observatorium-demo

# Clean up any local certificate files
if [ -f admin-client.crt ]; then
    rm -f admin-client.crt admin-client.key ca.crt
    echo "🔐 Cleaned up certificate files"
fi

echo "✅ Cleanup complete!"