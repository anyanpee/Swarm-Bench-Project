#!/bin/bash
# Verifier entrypoint - ONLY calls verify.py

set -e

echo "Running SBOM Compliance Audit Verifier..."
python3 verify.py

# Exit with verify.py's exit code
exit $?
