# input_artifacts

This directory is copied into the agent container at `/task/`.

Place any static reference files the agent may need at runtime here
(e.g., a list of known SPDX licence identifiers, a list of known SBOM
filename patterns, etc.).

The agent must NOT find any solution data, test scripts, or verifier
code in this directory.
