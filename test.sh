#!/bin/bash

#########################################################################################
# A script to run integration tests for the OAuth agent, with a mock authorization server
# Ensure that the OAuth Agent is running before executing this script
#########################################################################################

cd "$(dirname "${BASH_SOURCE[0]}")"
cd test/integration
dotnet test -l "console;verbosity=normal" # --filter Category="LoginController"