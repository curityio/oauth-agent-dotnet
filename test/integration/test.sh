#!/bin/bash

######################################################
# An early script to manage testing of the OAuth agent
######################################################

cd "$(dirname "${BASH_SOURCE[0]}")"
BASE_URL='http://localhost:8080/oauth-agent'

#
# Start login
#
echo 'Calling login start ...'
curl -X POST "$BASE_URL/login/start" -d @startLogin.json -H "content-type: application/json" | jq

#
# End login
#
echo 'Calling login end ...'
curl -X POST "$BASE_URL/login/end" -d @endLogin.json -H "content-type: application/json" | jq

#
# Get user info
#

#
# Get claims
#

#
# Refresh token
#

#
# Logout
#
echo 'Calling logout ...'
curl -X POST "$BASE_URL/logout" | jq