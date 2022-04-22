#!/bin/bash
# Set API token to given user (in 'users' table in PSQL DB 'nerd').
# If no token is specified, a random string of 10 alphanumeric characters is used.

if [ -z "$1" ]; then
  echo -e "Usage:\n   $0 user_name [token]" >&2
  exit 1
fi
user=$1
if [ -z "$2" ]; then
  token="$(</dev/urandom tr -dc 'a-zA-Z0-9' | head -c 10)"
else
  token="$2"
fi
echo "Setting token '$token' to user '$user'"
psql -U nerd nerd_users -c "UPDATE users SET api_token = '$token' WHERE id = '$user'"

