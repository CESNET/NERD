#!/bin/bash

if [[ "$#" -ne 5 ]]; then
  echo "Create a local user in NERD user database."
  echo "Usage:"
  echo "  $0 username list,of,groups name email org"
  echo
  echo "Username should be prefixed with 'local:' or 'shibboleth:'"
  echo "Groups are plain strings separated by commas, e.g.: registered,trusted"
  exit 1
fi

die () { echo "Exiting due to error"; exit 2; }

username=$1
groups=$2
name=$3
email=$4
org=$5

groups_for_sql="{\"$(sed 's/, */","/g' <<<"$groups")\"}"

echo "Adding a new user with the following parameters:"
echo "  Username:     $username"
echo "  Groups:       $groups_for_sql"
echo "  Full name:    $name"
echo "  Email:        $email"
echo "  Organization: $org"
echo
if [[ $username =~ ^local: ]]; then
  read -p "Enter password for the new user (or leave empty to generate a random one): " pass
  echo
  if [[ "$pass" == "" ]]; then
      pass="$(</dev/urandom tr -dc 'a-zA-Z0-9' | head -c 10)"
      echo "Generated password: $pass"
      echo
  fi
elif [[ $username =~ ^shibboleth: ]]; then
  read -p "Press enter to confirm (or Ctrl-C to quit): " _
else
  echo "ERROR: No valid prefix in username, it must begin with 'local:' or 'shibboleth:'"
  exit 2
fi

sql="insert into users values ('$username', '$groups_for_sql', '$name', '$email', '$org');"

echo "Running SQL command: $sql"
psql -U nerd nerd_users -c "$sql" || die

if [[ $username =~ ^local: ]]; then
  HTPASSWD_FILE=/etc/nerd/htpasswd
  echo "Setting the password into $HTPASSWD_FILE"
  htpasswd -b $HTPASSWD_FILE "${username#local:}" "$pass" || die
fi

echo "Done"

