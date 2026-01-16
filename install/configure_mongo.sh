#!/bin/sh

BASEDIR=$(dirname $0)
. $BASEDIR/common.sh

echob "=============== Configure MongoDB ==============="

echob "** Configuring MongoDB **"

CFG=/etc/nerd/nerd.yml
DBNAME=$(yq '.mongodb.dbname' "$CFG")
USER=$(yq '.mongodb.username' "$CFG")
PASS=$(yq '.mongodb.password' "$CFG")
RS=$(yq '.mongodb.rs // ""' "$CFG")

# Set up authentication
mongosh $DBNAME --eval "db.createUser({user: '$USER', pwd: '$PASS', roles: [{role: 'readWrite', db: '$DBNAME'}]})"
if [[ -n "$RS" && "$RS" != "null" ]]; then
  # Replica set
  HOSTS=$(yq '.mongodb.host | join(",")' "$CFG")
  URI="mongodb://${USER}:${PASS}@${HOSTS}/${DBNAME}?replicaSet=${RS}&authSource=${DBNAME}"
  yq -i '.security.authorization = "enabled"' /etc/mongod.conf
  yq -i '.security.keyfile = "/etc/nerd/mongodb_keyfile"' /etc/mongod.conf

  # Generate keyfile
  echoy "Generating new RS key (/etc/nerd/mongodb_keyfile), please distribute this key to other RS members"
  openssl rand -base64 756 > /etc/nerd/mongodb_keyfile
  chmod 600 /etc/nerd/mongodb_keyfile
  echoy "$(cat /etc/nerd/mongodb_keyfile)"
else
  # Standalone
  HOST=$(yq '.mongodb.host' "$CFG")
  URI="mongodb://${USER}:${PASS}@${HOST}/${DBNAME}?authSource=${DBNAME}"
  yq -i '.security.authorization = "enabled"' /etc/mongod.conf
fi

echo "$URI" > /etc/nerd/mongodb_credentials
chown nerd:nerd /etc/nerd/mongodb_credentials
chmod 664 /etc/nerd/mongodb_credentials

# Set up NERD DB (create indexes)
mongosh "$(cat /etc/nerd/mongodb_credentials)" $BASEDIR/mongo_prepare_db.js
