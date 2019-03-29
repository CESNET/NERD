#!/bin/sh

echo "=============== Configure MongoDB ==============="

echo "** Configuring MongoDB **"

# Set up MongoDB for NERD (create indexes)
mongo nerd /tmp/nerd_install/mongo_prepare_db.js
