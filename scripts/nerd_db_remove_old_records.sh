#!/bin/sh
# Removes all records last updated more than 14 days ago from NERD database.

d=$(date +%Y-%m-%d -d "14 days ago")

# "var x" supresses output of the function result
mongo nerd --quiet --eval "var x = db.ip.remove({ts_last_event: {\$lt: ISODate(\"${d}T00:00:00\")}})"

