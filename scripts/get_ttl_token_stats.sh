#!/bin/sh
# Get statistics on number of IP records by TTL tokens
# grep is used because mongosh puts an empty line at the end that we don't want there
mongosh nerd --quiet --eval 'db.ip.aggregate([{$project: {ttl: {$objectToArray: "$_ttl"}}}, {$unwind: "$ttl"}, {$group: {"_id": "$ttl.k", cnt: {$sum: 1}}}, {$sort: {cnt: -1}}]).forEach( function(x) { print(x["_id"] + "\t" + x["cnt"]); })' | grep -v "^$"
