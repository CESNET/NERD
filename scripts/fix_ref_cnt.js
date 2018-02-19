// This script recomputes all references between deifferent entities in NERD
// database and set "_ref_cnt" fields accordingly.
// If some record has no reference (an inconsistency which shouldn't normally
// happen) it's removed.

// IMPORTANT: Stop NERDd before running the script! Database must not be 
// changed while the script is running.

// ** ip -> bgppref **
// Set _ref_cnt in "bgppref" records to number of IPs pointing to it from "ip" records
// Reset _ref_cnt to 0 in all records
db.bgppref.update({}, {$set: {_ref_cnt: 0}}, {multi: true});
// Count references and set _ref_cnt
db.ip.aggregate([
    {$match: {bgppref: {$exists: true}}},
    {$project: {_id: 1, bgppref: 1}},
    {$group: {_id: "$bgppref", cnt: {$sum: 1}}}
]).forEach( function(x) {
    db.bgppref.update({_id: x._id}, {$set: {_ref_cnt: x.cnt}})
});
// Delete records with _ref_cnt = 0 (shouldn't normally happen)
res = db.bgppref.remove({_ref_cnt: 0});
if (res["nRemoved"] > 0) {
    print("NOTICE: Removed " + res["nRemoved"] + " 'bgppref' records with no reference.");
}


// ** ip -> ipblock **
// Set _ref_cnt in "ipblock" records to number of IPs pointing to it from "ip" records
// Reset _ref_cnt to 0 in all records
db.ipblock.update({}, {$set: {_ref_cnt: 0}}, {multi: true});
// Count references and set _ref_cnt
db.ip.aggregate([
    {$match: {ipblock: {$exists: true}}},
    {$project: {_id: 1, ipblock: 1}},
    {$group: {_id: "$ipblock", cnt: {$sum: 1}}}
]).forEach( function(x) {
    db.ipblock.update({_id: x._id}, {$set: {_ref_cnt: x.cnt}})
});
// Delete records with _ref_cnt = 0 (shouldn't normally happen)
res = db.ipblock.remove({_ref_cnt: 0});
if (res["nRemoved"] > 0) {
    print("NOTICE: Removed " + res["nRemoved"] + " 'ipblock' records with no reference.");
}


// ** bgppref <-> asn **
// Reset array of pointers in "asn" to []
db.asn.update({}, {$set: {bgppref: []}}, {multi: true});
// For each "asn", set its list of pointers to all "bgpprefs" which point to the "asn"
db.bgppref.aggregate([
    {$match: {asn: {$exists: true}}},
    {$project: {_id: 1, asn: 1}},
    {$unwind: "$asn"},
    {$group: {_id: "$asn", bgppref: {$push: "$_id"}}}
]).forEach( function(x) {
    db.asn.update({_id: x._id}, {$set: {bgppref: x.bgppref}})
});
// Delete records with empty list of pointers (shouldn't normally happen)
res = db.asn.remove({bgppref: {$size: 0}});
if (res["nRemoved"] > 0) {
    print("NOTICE: Removed " + res["nRemoved"] + " 'asn' records with no reference.");
}

// Reset array of pointers in "bgppref" to []
db.bgppref.update({}, {$set: {asn: []}}, {multi: true});
// For each "bgppref", set its list of pointers to all "asns" which point to the "bgppref"
db.asn.aggregate([
    {$match: {bgppref: {$exists: true}}},
    {$project: {_id: 1, bgppref: 1}},
    {$unwind: "$bgppref"},
    {$group: {_id: "$bgppref", asn: {$push: "$_id"}}}
]).forEach( function(x) {
    db.bgppref.update({_id: x._id}, {$set: {asn: x.asn}})
});
// Delete records with empty list of pointers (shouldn't normally happen)
res = db.bgppref.remove({asn: {$size: 0}});
if (res["nRemoved"] > 0) {
    print("NOTICE: Removed " + res["nRemoved"] + " 'bgppref' records with no reference.");
}


// ** asn/ipblock -> org **
// Set _ref_cnt in "org" records to number of IPs pointing to it from "asn" and "ipblock" records
// Reset _ref_cnt to 0 in all records
db.org.update({}, {$set: {_ref_cnt: 0}}, {multi: true});
db.asn.aggregate([
    {$match: {org: {$exists: true}}},
    {$project: {_id: 1, org: 1}},
    {$group: {_id: "$org", cnt: {$sum: 1}}}
]).forEach( function(x) {
    db.org.update({_id: x._id}, {$inc: {_ref_cnt: x.cnt}})
});
db.ipblock.aggregate([
    {$match: {org: {$exists: true}}},
    {$project: {_id: 1, org: 1}},
    {$group: {_id: "$org", cnt: {$sum: 1}}}
]).forEach( function(x) {
    db.org.update({_id: x._id}, {$inc: {_ref_cnt: x.cnt}})
});
// Delete records with _ref_cnt = 0 (shouldn't normally happen)
res = db.org.remove({_ref_cnt: 0});
if (res["nRemoved"] > 0) {
    print("NOTICE: Removed " + res["nRemoved"] + " 'org' records with no reference.");
}
