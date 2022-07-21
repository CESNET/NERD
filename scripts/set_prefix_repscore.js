// Set reputation score of each BGP prefix as an average of rep. scores of all
// IP addresses within it (including the noes not in DB, which heve rep.score=0)

// var cnt = db.bgppref.count();
// var i = 0;

db.ip.aggregate(
  [
    {$match: {"bgppref": {$exists: 1}}},
    {$project: {"bgppref": 1, "rep": 1}},
    //{$limit: 50},
    {$group: {_id: "$bgppref", sum_rep: {$sum: "$rep"}}},
  ],
  {allowDiskUse:true}
).forEach(function (x) {
  prefix_id = x["_id"];
  prefix_len = prefix_id.split("/")[1];
  prefix_size = 1 << (32 - prefix_len);
  avg_rep = x["sum_rep"] / prefix_size;
//  print("(" + prefix_id + ").rep <= " + avg_rep);
  db.bgppref.updateMany({"_id": prefix_id}, {"$set": {"rep": avg_rep}});
//   i += 1;
//   if (i % 1000 == 0) {
//     print("Done: "+i+"/"+cnt);
//   }
})
