// Update collections n_ip_by_cat and n_ip_by_node, which contain number of IPs with given Category and Node, respectively. They also serve as lists of all existing Categories and Nodes.
db.ip.aggregate([{$unwind: {path: "$events"}}, {$group: {_id: {ip: "$_id", x: "$events.cat"}}}, {$group: {_id: "$_id.x", n: {$sum: 1}}}, {$out: "n_ip_by_cat"}], {allowDiskUse:true})
db.ip.aggregate([{$unwind: {path: "$events"}}, {$group: {_id: {ip: "$_id", x: "$events.node"}}}, {$group: {_id: "$_id.x", n: {$sum: 1}}}, {$out: "n_ip_by_node"}], {allowDiskUse:true})
db.ip.aggregate([{$unwind: {path: "$bl"}}, {$match: {"bl.v": 1}}, {$group: {_id: {ip: "$_id", x: "$bl.n"}}}, {$group: {_id: "$_id.x", n: {$sum: 1}}}, {$out: "n_ip_by_bl"}], {allowDiskUse:true})
db.ip.aggregate([{$unwind: {path: "$dbl"}}, {$match: {"dbl.v": 1}}, {$group: {_id: {ip: "$_id", x: "$dbl.n"}}}, {$group: {_id: "$_id.x", n: {$sum: 1}}}, {$out: "n_ip_by_dbl"}], {allowDiskUse:true})
//TODO tags (needs to change storage format)
