/* JS code for ip.html (detail of IP address) */

function category2color(cat, alpha=1.0) {
  var rgb = {
      "ReconScanning": "170,255,255",
      "AttemptLogin": "111,217,46",
      "AbusiveSpam": "102,51,14",
      "AnomalyTraffic": "119,136,153",
      "AttemptExploit": "218,112,214",
      "AvailabilityDDoS": "169,0,0",
      "AvailabilityDoS": "229,46,46",
      "IntrusionBotnet": "255,140,0",
      "IntrusionUserCompromise": "204,42,20",
      "VulnerableConfig": "255,228,181",
      "VulnerableOpen": "238,232,170",
  }[cat] || "170,170,170";
  return "rgba(" + rgb + "," + alpha + ")";
}

// Create graph with numbers of events per day
function create_event_graph(elem, event_data) { 
  const N_DAYS = 30;
  // Get list of dates from today to N days
  // We use this both to get data from "ipinfo.events" and as labels in the graph, since the same format is OK for both
  let dates = [];
  let i;
  for (i = N_DAYS; i >= 0; i--) {
     dates.push(moment().subtract(i, "days").format("YYYY-MM-DD"));
  }
  // Construct datasets, one for each category, values are numbers of events per day
  let datasets = [];
  for (evtrec of event_data) {
    date_ix = dates.indexOf(evtrec.date);
    if (date_ix == -1)
      continue // Skip records with date out of range
    let ds = datasets.find(s => s.label == evtrec.cat); // Find dataset for the category
    if (ds === undefined) {
      // If not found, initialize a new dataset object
      ds = {
          label: evtrec.cat,
          data: new Array(dates.length).fill(0),
          backgroundColor: category2color(evtrec.cat, 0.5),
          borderWidth: 1,
      }
      datasets.push(ds);
    }
    ds.data[date_ix] += evtrec.n;
  }
  // Create the plot
  let event_chart = new Chart('plot-events', {
      type: 'bar',
      data: {
          labels: dates.map(d => moment(d).format("MMM D")),
          datasets: datasets
      },
      options: {
          animation: false,
          responsive: true,
          maintainAspectRatio: false,
          scales: {
              xAxes: [{
                  stacked: true
              }],
              yAxes: [{
                  min: 0,
                  stacked: true,
                  scaleLabel: {
                      display: true,
                      labelString: "Number of events",
                  },
                  ticks: {
                      precision: 0,
                  }
              }]
          },
          legend: {
            position: 'bottom'
          },
          tooltips: {
            mode: 'index'
          }
      }
  });
}
