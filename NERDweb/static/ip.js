/* JS code for ip.html (detail of IP address) */
function category2color(cat, alpha = 1.0) {
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

var default_colors = ['#3366CC', '#DC3912', '#FF9900', '#109618', '#990099', '#3B3EAC', '#0099C6', '#DD4477', '#66AA00', '#B82E2E', '#316395', '#994499', '#22AA99', '#AAAA11', '#6633CC', '#E67300', '#8B0707', '#329262', '#5574A6', '#3B3EAC']

const N_DAYS = 30;

// Get list of dates from today to N days
// We use this both to get data from "ipinfo.events" and as labels in the graph, since the same format is OK for both
function get_dates() {
  dates = [];
  let i;
  for (i = N_DAYS; i >= 0; i--) {
      dates.push(moment().subtract(i, "days").format("YYYY-MM-DD"));
  }
  return dates;
}

// Create graph with numbers of events per day
function create_event_graph(elem, event_data) {
  let dates = get_dates();

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
  let event_chart = new Chart(elem, {
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
              x: {
                  stacked: true
              },
              y: {
                  stacked: true,
                  min: 0,
                  max: (datasets.length > 0 ? null : 1), // force max=1 if no data are there
                  ticks: {
                      precision: 0,
                  },
                  title: {
                      display: true,
                      text: 'Number of events'
                  }
              }
          },
          plugins: {
              legend: {
                  position: 'bottom'
              },
              tooltip: {
                  mode: 'index'
              }
          },

      }
  });
}

// Create graph for DSHIELD reports and targets
function create_event_graph_dshield(elem, event_data) {
  let dates = get_dates();
  // get number of reports and targets for each day
  let reports = [];
  let targets = [];
  for (evtrec of event_data) {
      date_ix = dates.indexOf(evtrec.date);

      if (date_ix != -1) {
          reports[date_ix] = evtrec.reports;
          targets[date_ix] = evtrec.targets;
      }
      else {
          reports.push(0);
          targets.push(0);
      }

  }
  // Create the plot
  let event_chart = new Chart(elem, {
      type: 'bar',
      data: {
          labels: dates.map(d => moment(d).format("MMM D")),
          datasets: [{
              label: "Reports",
              borderWidth: 1,
              data: reports,
              backgroundColor: "rgb(66,66,66)"
          },
          {
              label: "Targets",
              borderWidth: 1,
              data: targets,
              backgroundColor: "rgb(166,166,166)"
          }
          ]
      },
      options: {
          barValueSpacing: 20, // makes bars next to each other
          animation: false,
          responsive: true,
          maintainAspectRatio: false,
          scales: {
              y: {
                  min: 0,
                  max: ((Math.max(...reports) == 0 && Math.max(...targets) == 0) ? 1 : null), // force max=1 if no data are there
                  ticks: {
                      precision: 0,
                  },
                  title: {
                      display: true,
                      text: 'Number of events'
                  }
              }
          },
          plugins: {
              legend: {
                  position: 'bottom'
              },
              tooltip: {
                  mode: 'index'
              }
          },

      }
  });
}


// Create graph for BLACKLISTS representing the presence on blacklist
function create_event_graph_bl(elem, event_data, info) {
  let dates = get_dates();

  let yLabels = {}; // names of blacklists
  let datasets = [];
  let count = 1;
  // event_data holds data for each blacklist
  for (list of event_data) {
      let vals = Object.values(list.h);
      let data = new Array(N_DAYS).fill(null);
      vals.forEach((key, index) => {
          data[dates.indexOf(moment(key).format("YYYY-MM-DD"))] = count;
      });

      // get name of blacklist obtained from blacklist info
      let name = list.n;
      if (info[list.n] != undefined)
          name = info[list.n].name

      ds = {
          label: name,
          data: data,
          borderColor: default_colors[count % 20],
          backgroundColor: default_colors[count % 20],
          borderWidth: 1,
          fill: false,
      }
      datasets.push(ds);
      yLabels[count] = name;
      count++;
  }

  // change height for charts containing many blacklists
  if (count > 7)
      document.getElementById("plot-events-bl").height = 35 * count;

  // Create the plot
  let event_chart = new Chart(elem, {
      type: 'line',
      data: {
          labels: dates.map(d => moment(d).format("MMM D")),
          datasets: datasets
      },
      options: {
          drawBorder: true,
          animation: false,
          responsive: true,
          maintainAspectRatio: false,
          scales: {
              y: {
                  beginAtZero: true,
                  title: {
                      display: true,
                      text: "Presence on blacklist",
                  },
                  ticks: {
                      callback: function (value, index, values) {
                          if (yLabels[value] !== undefined)
                              return yLabels[value];
                          else
                              return "";
                      }
                  }
              }
          },
          plugins: {
              legend: {
                  position: 'bottom'
              },
              tooltip: {
                  mode: 'index',
                  callbacks: {
                      label: function (tooltipItems, data) {
                          return yLabels[tooltipItems.raw];
                      }
                  }
              },
          },
      }
  });
}


// Create graph for OTX representing OTX pulses
function create_event_graph_otx(elem, event_data) {
  let dates = get_dates();

  let yLabels = {}; 
  let eventsByAuthor = {}; 
  let datasets = [];
  let values = [[]];
  let count = 0;
  
  for (pulse of event_data) {
      if (eventsByAuthor[pulse.author_name] !== undefined) {
          eventsByAuthor[pulse.author_name].push([pulse.indicator_created, pulse.pulse_name]);
      }
      else {
          // if this author has a pulse contribution in last 30 days
          if (dates.indexOf(moment(pulse.indicator_created).format("YYYY-MM-DD")) !== -1)
              eventsByAuthor[pulse.author_name] = [[pulse.indicator_created, pulse.pulse_name]];
      }
  }

  for (author in eventsByAuthor) {
      let data = new Array(N_DAYS).fill(null);
      let v = []

      for (d of eventsByAuthor[author]) {
          data[dates.indexOf(moment(d[0]).format("YYYY-MM-DD"))] = count;
          v[dates.indexOf(moment(d[0]).format("YYYY-MM-DD"))] = d[1];
      }
      values.push(v);

      ds = {
          label: author,
          data: data,
          backgroundColor: "black",
          borderWidth: 1,
          fill: false,
      }
      datasets.push(ds);
      yLabels[count] = author;
      count++;
  }


  // Create the plot
  let event_chart = new Chart(elem, {
      type: 'line',
      data: {
          labels: dates.map(d => moment(d).format("MMM D")),
          datasets: datasets
      },
      plugins:
          [ChartDataLabels],
      options: {
          drawBorder: true,
          animation: false,
          responsive: true,
          maintainAspectRatio: false,
          responsive: true,
          scales: {
              y: {
                  min: -0.5,
                  max: datasets.length - 0.5,
                  stepSize: 1,
                  autoSkip: true,
                  title: {
                      display: true,
                      text: "OTX pulses by author",
                  },
                  ticks: {
                      callback: function (value, index, values) {
                          if (yLabels[value] !== undefined)
                              return yLabels[value];
                          else
                              return "";
                      }
                  },
                  grid: {
                      drawBorder: false,
                      color: function(context) {
                        if (yLabels[context.tick.value] !== undefined) {
                          return "#cccccc";
                        }
                        return '#ffffff';
                      },
                  }
              }
          },
          layout: {
              padding: {
                  top: 20,
              }
          },
          plugins: {
              datalabels:
              {
                  rotation: '-45',
                  align: '-45',
                  anchor: 'end',
                  formatter: function(value, context) {
                      return values[context.datasetIndex + 1][context.dataIndex];
                    }
              },
              legend: {
                  display: false
              },
              tooltip: {
                  mode: 'index',
                  callbacks: {
                      label: function (tooltipItems, data) {
                          return values[tooltipItems.datasetIndex + 1][tooltipItems.index];

                      }
                  }
              },
          }

      }
  });
}     

// GRIP show / hide IP list
function show_ips(e)
{
    div = document.getElementById(e.target.getAttribute("name"));
    if (div.style.display == "none")
    {
        div.style.display = "";
        e.target.innerHTML = "hide IPs";
    }
    else
    {
        div.style.display = "none";
        e.target.innerHTML = "show IPs";
    }
    
}