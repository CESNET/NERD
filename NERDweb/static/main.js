/* NERD web - main JS code, common for whole web */

function create_event_table(data) { /* data are "dataset" field of a DOM node with "data-" attributes set */
  if (data.table == "") {
     return "No events";
  }
  var cats = data.cats.split(",");
  var dates = data.dates.split(",");
  var table = [];
  var table_rows = data.table.split(";");
  for (i = 0; i < table_rows.length; i++) {
    table.push(table_rows[i].split(","));
  }
  var nodes = data.nodes.split(",");
  
  var content = "<table><tr><th></th><th>";
  content += cats.join("</th><th>");
  content += "</th></tr>";
  for (i = 0; i < dates.length; i++) {
    content += "<tr><th>"+dates[i]+"</th><td>";
    content += table[i].join("</td><td>");
    content += "</td></tr>";
  }
  content += "</table>";
  content += "<b>Nodes (" + nodes.length + "):</b> " + nodes.join(", ");
  return content;
}

$(function() {
  /* jQuery UI tooltip at:
     - country flags (with name of the country)
     - "events" table cells
     - AS number
     - download button
  */
  $( document ).tooltip({
    items: ".country [title], .asn [title], .tag[title], button[title]",
    track: false,
    show: false,
    hide: false,
    position: {my: "left bottom", at: "left-7px top-2px", collision: "flip"},
    content: function() {
      return format_dates_in_tooltip($(this).attr('title'));
    } /* This is needed to allow HTML in tooltip text */
  });
  /* jQuery UI tooltip at "events" cell with event table */
  $( ".events" ).tooltip({
    items: ".events",
    track: false,
    show: false,
    hide: false,
    position: {my: "left bottom", at: "left-7px top-2px", collision: "flip"},
    content: function() { return create_event_table(this.dataset) }, /*$(".tooltip_event_table", this).html(); },*/
    tooltipClass: "events_tooltip"
  });
  /* jQuery UI tooltip at times with "timeago" */
  $( ".time" ).tooltip({
    items: ".time",
    track: false,
    show: false,
    hide: false,
    content: function() {
      timestamp = $(this).data("time");
      date_obj = new Date(timestamp*1000);
      return moment(date_obj).fromNow()
    },
    position: {my: "left bottom", at: "left-7px top-2px", collision: "flip"}
  });
});
