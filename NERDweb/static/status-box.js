/* JS code for status-box (normally only available to admins) */

/**** Show/hide & enable/disable *****/

var refresh_status_enable = false; // Enable/disable refresh status
var refreshing_status = false; // Whether refresh is in progress (to avoid multiple parallel calls it they are very slow and refresh interval is small)

function toggle_status_box() {
    var div = $('#status-block > div');
    var a = $('#status_box_toggle');
    if (a.text() == "▲") {
        div.hide();
        a.text("▼");
        refresh_status_enable = false;
        $("#status_refresh_toggle").text("disabled");
        smoothie.stop();
    }
    else {
        div.show();
        a.text("▲");
    }
}

function toggle_status_refresh() {
    if (refresh_status_enable) {
        refresh_status_enable=false;
        $("#status_refresh_toggle").text("disabled");
        smoothie.stop();
    }
    else {
        refresh_status_enable=true;
        $("#status_refresh_toggle").text("enabled");
        smoothie.start();
    }
}

/***** Graph with number of updates/s *****/
// resize the canvas to 100% width
$("#status-updates-plot").attr("width", $("#status-updates-plot").css("width"));
// Create reqs/s chart
var smoothie = new SmoothieChart({millisPerPixel:200, interpolation:'linear', 
    grid: {fillStyle:'#ffffff', millisPerLine:5000, verticalSections:4},
    labels: {fillStyle:'#000000'},
    minValue: 0, maxValue: 400
});
smoothie.streamTo(document.getElementById("status-updates-plot"));
smoothie.stop();
var updates_timeseries = new TimeSeries();
smoothie.addTimeSeries(updates_timeseries, {lineWidth: 2, strokeStyle:'#00c000', fillStyle: 'rgba(0,128,0,0.25)'});


/***** AJAX request to get NERD status information *****/
function refresh_status(force=false) {
    if (!force && (!refresh_status_enable || refreshing_status)) {
        return;
    }
    refreshing_status = true;
    $("#status-block .refresh-spinner").css('visibility', 'visible');
    $.getJSON(
        URL_GET_STATUS,
        function(data) {
            $("#status-cnt-ip").text(data.cnt_ip);
            $("#status-cnt-bgppref").text(data.cnt_bgppref);
            $("#status-cnt-asn").text(data.cnt_asn);
            $("#status-cnt-ipblock").text(data.cnt_ipblock);
            $("#status-cnt-org").text(data.cnt_org);
            $("#status-updates").text(data.updates_processed);
            $("#status-disk-usage").text(data.disk_usage);
            $("#status-idea-queue").text(data.idea_queue);
            // Set width of bar and its color
            var bar_width = (data.idea_queue * 100 / 10000);
            $("#status-idea-queue-bar div").css('width', bar_width + "%");
            if (bar_width < 50) {
                $("#status-idea-queue-bar div").css('background-color', '#0c0');
            }
            else if (bar_width < 75) {
                $("#status-idea-queue-bar div").css('background-color', '#ea0');
            }
            else {
                $("#status-idea-queue-bar div").css('background-color', '#c00');
            }
            
            $("#status-updreq-queue").text(data.update_queue);
            // Set width of bar and its color
            var bar_width = (data.update_queue * 100 / 1000);
            if (bar_width > 100) {
                bar_width = 100;
            }
            $("#status-updreq-queue-bar div").css('width', bar_width + "%");
            if (bar_width < 50) {
                $("#status-updreq-queue-bar div").css('background-color', '#0c0');
            }
            else if (bar_width < 75) {
                $("#status-updreq-queue-bar div").css('background-color', '#ea0');
            }
            else {
                $("#status-updreq-queue-bar div").css('background-color', '#c00');
            }
            // Add data to res/s plot
            updates_timeseries.append(new Date().getTime(), data.updates_processed);
        }
    )
    .always(function() {
        refreshing_status = false;
        $("#status-block .refresh-spinner").css('visibility', 'hidden');
    });
}

// Set automatic refresh every 2s
var status_refresh_timer = window.setInterval(refresh_status, 2000);
// Run refresh once on load
$(function() { refresh_status(true) });
