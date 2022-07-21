// Functions to request cretion of a new IP address record, wait until data are ready and then reloads the page (ip.html)

var pollInterval;
var queryCounter;

function show_error(message){
    var elem = $(".notfound-fetching");
    elem.removeClass().addClass("notfound-error");
    elem.text(message);
    elem.css("display", "block");
}

function request_ip_data(url, poll_url) {
    // Request creation of a temporary record for the IP
    fetch(url)
        .then(function(response) {
            if (response.ok) {
                // Show information that the data are being fetched
                $(".notfound-fetching").css("display", "block");
                // Start polling for the data prepared (every second)
                pollInterval = setInterval(_poll, 1000, poll_url);
                queryCounter = 0;
            }
            else if (response.status == 429) {
                show_error("ERROR: Can't fetch IP data, rate limit exceeded.");
            }
            else {
                console.error("Unexpected reply from " + url + ": ", response);
            }
        })
        .catch(function(error){
          console.error("Error when querying " + url + ": ", error);
        });
}

function _poll(url){
    fetch(url)
        .then((response) => response.text())
        .then(function(response) {
            if (response === "true") {
                location.reload();
            }
            else if (queryCounter > 30) { // stop polling after 30 seconds
                clearInterval(pollInterval);
                show_error("Timeout - backend is probably overloaded or stopped for maintenance. Try again later.");
            }
            queryCounter++;
        })
        .catch(function(error){
            clearInterval(pollInterval);
            console.error("Error when polling _is_prepared:", error);
            show_error("Error while trying to load the data!");
        });
}
