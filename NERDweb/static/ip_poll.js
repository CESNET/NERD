// Script, which waits till the data of IP address are ready and then reloads the page (ip.html)

// poll every second
var pollInterval = setInterval(poll, 1000);
var queryCounter = 0;

function show_error(message){
    var elem = document.getElementsByClassName("notfound-fetching")[0];
    elem.className = "notfound-error";
    elem.innerHTML = message;
}

function poll(){
    console.log("Trying " + window.location.href + "/_is_prepared ...");
    fetch(window.location.href + "/_is_prepared")
        .then((response) => response.text())
        .then(function(data) {
            console.log("Response:", data);
            if (data === "true") {
                location.reload();
            }
            else if (queryCounter > 30) { // stop polling after 30 seconds
                clearInterval(pollInterval);
                show_error("Timeout - backend is probably overloaded. Try again later.");
            }
            queryCounter++;
        })
        .catch(function(error){
            clearInterval(pollInterval);
            console.log("Error when polling _is_prepared:", error);
            show_error("Error while trying to load the data!");
        });
}
