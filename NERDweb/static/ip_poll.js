// Script, which waits till the data of IP address are ready and then reloads the page (ip.html)

// poll every second
var pollInterval = setInterval(poll, 1000);
var queryCounter = 0;

function show_error(){
    data_info = document.getElementsByClassName("notfound2");
    data_info[0].innerHTML = "Error while trying to load the data!";
}

function poll(){
    fetch(window.location.href + "/_is_prepared")
        .then((response) => response.text())
        .then(function(data){
            if (data === "true"){
                // when IP data is ready, stop polling
                clearInterval(pollInterval);
                if (queryCounter !== 0){
                    // do not reload, if the data was ready before
                    $( "#ip-entity-info" ).load(window.location.href + " #ip-entity-info" );
                    queryCounter = 0;
                }
            }
            else {
                // stop polling after cca 30 seconds
                if(queryCounter > 30){
                    clearInterval(pollInterval);
                    show_error();
                }
            }
            queryCounter++;
        })
        .catch(function(error){
            clearInterval(pollInterval);
            console.log(error);
            show_error();
        });
}
