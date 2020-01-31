// Script, which waits till the data of IP address are ready and then reloads the page (ip.html)

// poll every second
var pollInterval = setInterval(poll, 1000);
var queryCounter = 0;


function poll(){
    fetch(window.location.href + "/_is_prepared")
      .then((response) => response.json())
      .then(function(data){
        if (data === true){
            // when IP data is ready, stop polling
            clearInterval(pollInterval);
            if (queryCounter !== 0){
                // do not reload, if the data was ready before
                $( "#ip-entity-info" ).load(window.location.href + " #ip-entity-info" );
                queryCounter = 0;
            }
        }
        queryCounter++;
      })
      .catch(function(error){
        console.log(error);
      });
}
