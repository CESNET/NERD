function formatDate(rawDate, utc){
    if(utc){
        var year = '' + rawDate.getUTCFullYear(),
            // month values are 0-11
            month = '' + (rawDate.getUTCMonth() + 1),
            day = '' + rawDate.getUTCDate(),
            hour = '' + rawDate.getUTCHours(),
            minute = '' + rawDate.getUTCMinutes(),
            second = '' + rawDate.getUTCSeconds();
    }
    else{
         var year = '' + rawDate.getFullYear(),
             // month values are 0-11
             month = '' + (rawDate.getMonth() + 1),
             day = '' + rawDate.getDate(),
             hour = '' + rawDate.getHours(),
             minute = '' + rawDate.getMinutes(),
             second = '' + rawDate.getSeconds();
    }

    if (month.length < 2) month = '0' + month;
    if (day.length < 2) day = '0' + day;
    if (hour.length < 2) hour = '0' + hour;
    if (minute.length < 2) minute = '0' + minute;
    if (second.length < 2) second = '0' + second;
    return '' + year + '-' + month + '-' + day + ' ' + hour + ':' + minute + ':' + second;
}


function toggleTimezone(){
    // check what timezone is set now
    var timezoneElem = document.getElementById("slider");
    var timezoneElemStyle = window.getComputedStyle(timezoneElem);
    var timezoneColor = timezoneElemStyle.getPropertyValue("background-color");
    var utc = true;

    if (timezoneColor === "rgb(55, 58, 235)"){
        utc = false;
    }

    $(".time").each(function () {
        var datetime;
        var rawDate;

        // if utc was set, create UTC datetime
        if(utc){
            datetime = $(this).text();
            rawDate = new Date(datetime.concat(" UTC"));
        }
        else{
            rawDate = new Date($(this).text());
        }
        // then pass !utc, because we toggled timezone and want to set new timezone, we had to check what timezone was
        // used before click for proper Date object creation and then format it with toggled timezone
        $(this).text(formatDate(rawDate, !utc));
    });
}

function formatAllDatesOnLoad(){
    var dates_in_utc = true;

    // get page name - ips.html has all times in local time but ip.html has all times in UTC
    var allPathElements = window.location.pathname.split("/");
    var page = allPathElements[allPathElements.length-1];
    if(page === ""){
        page = allPathElements[allPathElements.length-2];
    }

    if(page === "ips"){
        console.log("dates in utc = false")
        dates_in_utc = false;
    }

    $(".time").each(function () {
        var datetime;
        var rawDate;
        // if dates are in utc, then create Date object properly
        if(dates_in_utc){
            datetime = $(this).text();
            rawDate = new Date(datetime.concat(" UTC"));
        }
        else{
            rawDate = new Date($(this).text());
        }
        // this is on load function, default is UTC timezone
        $(this).text(formatDate(rawDate, true));
    });
}

/*function toggleTimezone() {
    var x = document.getElementById("timezone");

    formatAllDates();

    // after correct format toggle text too
    if (x.innerHTML.trim() === "Current timezone: UTC"){
        x.innerHTML = "Current timezone: local";
    }
    else{
        x.innerHTML = "Current timezone: UTC";
    }
}*/

document.addEventListener("DOMContentLoaded", function () {
    formatAllDatesOnLoad();
});