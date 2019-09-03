var utc_on = true;

function formatDate(rawDate ){
    if(utc_on){
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
    // switch timezone
    utc_on = !utc_on;
    // format every time value properly
    $(".time").each(function () {
        var datetime = $(this).data("time");
        var rawDate = new Date(datetime*1000);
        $(this).text(formatDate(rawDate));
    });
}

function formatAllDatesOnLoad(){
    $(".time").each(function () {
        var datetime = $(this).data("time");
        var rawDate = new Date(datetime*1000);
        $(this).text(formatDate(rawDate));
    });
}

document.addEventListener("DOMContentLoaded", function () {
    formatAllDatesOnLoad();
});