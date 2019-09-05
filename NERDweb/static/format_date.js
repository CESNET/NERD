function utc_on() {
    return $("#utc-togBtn").is(":checked");
}

function formatDate(rawDate){
    if(utc_on()) {
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

function format_tag_tooltip(tooltip_str){
    if(utc_on()) {
        // date is always in UTC by default in tooltips
        return tooltip_str
    }

    // find all dates in tooltip and replace them with local time
    var date_regex = new RegExp('\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}(:\\d{2}(.\\d\\+)?)?', 'g');
    return tooltip_str.replace(date_regex, function (date) { return formatDate(new Date(date + "Z")); } ); // TODO set precision (sec/msec) based on existence of regexp groups 1 and 2.
}

function reformatAllDates(){
    // format every time value properly
    $(".time").each(function () {
        if (!$(this).get(0).className.includes("duration")) {
            var datetime = $(this).data("time");
            var rawDate = new Date(datetime * 1000);
            $(this).text(formatDate(rawDate));
        }
    });
}

document.addEventListener("DOMContentLoaded", function () {
    reformatAllDates();
});
