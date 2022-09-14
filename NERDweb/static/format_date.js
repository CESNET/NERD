// This code handles the UTC-local time switch.
// When the switch is toggled, all times on the page are reformatted to show time in UTC or browser's local time.
// Each element containing time must have ".time" class and "data-time" attribute with timestamp as integer in UTC.
// The state of the switch is stored in localStorage, so it persists traversal of various pages.

function is_utc_on() {
    return $("#utc-togBtn").is(":checked");
}

function on_utc_switch_clicked() {
    // reformat all dates to reflect the change and store current state to localStorage, so it persists on various pages
    reformatAllDates();
    window.localStorage.setItem("utc-switch", (is_utc_on() ? "true" : "false"));
}

function formatDate(rawDate){
    if(is_utc_on()) {
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

function format_dates_in_tooltip(tooltip_str){
    if(is_utc_on()) {
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
    // on load - get saved state from localStorage, set/unset the checkbox and reformat all dates
    if (window.localStorage.getItem("utc-switch") == "true") {
        $("#utc-togBtn").prop("checked", true);
    }
    else { // false or not set = local
        $("#utc-togBtn").prop("checked", false);
    }
    reformatAllDates();
    $("#utc-switch").css("display", "inline-block"); // show the switch, which is hidden by default (otherwise it may load in one state and then, after this code runs, switch to the other state, which looks weird)
    $("#timezone-label").css("display", "block");

    // Set title with explanation and actual "local" timezone.
    var tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    var title="Switch whether all time information on the page should be displayed in UTC or your local timezone ("+tz+").";
    $("#utc-switch").prop('title', title);
});
