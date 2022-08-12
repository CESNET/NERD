/* JS code for ips.html (search of IP records) */

// Trigger this immediately after form definition
function set_up_search_form() {

// Improve selects using "multiselect" library/plugin
  $("select#country").multiselect({texts: {placeholder: "Any"}, search: true, selectAll: true});
  $("select#source").multiselect({texts: {placeholder: "Any"}, search: true});
  $("select#cat").multiselect({texts: {placeholder: "Any"}, search: true});
  $("select#node").multiselect({texts: {placeholder: "Any"}, search: true});
  $("select#blacklist").multiselect({texts: {placeholder: "Any"}, search: true});
  $("select#tag").multiselect({texts: {placeholder: "Any"}, search: true});
  

  // Set up an operation (and/or) button
  function set_up_op_button(button_id, form_elem_id, title_or, title_and) {
    $(button_id).on("click", function() {
      if ($(form_elem_id).val() == 'and') {
        $(form_elem_id).val("or");
        $(this).find(".or").addClass("selected");
        $(this).find(".and").removeClass("selected");
      } else {
        $(form_elem_id).val("and");
        $(this).find(".and").addClass("selected");
        $(this).find(".or").removeClass("selected");
      }
      return false;
    });

    if ($(form_elem_id).val() == "or") {
      $(button_id).find(".or").addClass("selected");
      $(button_id).find(".and").removeClass("selected");
    } else {
      $(button_id).find(".and").addClass("selected");
      $(button_id).find(".or").removeClass("selected");
    }
  }

  // Set up an operation (desc/asc) button
  function order_check() {
    $(".order")
    .click( function() {
    if ($("#asc").is(":checked"))
    {
      $("#asc").prop('checked', false);
      $(this).find(".or").addClass("selected");
      $(this).find(".and").removeClass("selected");
    }
    else
    {
      $("#asc").prop('checked', true);
      
      $(this).find(".and").addClass("selected");
      $(this).find(".or").removeClass("selected");
    }
    return false;
  });
    if ($("#asc").is(":checked"))
    {
      if (sessionStorage.getItem("currentPanel") == null || sessionStorage.getItem("currentPanel") == 0)
      {
        $(".order").find(".and").addClass("selected");
        $(".order").find(".or").removeClass("selected");
      }
      else
      {
        console.log("HERE");
        $(".order").eq(1).find(".and").addClass("selected");
        $(".order").eq(1).find(".or").removeClass("selected");
      }
    }
    else
    {
      if (sessionStorage.getItem("currentPanel") == null || sessionStorage.getItem("currentPanel") == 0)
      {
        $(".order").find(".or").addClass("selected");
        $(".order").find(".and").removeClass("selected");
      }
      else
      {
        console.log("HERE");
        $(".order").eq(1).find(".or").addClass("selected");
        $(".order").eq(1).find(".and").removeClass("selected");
      }
    }
    };
    

    set_up_op_button("#source_op_button", "#source_op", "OR: At least one of the selected categories", "AND: All selected categories")
    set_up_op_button("#cat_op_button", "#cat_op", "OR: At least one of the selected categories", "AND: All selected categories")
    set_up_op_button("#node_op_button", "#node_op", "OR: At least one of the selected nodes", "AND: All selected nodes")
    set_up_op_button("#bl_op_button", "#bl_op", "OR: At least one of the selected blacklists", "AND: All selected blacklists")
    set_up_op_button("#tag_op_button", "#tag_op", "OR: At least one of the selected tags", "AND: All selected tags")
    

  order_check();
}


// Set-up possibility to click on a part of hostname to set it as a filer
function set_hostname_filter(hostname) {
  document.location = ROOT + "ips/?hostname=" + hostname;
};

$(function () {
  $("td.hostname").each( function () {
    hostname = $(this).text();
    if (hostname == "--")
      return;
    parts = hostname.split(".");
    $(this).html("<span>" + parts.join("</span><span>.") + "</span>");
  });
  $("td.hostname span")
    .css("cursor", "pointer")
    .click( function () {
      set_hostname_filter( $(this).text() + $(this).nextAll().text() );
    })
    .hover(
      function () { // mouseenter
        $(this).css("text-decoration", "underline");
        $(this).nextAll().css("text-decoration", "underline");
        $(this).attr("title", "Set as filter");
      },
      function () { // mouseleave
        $(this).css("text-decoration", "");
        $(this).nextAll().css("text-decoration", "");
        $(this).attr("title", "");
      }
    )
});

