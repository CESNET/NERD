/* JS code for ips.html (search of IP records) */

// Trigger this immediately after form definition
function set_up_search_form() {

  // Improve selects using "multiselect" library/plugin
  $("select#cat").multiselect({texts: {placeholder: "\xa0"}, search: true});
  $("select#node").multiselect({texts: {placeholder: "\xa0"}, search: true});
  $("select#blacklist").multiselect({texts: {placeholder: "\xa0"}, search: true});
  $("select#tag").multiselect({texts: {placeholder: "\xa0"}, search: true});

  // Set up an operation (and/or) button
  function set_up_op_button(button_id, form_elem_id, title_or, title_and) {
    $(button_id).on("click", function() {
      if ($(form_elem_id).val() == 'and') {
        $(form_elem_id).val("or");
        $(this).text("\u22c1").attr("title", title_or); // \u22c1 = Logical OR
      } else {
        $(form_elem_id).val("and");
        $(this).text("\u22c0").attr("title", title_and); // \u22c0 = Logical AND
      }
      return false;
    });
    if ($(form_elem_id).val() == "or") {
        $(button_id).text("\u22c1").attr("title", title_or);
    } else {
        $(button_id).text("\u22c0").attr("title", title_and);
    }
  }
  set_up_op_button("#cat_op_button", "#cat_op", "OR: At least one of the selected categories", "AND: All selected categories")
  set_up_op_button("#node_op_button", "#node_op", "OR: At least one of the selected nodes", "AND: All selected nodes")
  set_up_op_button("#bl_op_button", "#bl_op", "OR: At least one of the selected blacklists", "AND: All selected blacklists")
  set_up_op_button("#tag_op_button", "#tag_op", "OR: At least one of the selected tags", "AND: All selected tags")
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

