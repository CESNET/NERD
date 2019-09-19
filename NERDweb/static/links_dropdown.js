// add eventListener for click on button --> expand dropdown
document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll('.links-dropbtn').forEach(
        element =>
            element.addEventListener('click', toggleDropdown)
    );
});

function toggleDropdown(event){
    var dropdown = event.target.nextElementSibling;
    // close all other dropdown menus
    close_dropdowns(dropdown);
    dropdown.classList.toggle('links-show');
}

// function which closes all dropdown menus or all except the one, which is passed as currentDropdown
function close_dropdowns(currentDropdown){
    var dropdowns = document.getElementsByClassName("links-dropdown-content");
    var i;
    for (i = 0; i < dropdowns.length; i++) {
        var openDropdown = dropdowns[i];
        if (openDropdown.classList.contains('links-show')) {
            if(currentDropdown === null){
                openDropdown.classList.remove('links-show');
            }
            else {
                if (currentDropdown !== openDropdown) {
                    openDropdown.classList.remove('links-show');
                }
            }
        }
    }
}

// Close the dropdown menu if the user clicks outside of it
window.onclick = function(event) {
    if (!event.target.matches('.links-dropbtn')) {
        close_dropdowns(null)
    }
};