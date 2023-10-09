var tabButtons=document.querySelectorAll(".tabContainer .buttonContainer button");
var tabPanels=document.querySelectorAll(".tabContainer .tabPanel");

function parser(){
    var search = document.getElementById('ip_list').value;
    var ip_list = search.match(/(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:(?!\/)|\/[12]?[0-9]|\/3[012])\b)/g);
    if (ip_list !== null)
    {
        ip_list = ip_list.toString();
        ip_list = ip_list.replaceAll(/,/g, '\n');
        // remove duplicates by converting to set, then back
        ip_list = Array.from(new Set(ip_list.split('\n'))).toString().replaceAll(',', '\n');
    }
    
    document.getElementById('ip_list').value = ip_list;
}

function changeTab(panelIndex) {
    sessionStorage.setItem("currentPanel", panelIndex);
    showPanel(sessionStorage.getItem("currentPanel"));
}

function showPanel(panelIndex) {

    tabButtons.forEach(function(node){
        node.classList.remove("selected");
    });

    tabButtons[panelIndex].classList.add("selected");

    tabPanels.forEach(function(node){
        node.style.display="none";
    });

    tabPanels[panelIndex].style.display="block";
}



if (sessionStorage.getItem("currentPanel") !== null)
    changeTab(sessionStorage.getItem("currentPanel"));
else
    changeTab(0);

    