var tabButtons=document.querySelectorAll(".tabContainer .buttonContainer button");
var tabPanels=document.querySelectorAll(".tabContainer .tabPanel");
let defaultColor = "#dddddd";

function parser(){
    var search = document.getElementById('ip_list').value;
    var ip_list = search.match(/((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/[012]?[0-9])?)/g);
    if (ip_list !== null)
    {
        ip_list = ip_list.toString();
        ip_list = ip_list.replaceAll(/,/g, '\n');
        // remove duplicates by converting to set, then back
        ip_list = Array.from(new Set(ip_list.split('\n'))).toString().replaceAll(',', '\n');
    }
    
    document.getElementById('ip_list').value = ip_list;
}

function changeTab(panelIndex, colorCode) {
    sessionStorage.setItem("currentPanel", panelIndex);
    showPanel(sessionStorage.getItem("currentPanel"), colorCode);
}

function showPanel(panelIndex, colorCode) {

    tabButtons.forEach(function(node){
        node.style.backgroundColor=colorCode;
        node.style.color="gray";
    });

    tabButtons[panelIndex].style.backgroundColor="";
    tabButtons[panelIndex].style.color="";

    tabPanels.forEach(function(node){
        node.style.display="none";
    });

    tabPanels[panelIndex].style.display="block";
}



if (sessionStorage.getItem("currentPanel") !== null)
    changeTab(sessionStorage.getItem("currentPanel"), defaultColor);
else
    changeTab(0, defaultColor);

    