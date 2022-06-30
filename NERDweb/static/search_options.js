var tabButtons=document.querySelectorAll(".tabContainer .buttonContainer button");
var tabPanels=document.querySelectorAll(".tabContainer .tabPanel");
let defaultColor = "#0061a2";

function parser(){
    var search = document.getElementById('ip_list').value;
    var ip_list = search.match(/((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/g).toString();
    ip_list = ip_list.replace(/,/g, '\n');
    document.getElementById('ip_list').value = ip_list;
}

function changeTab(panelIndex, colorCode) {
    sessionStorage.setItem("currentPanel", panelIndex);
    showPanel(sessionStorage.getItem("currentPanel"), colorCode);
}

function showPanel(panelIndex, colorCode) {

    tabButtons.forEach(function(node){
        node.style.backgroundColor="";
        node.style.color="";
    });

    tabButtons[panelIndex].style.backgroundColor=colorCode;
    tabButtons[panelIndex].style.color="white";

    tabPanels.forEach(function(node){
        node.style.display="none";
    });

    tabPanels[panelIndex].style.display="block";
}



if(window.location.href.endsWith("/nerd/ips/")){
    changeTab(0, defaultColor);
}

else
{
    if (sessionStorage.getItem("currentPanel") !== null)
        changeTab(sessionStorage.getItem("currentPanel"), defaultColor);
    else
        changeTab(0, defaultColor);
}
    