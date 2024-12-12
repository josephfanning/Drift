// Functions for the nav bar start here 
function openDrawer() { 
    document.getElementById("myDrawer").style.width = "250px";
  }

function closeDrawer() {
    document.getElementById("myDrawer").style.width = "0";
  }

  document.addEventListener('DOMContentLoaded', function() {
    document.body.classList.add('nav-fade-in');
  });