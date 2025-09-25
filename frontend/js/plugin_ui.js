


chrome.tabs.query({ currentWindow: true, active: true }, function(tabs){
    chrome.storage.local.get(['results', 'legitimatePercents', 'isPhish'], function(items) {
        var result = items.results[tabs[0].id];
        var isPhish = items.isPhish[tabs[0].id];
        var legitimatePercent = items.legitimatePercents[tabs[0].id];
    
        
        
        $("#site_score").text(parseInt(legitimatePercent)+"%");
        if(isPhish) {
            $("#res-circle").css("background", "#e81010");
            $("#site_msg").text("Warning!! You're being phished.");
            $("#site_score").text(parseInt(legitimatePercent)-20+"%");
        }
    });
    
});

