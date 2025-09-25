
/*
$('a').click(function(){
    alert("You are about to go to "+$(this).attr('href'));
});
*/

var result = {};


//---------------------- 1.  IP Address  ----------------------

var url = window.location.href;
// alert(url);
var urlDomain = window.location.hostname;

//url="0x58.0xCC.0xCA.0x62"

var patt = /(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]?[0-9])(\.|$){4}/;
var patt2 = /(0x([0-9][0-9]|[A-F][A-F]|[A-F][0-9]|[0-9][A-F]))(\.|$){4}/;
var ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;


if(ip.test(urlDomain)||patt.test(urlDomain)||patt2.test(urlDomain)){ 
    result["IP Address"]="1";
}else{
    result["IP Address"]="-1";
}

//alert(result);

//---------------------- 2.  URL Length  ----------------------


//alert(url.length);
if(url.length<54){
    result["URL Length"]="-1";
}else if(url.length>=54&&url.length<=75){
    result["URL Length"]="0";
}else{
    result["URL Length"]="1";
}
//alert(result);


//---------------------- 3.  Tiny URL  ----------------------

var onlyDomain = urlDomain.replace('www.','');

if(onlyDomain.length<7){
    result["Tiny URL"]="1";
}else{
    result["Tiny URL"]="-1";
}
//alert(result);

//---------------------- 4.  @ Symbol  ----------------------

patt=/@/;
if(patt.test(url)){ 
    result["@ Symbol"]="1";
}else{
    result["@ Symbol"]="-1";
}

//---------------------- 5.  Redirecting using //  ----------------------

if(url.lastIndexOf("//")>7){
    result["Redirecting using //"]="1";
}else{
    result["Redirecting using //"]="-1";
}

//---------------------- 6. (-) Prefix/Suffix in domain  ----------------------

patt=/-/;
if(patt.test(urlDomain)){ 
    result["(-) Prefix/Suffix in domain"]="1";
}else{
    result["(-) Prefix/Suffix in domain"]="-1";
}

//---------------------- 7.  No. of Sub Domains  ----------------------

//patt=".";

if((onlyDomain.match(RegExp('\\.','g'))||[]).length==1){ 
    result["No. of Sub Domains"]="-1";
}else if((onlyDomain.match(RegExp('\\.','g'))||[]).length==2){ 
    result["No. of Sub Domains"]="0";    
}else{
    result["No. of Sub Domains"]="1";
}

//---------------------- 8.  HTTPS  ----------------------


patt=/https:\/\//;
if(patt.test(url)){
    result["HTTPS"]="-1";
}else{
    result["HTTPS"]="1";
}



//---------------------- 9. Favicon  ----------------------

var favicon = undefined;
var nodeList = document.getElementsByTagName("link");
for (var i = 0; i < nodeList.length; i++)
{
    if((nodeList[i].getAttribute("rel") == "icon")||(nodeList[i].getAttribute("rel") == "shortcut icon"))
    {
        favicon = nodeList[i].getAttribute("href");
    }
}
if(!favicon) {
    result["Favicon"]="-1";
}else if(favicon.length==12){
    result["Favicon"]="-1";
}else{
    patt=RegExp(urlDomain,'g');
    if(patt.test(favicon)){
        result["Favicon"]="-1";
    }else{
        result["Favicon"]="1";
    }
}


//---------------------- 10. Using Non-Standard Port  ----------------------

result["Port"]="-1";

//---------------------- 11.  HTTPS in URL's domain part  ----------------------


patt=/https/;
if(patt.test(onlyDomain)){
    result["HTTPS in URL's domain part"]="1";
}else{
    result["HTTPS in URL's domain part"]="-1";
}

// alert(result);

//---------------------- 12.  Request URL  ----------------------

var imgTags = document.getElementsByTagName("img");

var phishCount=0;
var legitCount=0;

patt=RegExp(onlyDomain,'g');

for(var i = 0; i < imgTags.length; i++){
    var src = imgTags[i].getAttribute("src");
    if(!src) continue;
    if(patt.test(src)){
        legitCount++;
    }else if(src.charAt(0)=='/'&&src.charAt(1)!='/'){
        legitCount++;
    }else{
        phishCount++;
    }
}
var totalCount=phishCount+legitCount;
var outRequest=(phishCount/totalCount)*100;
//alert(outRequest);

if(outRequest<22){
    result["Request URL"]="-1";
}else if(outRequest>=22&&outRequest<61){
    result["Request URL"]="0";
}else{
    result["Request URL"]="1";
}

//---------------------- 13.  URL of Anchor  ----------------------
var aTags = document.getElementsByTagName("a");

phishCount=0;
legitCount=0;
var allhrefs="";

for(var i = 0; i < aTags.length; i++){
    var hrefs = aTags[i].getAttribute("href");
    if(!hrefs) continue;
    allhrefs+=hrefs+"       ";
    if(patt.test(hrefs)){
        legitCount++;
    }else if(hrefs.charAt(0)=='#'||(hrefs.charAt(0)=='/'&&hrefs.charAt(1)!='/')){
        legitCount++;
    }else{
        phishCount++;
    }
}
totalCount=phishCount+legitCount;
outRequest=(phishCount/totalCount)*100;

if(outRequest<31){
    result["Anchor"]="-1";
}else if(outRequest>=31&&outRequest<=67){
    result["Anchor"]="0";
}else{
    result["Anchor"]="1";
}

//alert(allhrefs);

//---------------------- 14. Links in script and link  ----------------------

var mTags = document.getElementsByTagName("meta");
var sTags = document.getElementsByTagName("script");
var lTags = document.getElementsByTagName("link");

phishCount=0;
legitCount=0;

allhrefs="sTags  ";

for(var i = 0; i < sTags.length; i++){
    var sTag = sTags[i].getAttribute("src");
    if(sTag!=null){
        allhrefs+=sTag+"      ";
        if(patt.test(sTag)){
            legitCount++;
        }else if(sTag.charAt(0)=='/'&&sTag.charAt(1)!='/'){
            legitCount++;
        }else{
            phishCount++;
        }
    }
}

allhrefs+="      lTags   ";
for(var i = 0; i < lTags.length; i++){
    var lTag = lTags[i].getAttribute("href");
    if(!lTag) continue;
    allhrefs+=lTag+"       ";
    if(patt.test(lTag)){
        legitCount++;
    }else if(lTag.charAt(0)=='/'&&lTag.charAt(1)!='/'){
        legitCount++;
    }else{
        phishCount++;
    }
}

totalCount=phishCount+legitCount;
outRequest=(phishCount/totalCount)*100;

if(outRequest<17){
    result["Script & Link"]="-1";
}else if(outRequest>=17&&outRequest<=81){
    result["Script & Link"]="0";
}else{
    result["Script & Link"]="1";
}

//alert(allhrefs);

//---------------------- 15.Server Form Handler ----------------------

var forms = document.getElementsByTagName("form");
var res = "-1";

for(var i = 0; i < forms.length; i++) {
    var action = forms[i].getAttribute("action");
    if(!action || action == "") {
        res = "1";
        break;
    } else if(!(action.charAt(0)=="/" || patt.test(action))) {
        res = "0";
    }
}
result["SFH"] = res;

//---------------------- 16.Submitting to mail ----------------------

var forms = document.getElementsByTagName("form");
var res = "-1";

for(var i = 0; i < forms.length; i++) {
    var action = forms[i].getAttribute("action");
    if(!action) continue;
    if(action.startsWith("mailto")) {
        res = "1";
        break;
    }
}
result["mailto"] = res;

//---------------------- 17.Using iFrame ----------------------

var iframes = document.getElementsByTagName("iframe");

if(iframes.length == 0) {
    result["iFrames"] = "-1";
} else {
    result["iFrames"] = "1";
}





//-------------------------------------- 19.is Illegal Https URL------------------------------------------------

function isIllegalHttpsURL(url) {
    // Convert the URL to lowercase for case-insensitive comparison
    var lowercasedURL = url.toLowerCase();

    // Check if the URL starts with "https://" and contains the word "illegal"
    return lowercasedURL.startsWith("https://") && lowercasedURL.includes("illegal");
}

// Example usage
var testURL = "https://example.com/illegal-page";
if (isIllegalHttpsURL(testURL)) {
    result["illegal HTTPS URL!"] = "-1";
} else {
    result["illegal HTTPS URL!"] = "1";
}

//------------------------------ 20.find Links To Pointing To Page------------------------------------------------------------

// # Links Pointing to Page Feature
function categorizeLinksPointingToPage(linkCount) {
    if (linkCount >= 10) {
        return 1; // High links pointing to the page
    } else if (linkCount > 0) {
        return 0; // Moderate links pointing to the page
    } else {
        return -1; // Low or no links pointing to the page
    }
}

// Example usage
const linksPointingToPageCount = 15; // Replace with your actual link count
const linksCategory = categorizeLinksPointingToPage(linksPointingToPageCount);


if (linksCategory === 1) {
    result["Links Pointing "] = "1";
} else if (linksCategory === 0) {
    result["Links Pointing "] = "0";
} else {
    result["Links Pointing "] = "-1";
}



//---------------------------------------- 21.generate Report---------------------------------------------------------


// # Statistical Report for { -1, 1 } feature
function generateReport(data) {
    try {
        if (!Array.isArray(data)) {
            throw new Error("Input must be an array");
        }

        if (data.length === 0) {
            throw new Error("Input array is empty");
        }

        const totalCount = data.length;
        const countMinusOne = data.filter(value => value === -1).length;
        const countOne = data.filter(value => value === 1).length;

        const percentageMinusOne = (countMinusOne / totalCount) * 100;
        const percentageOne = (countOne / totalCount) * 100;

        return {
            totalCount,
            countMinusOne,
            countOne,
            percentageMinusOne,
            percentageOne
        };
    } catch (error) {
        return { error: error.message };
    }
}

// Example usage
const data = [-1, 1, 1, -1, -1, 1, -1, 1, 1];
const report = generateReport(data);

if (report.percentageMinusOne > 50) {
    result["generate Report"] = "-1";
} else {
    result["generate Report"] = "1";
}

//--------------------------------- 22.Web Traffic Feature----------------------------------------------

// # Web Traffic Feature
function categorizeWebTraffic(trafficValue) {
    if (trafficValue === -1) {
        return "Low Web Traffic";
    } else if (trafficValue === 0) {
        return "Moderate Web Traffic";
    } else if (trafficValue === 1) {
        return "High Web Traffic";
    } else {
        return "Unknown Web Traffic Value";
    }
}

// Example usage
const webTrafficValue = 1; // Replace with your actual web traffic value
const webTrafficCategory = categorizeWebTraffic(webTrafficValue);

if (webTrafficCategory === 1) {
    result["Web Traffic "] = "1";
} else if (webTrafficCategory === 0) {
    result["Web Traffic "] = "0";
} else {
    result["Web Traffic"] = "-1";
}


//--------------------------------------------- 23.DNS Record Feature---------------------------------------------------

// # DNS Record Feature
function categorizeDNSRecord(dnsRecordValue) {
    if (dnsRecordValue === -1) {
        return "Invalid DNS record";
    } else if (dnsRecordValue === 1) {
        return "Valid DNS record";
    } else {
        return "Unknown DNS record value";
    }
}

// Example usage
const dnsRecordValue = 1; // Replace with your actual DNS record value
const dnsRecordCategory = categorizeDNSRecord(dnsRecordValue);

if (dnsRecordCategory  === 1) {
    result["DNS Record"] = "1";
} else {
    result["DNS Record"] = "-1";

}


///-----------------------------------------------------------------------






//---------------------- Sending the result  ----------------------

chrome.runtime.sendMessage(result, function(response) {
    console.log(result);
    //console.log(response);
});

chrome.runtime.onMessage.addListener(
    function(request, sender, sendResponse) {
      if (request.action == "alert_user")
        alert("Warning!!! This seems to be a phishing website.");
      return Promise.resolve("Dummy response to keep the console quiet");
    }
);