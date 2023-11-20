
function FindProxyForURL(url, host) {
    var PROXY = "PROXY 71.183.76.204:9233; PROXY 1.1.1.1:80";
    //proxy our custom remote netfree tools server
    if(isInNet(dnsResolve(host), "127.123.123.123", "255.255.255.255")) return PROXY;
    // bypass local
	if(isInNet(dnsResolve(host), "127.0.0.1", "255.0.0.0")) return "DIRECT";
	if(isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) return "DIRECT";
	if(isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0")) return "DIRECT";
	if(isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")) return "DIRECT";

  // private rules

    //gizber
    if(shExpMatch(url, "*gizber.com*")) return "DIRECT";
    //our ip
    if(isInNet(dnsResolve(host), "15.204.241.22", "255.255.255.255")) return "DIRECT";
    //office ip
    if(isInNet(dnsResolve(host), "71.183.76.202", "255.255.255.255")) return "DIRECT";
    // my ip
    if(isInNet(dnsResolve(host), "71.183.76.204", "255.255.255.255")) return "DIRECT";
    //tabnine
    if(shExpMatch(url, "*tabnine.com*")) return "DIRECT";
	
	return PROXY;
}
