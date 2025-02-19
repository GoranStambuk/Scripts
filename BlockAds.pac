// Network configuration script by Gorstak, ver 12.
// Enhanced ad-blocking PAC file

// Variable to skip proxy
var pass = "DIRECT";

// Variable for dead-end route
var blackhole = "PROXY 0.0.0.0:3421";

// Improved regex pattern to block more ad-related domains
var adRegex = new RegExp(
    "^(.+[-_.])?(ads?|banners?|track(er|ing)?|doubleclick|adservice|adnxs|adtech|googleads|partner|sponsor|clicks|pop(up|under)|promo|marketing|affiliates?|metrics|statcounter|analytics|pixel)"
);

// Proxy auto-config function
function FindProxyForURL(url, host) {
    host = host.toLowerCase();
    
    // Block ad domains
    if (adRegex.test(host)) {
        return blackhole;
    }
    
    // Allow everything else
    return pass;
}
