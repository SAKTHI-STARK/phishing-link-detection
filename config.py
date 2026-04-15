import re

SHORTENER_REGEX = re.compile(
    r'(?:bit\.ly|goo\.gl|shorte\.st|tinyurl\.com|ow\.ly|t\.co|tr\.im|is\.gd|'
    r'buff\.ly|adf\.ly|bit\.do|cutt\.ly|tiny\.cc|rebrandly\.com|short\.io|'
    r'bl\.ink|dub\.co|amzn\.to|rb\.gy|lnkd\.in|ift\.tt|cli\.re|soo\.gd|'
    r's2r\.co|clicky\.me|budurl\.com|bc\.vc|u\.to|yourls\.org|'
    r'prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.ae|'
    r't2m\.io|lc\.chat|po\.st|short\.cm|x\.co|clyp\.it|sh\.st|viid\.me|'
    r'zi\.ma|href\.li|t\.ly|shorturl\.at|spoti\.fi|vk\.cc|git\.io|'
    r'trib\.al|tinyone\.me|urlzs\.com)',
    re.IGNORECASE
)

# Mapping of Feature Name (used in model) to Method Name (in FeatureExtraction class)
FEATURE_METHODS = {
    "UsingIP": "UsingIp",
    "LongURL": "longUrl",
    "ShortURL": "shortUrl",
    "Symbol@": "symbol",
    "Redirecting//": "redirecting",
    "PrefixSuffix-": "prefixSuffix",
    "SubDomains": "SubDomains",
    "HTTPS": "Hppts",
    "DomainRegLen": "DomainRegLen",
    "Favicon": "Favicon",
    "NonStdPort": "NonStdPort",
    "HTTPSDomainURL": "HTTPSDomainURL",
    "RequestURL": "RequestURL",
    "AnchorURL": "AnchorURL",
    "LinksInScriptTags": "LinksInScriptTags",
    "ServerFormHandler": "ServerFormHandler",
    "InfoEmail": "InfoEmail",
    "AbnormalURL": "AbnormalURL",
    "WebsiteForwarding": "WebsiteForwarding",
    "StatusBarCust": "StatusBarCust",
    "DisableRightClick": "DisableRightClick",
    "UsingPopupWindow": "UsingPopupWindow",
    "IframeRedirection": "IframeRedirection",
    "AgeofDomain": "AgeofDomain",
    "DNSRecording": "DNSRecording",
    "PageRank": "PageRank",
    "LinksPointingToPage": "LinksPointingToPage",
    "StatsReport": "StatsReport",
    "DomainEntropy": "DomainEntropy",
    "FreeHosting": "FreeHosting"
}

DEFAULT_FEATURE_NAMES = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//",
    "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "Favicon",
    "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL",
    "LinksInScriptTags", "ServerFormHandler", "InfoEmail", "AbnormalURL",
    "WebsiteForwarding", "StatusBarCust", "DisableRightClick",
    "UsingPopupWindow", "IframeRedirection", "AgeofDomain",
    "DNSRecording", "PageRank",
    "LinksPointingToPage", "StatsReport"
]

# Features that require the website's HTML content (Soup)
FEATURES_NEEDING_HTML = [
    "Favicon", "RequestURL", "AnchorURL", "LinksInScriptTags", 
    "ServerFormHandler", "InfoEmail", "StatusBarCust", 
    "DisableRightClick", "UsingPopupWindow", "IframeRedirection", 
    "LinksPointingToPage"
]

# Features that require WHOIS registration data
FEATURES_NEEDING_WHOIS = [
    "DomainRegLen", "AbnormalURL", "AgeofDomain", "DNSRecording"
]

FEATURE_SEVERITY = {
    "critical": {
        "weight": 3.0,
        "features": [
            "UsingIP", "ServerFormHandler", "FreeHosting", "StatsReport", "DomainEntropy"
        ]
    },
    "high": {
        "weight": 2.0,
        "features": [
            "RequestURL", "AnchorURL", "LinksInScriptTags", "WebsiteForwarding",
            "HTTPS", "AbnormalURL", "IframeRedirection"
        ]
    },
    "medium": {
        "weight": 1.5,
        "features": [
            "AgeofDomain", "DomainRegLen", "DNSRecording", "SubDomains",
            "PrefixSuffix-", "DisableRightClick", "UsingPopupWindow"
        ]
    },
    "low": {
        "weight": 1.0,
        "features": [
            "LongURL", "ShortURL", "Symbol@", "Redirecting//", "InfoEmail",
            "StatusBarCust", "LinksPointingToPage", "Favicon", "NonStdPort", "HTTPSDomainURL", "PageRank"
        ]
    }
}
