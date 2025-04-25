import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None
        self.features = []

        try:
            self.response = requests.get(url, timeout=5)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.extract_features()

    def extract_features(self):
        self.features.extend([
            self.UsingIp(),
            self.longUrl(),
            self.shortUrl(),
            self.symbol(),
            self.redirecting(),
            self.prefixSuffix(),
            self.SubDomains(),
            self.Hppts(),
            self.DomainRegLen(),
            self.Favicon(),
            self.NonStdPort(),
            self.HTTPSDomainURL(),
            self.RequestURL(),
            self.AnchorURL(),
            self.LinksInScriptTags(),
            self.ServerFormHandler(),
            self.InfoEmail(),
            self.AbnormalURL(),
            self.WebsiteForwarding(),
            self.StatusBarCust(),
            self.DisableRightClick(),
            self.UsingPopupWindow(),
            self.IframeRedirection(),
            self.AgeofDomain(),
            self.DNSRecording(),
            self.WebsiteTraffic(),
            self.PageRank(),
            self.GoogleIndex(),
            self.LinksPointingToPage(),
            self.StatsReport()
        ])

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    def longUrl(self):
        length = len(self.url)
        if length < 54:
            return 1
        elif 54 <= length <= 75:
            return 0
        else:
            return -1

    def shortUrl(self):
        shorteners = r'(bit\.ly|goo\.gl|shorte\.st|tinyurl|ow\.ly|t\.co|tr\.im|is\.gd|buff\.ly|adf\.ly|bit\.do|cutt\.ly|tiny\.cc)'
        return -1 if re.search(shorteners, self.url) else 1

    def symbol(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    def prefixSuffix(self):
        return -1 if '-' in self.domain else 1

    def SubDomains(self):
        dots = self.domain.split('.')
        if len(dots) <= 2:
            return 1
        elif len(dots) == 3:
            return 0
        return -1

    def Hppts(self):
        return 1 if self.urlparse and self.urlparse.scheme == 'https' else -1

    def DomainRegLen(self):
        try:
            exp = self.whois_response.expiration_date
            create = self.whois_response.creation_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(create, list): create = create[0]
            age = (exp.year - create.year) * 12 + (exp.month - create.month)
            return 1 if age >= 12 else -1
        except:
            return -1

    def Favicon(self):
        try:
            for link in self.soup.find_all('link', href=True):
                if self.domain in link['href']:
                    return 1
            return -1
        except:
            return -1

    def NonStdPort(self):
        return -1 if ':' in self.domain else 1

    def HTTPSDomainURL(self):
        return -1 if 'https' in self.domain else 1

    def RequestURL(self):
        try:
            total, success = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    src = element['src']
                    if self.domain in src or self.url in src:
                        success += 1
                    total += 1
            percentage = (success / total * 100) if total > 0 else 0
            if percentage < 22:
                return 1
            elif 22 <= percentage < 61:
                return 0
            else:
                return -1
        except:
            return -1

    def AnchorURL(self):
        try:
            total, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                href = a['href'].lower()
                if '#' in href or 'javascript' in href or 'mailto:' in href or (self.domain not in href and self.url not in href):
                    unsafe += 1
                total += 1
            percentage = (unsafe / total * 100) if total > 0 else 0
            if percentage < 31:
                return 1
            elif 31 <= percentage < 67:
                return 0
            else:
                return -1
        except:
            return -1

    def LinksInScriptTags(self):
        try:
            total, internal = 0, 0
            for tag in self.soup.find_all(['link', 'script']):
                href = tag.get('href') or tag.get('src')
                if href:
                    if self.domain in href or self.url in href:
                        internal += 1
                    total += 1
            percentage = (internal / total * 100) if total > 0 else 0
            if percentage < 17:
                return 1
            elif 17 <= percentage < 81:
                return 0
            else:
                return -1
        except:
            return -1

    def ServerFormHandler(self):
        try:
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return 1
            for form in forms:
                action = form['action']
                if action in ["", "about:blank"]:
                    return -1
                elif self.domain not in action:
                    return 0
            return 1
        except:
            return -1

    def InfoEmail(self):
        return -1 if re.search(r'mailto:', self.response.text if self.response else "") else 1

    def AbnormalURL(self):
        return -1 if self.whois_response and self.whois_response.domain_name not in self.url else 1

    def WebsiteForwarding(self):
        try:
            redirects = len(self.response.history)
            if redirects <= 1:
                return 1
            elif redirects <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    def StatusBarCust(self):
        return -1 if re.search("onmouseover=.*status", self.response.text if self.response else "") else 1

    def DisableRightClick(self):
        return -1 if re.search(r'event.button ?== ?2', self.response.text if self.response else "") else 1

    def UsingPopupWindow(self):
        return -1 if re.search(r'alert\(', self.response.text if self.response else "") else 1

    def IframeRedirection(self):
        return -1 if re.search(r'<iframe', self.response.text if self.response else "") else 1

    def AgeofDomain(self):
        try:
            creation = self.whois_response.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            today = date.today()
            age = (today.year - creation.year) * 12 + (today.month - creation.month)
            return 1 if age >= 6 else -1
        except:
            return -1

    def DNSRecording(self):
        return self.AgeofDomain()

    def WebsiteTraffic(self):
        try:
            with urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url) as u:
                soup = BeautifulSoup(u, 'xml')
                rank = soup.find("REACH")['RANK']
                return 1 if int(rank) < 100000 else 0
        except:
            return -1

    def PageRank(self):
        try:
            response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            rank = int(re.search(r"Global Rank: ([0-9]+)", response.text).group(1))
            return 1 if rank < 100000 else -1
        except:
            return -1

    def GoogleIndex(self):
        try:
            return 1 if list(search(self.url, num=1)) else -1
        except:
            return 1

    def LinksPointingToPage(self):
        try:
            links = re.findall(r"<a href=", self.response.text if self.response else "")
            if len(links) == 0:
                return 1
            elif len(links) <= 2:
                return 0
            return -1
        except:
            return -1

    def StatsReport(self):
        try:
            bad_url = re.search(r'at\.ua|usa\.cc|96\.lt|ow\.ly', self.url)
            ip = socket.gethostbyname(self.domain)
            bad_ip = re.search(r'146\.112\.61\.108|216\.218\.185\.162', ip)
            return -1 if bad_url or bad_ip else 1
        except:
            return 1

    def getFeaturesList(self):
        return self.features
