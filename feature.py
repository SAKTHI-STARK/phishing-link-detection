import ssl
import ipaddress
import re
import socket
import requests
import whois
import logging
from bs4 import BeautifulSoup
from googlesearch import search
from datetime import date
from urllib.parse import urlparse

import asyncio
from config import (
    SHORTENER_REGEX, FEATURE_METHODS, DEFAULT_FEATURE_NAMES, 
    FEATURES_NEEDING_HTML, FEATURES_NEEDING_WHOIS
)

# Configure logging
logger = logging.getLogger(__name__)

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None
        self.features_dict = {}
        self.ssl_error = False
        self.connection_failed = False

        # Events for dependency synchronization
        self._html_event = asyncio.Event()
        self._whois_event = asyncio.Event()

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except Exception as e:
            logger.debug(f"Failed to parse URL {url}: {e}")

    async def _setup_html(self):
        """Fetch page content in parallel."""
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        try:
            # Use to_thread for blocking requests call
            resp = await asyncio.to_thread(requests.get, self.url, timeout=5, headers=headers)
            self.response = resp
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except requests.exceptions.SSLError:
            self.ssl_error = True
        except Exception:
            self.connection_failed = True
        finally:
            self._html_event.set()

    async def _setup_whois(self):
        """Fetch WHOIS data in parallel."""
        try:
            self.whois_response = await asyncio.to_thread(whois.whois, self.domain)
        except Exception:
            pass
        finally:
            self._whois_event.set()

    async def _run_check(self, name, method_name):
        """Run a single feature check, waiting for dependencies if necessary."""
        try:
            if name in FEATURES_NEEDING_HTML:
                await self._html_event.wait()
            elif name in FEATURES_NEEDING_WHOIS:
                await self._whois_event.wait()
            
            # Run the actual sync method in a separate thread to keep the event loop responsive
            method = getattr(self, method_name)
            self.features_dict[name] = await asyncio.to_thread(method)
        except Exception:
            self.features_dict[name] = -1

    async def extract(self):
        """Coordinate parallel execution of setup tasks and all feature checks."""
        # 1. Start setup tasks
        setup_tasks = [
            asyncio.create_task(self._setup_html()),
            asyncio.create_task(self._setup_whois())
        ]

        # 2. Start all feature checks
        check_tasks = [
            self._run_check(name, method_name) 
            for name, method_name in FEATURE_METHODS.items()
        ]

        # 3. Wait for everything to complete
        await asyncio.gather(*setup_tasks, *check_tasks)

    def extract_all_to_dict(self):
        """Legacy method - now triggers a warning or should be avoided in async flow."""
        pass

    def getFeaturesList(self, feature_names=None):
        """
        Returns features in the order specified by feature_names.
        If feature_names is None, it defaults to the original 30 features.
        """
        if feature_names is None:
            feature_names = DEFAULT_FEATURE_NAMES
        
        return [self.features_dict.get(name, -1) for name in feature_names]



    # --- Feature implementation methods ---
    def UsingIp(self) -> int:
        try:
            hostname = self.urlparse.hostname
            if not hostname:
                return 1
            ipaddress.ip_address(hostname)
            return -1 # It IS an IP address (Phishing)
        except: 
            return 1 # Not an IP (Legitimate domain)

    def longUrl(self) -> int:
        length = len(self.url)
        if length < 54: return 1 # positive
        elif 54 <= length <= 75: return 0 # suspicious
        return -1 # phishing (long URL)

    def shortUrl(self)  -> int:
        """Return -1 if shortened URL (phishing), 1 if legitimate"""
        return -1 if SHORTENER_REGEX.search(self.url) else 1

    def symbol(self) -> int:
        return -1 if "@" in self.url else 1

    def redirecting(self) -> int:
        return -1 if self.url.rfind('//') > 6 else 1

    def prefixSuffix(self) -> int:
        return -1 if '-' in self.domain else 1

    def SubDomains(self) -> int:
        try:
            dots = self.domain.split('.')
            if len(dots) <= 2: return 1
            elif len(dots) == 3: return 0
            return -1
        except: return -1

    def Hppts(self) -> int:
        """
        Returns:
        1  = Trusted CA certificate
        0  = Self-signed certificate
        -1 = No HTTPS
        -2 = Connection failed
        """
        try:
            parsed = urlparse(self.url)

            if parsed.scheme != "https":
                return -1

            hostname = parsed.hostname

            if not hostname:
                return -2

            ctx = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    issuer = cert.get("issuer")
                    subject = cert.get("subject")

                    if issuer == subject:
                        return 0   # self-signed
                    else:
                        return 1   # trusted CA

        except ssl.SSLError:
            return 0

        except Exception:
            return -2

    def DomainRegLen(self) -> int:
        # check if domain is registered for less than 1 year
        try:
            exp = self.whois_response.expiration_date
            create = self.whois_response.creation_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(create, list): create = create[0]
            age = (exp.year - create.year) * 12 + (exp.month - create.month)
            return 1 if age >= 12 else -1
        except: return -1

    def Favicon(self) -> int:
        try:
            if not self.soup: return -1
            for link in self.soup.find_all('link', href=True):
                if self.domain in link['href']: return 1
            return -1
        except: return -1

    def NonStdPort(self) -> int:
        return -1 if ':' in self.domain else 1

    def HTTPSDomainURL(self) -> int:
        # http://https-paypal-login.com return -1
        return -1 if 'https' in self.domain else 1

    def RequestURL(self) -> int:
        try:
            if not self.soup: return -1
            total, success = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    src = element['src']
                    if self.domain in src or self.url in src: success += 1
                    total += 1
            if total == 0: return 0 # Suspicious if no resources found
            percentage = (success / total * 100)
            if percentage < 22: return 1
            elif 22 <= percentage < 61: return 0
            return -1
        except: return -1

    def AnchorURL(self) -> int:
        try:
            if not self.soup: return -1
            total, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                href = a['href'].lower()
                if '#' in href or 'javascript' in href or 'mailto:' in href or (self.domain not in href and self.url not in href):
                    unsafe += 1
                total += 1
            if total == 0: return 0 # Suspicious if no links found
            percentage = (unsafe / total * 100)
            if percentage < 31: return 1
            elif 31 <= percentage < 67: return 0
            return -1
        except: return -1

    def LinksInScriptTags(self) -> int:
        try:
            if not self.soup: return -1
            total, internal = 0, 0
            for tag in self.soup.find_all(['link', 'script']):
                href = tag.get('href') or tag.get('src')
                if href:
                    if self.domain in href or self.url in href: internal += 1
                    total += 1
            if total == 0: return 0
            percentage = (internal / total * 100)
            if percentage < 17: return 1
            elif 17 <= percentage < 81: return 0
            return -1
        except: return -1

    def ServerFormHandler(self) -> int:
        try:
            if not self.soup: return -1
            forms = self.soup.find_all('form', action=True)
            if not forms: return 1
            for form in forms:
                action = form['action']
                if action in ["", "about:blank"]: return -1
                elif self.domain not in action: return 0
            return 1
        except: return -1

    def InfoEmail(self) -> int:
        try: return -1 if re.search(r'mailto:', self.response.text if self.response else "") else 1
        except: return 1

    def AbnormalURL(self) -> int:
        try: return -1 if self.whois_response and self.whois_response.domain_name not in self.url else 1
        except: return 1

    def WebsiteForwarding(self) -> int:
        try:
            if not self.response: return -1
            redirects = len(self.response.history)
            if redirects <= 1: return 1
            elif redirects <= 4: return 0
            return -1
        except: return -1

    def StatusBarCust(self) -> int:
        try: return -1 if re.search("onmouseover=.*status", self.response.text if self.response else "") else 1
        except: return 1

    def DisableRightClick(self) -> int:
        try: return -1 if re.search(r'event.button ?== ?2', self.response.text if self.response else "") else 1
        except: return 1

    def UsingPopupWindow(self) -> int:
        try: return -1 if re.search(r'alert\(', self.response.text if self.response else "") else 1
        except: return 1

    def IframeRedirection(self) -> int:
        try: return -1 if re.search(r'<iframe', self.response.text if self.response else "") else 1
        except: return 1

    def AgeofDomain(self) -> int:
        try:
            creation = self.whois_response.creation_date
            if isinstance(creation, list): creation = creation[0]
            today = date.today()
            age = (today.year - creation.year) * 12 + (today.month - creation.month)
            return 1 if age >= 6 else -1
        except: return -1

    def DNSRecording(self) -> int:
        return self.AgeofDomain()

    def WebsiteTraffic(self) -> int:
        return -1 # Alexa API dead

    def PageRank(self) -> int:
        try:
            response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain}, timeout=5)
            rank = int(re.search(r"Global Rank: ([0-9]+)", response.text).group(1))
            return 1 if rank < 100000 else -1
        except: return -1

    def GoogleIndex(self) -> int:
        try:
            return 1 if list(search(self.url, num=1)) else -1
        except: return -1

    def LinksPointingToPage(self) -> int:
        try:
            if not self.response: return -1
            links = re.findall(r"<a href=", self.response.text)
            if len(links) == 0: return 1
            elif len(links) <= 2: return 0
            return -1
        except: return -1

    def StatsReport(self) -> int:
        try:
            bad_url = re.search(r'at\.ua|usa\.cc|96\.lt|ow\.ly', self.url)
            ip = socket.gethostbyname(self.domain)
            bad_ip = re.search(r'146\.112\.61\.108|216\.218\.185\.162', ip)
            return -1 if bad_url or bad_ip else 1
        except: return -1
