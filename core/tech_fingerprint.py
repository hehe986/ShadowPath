"""
core/tech_fingerprint.py - Technology Detection Engine
=======================================================
Deteksi teknologi yang dipakai target dari HTTP header + HTML content,
tanpa dependency eksternal (murni regex + pattern matching).

Kategori yang dideteksi:
  - Web Server        (nginx, Apache, IIS, LiteSpeed, ...)
  - Programming Lang  (PHP, ASP.NET, Java, Python, Ruby, Node, ...)
  - Framework         (Laravel, Django, Rails, Express, Spring, ...)
  - CMS               (WordPress, Joomla, Drupal, Magento, ...)
  - JS Library        (jQuery, React, Vue, Angular, Bootstrap, ...)
  - CDN               (Cloudflare, Akamai, Fastly, CloudFront, ...)
  - WAF               (Cloudflare, Sucuri, Imperva, ModSecurity, ...)
  - Analytics         (Google Analytics, GTM, Hotjar, ...)

Semua pattern berbasis signature publik (Wappalyzer-style, disederhanakan).
"""

import re


# =============================================================
# SIGNATURE DATABASE
# =============================================================
# Format: kategori -> {nama_teknologi: {header/html/cookie patterns}}

_SIGNATURES = {
    "server": {
        "nginx":        {"header": {"server": r"nginx"}},
        "Apache":       {"header": {"server": r"apache"}},
        "Microsoft-IIS":{"header": {"server": r"microsoft-iis|iis"}},
        "LiteSpeed":    {"header": {"server": r"litespeed"}},
        "OpenResty":    {"header": {"server": r"openresty"}},
        "Caddy":        {"header": {"server": r"caddy"}},
        "Tomcat":       {"header": {"server": r"tomcat|coyote"}},
        "Gunicorn":     {"header": {"server": r"gunicorn"}},
        "Kestrel":      {"header": {"server": r"kestrel"}},
        "Cloudflare":   {"header": {"server": r"cloudflare"}},
    },
    "language": {
        "PHP":       {"header": {"x-powered-by": r"php", "set-cookie": r"phpsessid"}},
        "ASP.NET":   {"header": {"x-powered-by": r"asp\.net", "x-aspnet-version": r".+"},
                      "html": r"__viewstate|asp\.net|\.aspx"},
        "Java":      {"header": {"set-cookie": r"jsessionid"}},
        "Python":    {"header": {"server": r"gunicorn|werkzeug|wsgiserver"}},
        "Ruby":      {"header": {"server": r"passenger|puma|unicorn"}},
        "Node.js":   {"header": {"x-powered-by": r"express"}},
        "Perl":      {"header": {"x-powered-by": r"perl"}},
        "ColdFusion":{"header": {"set-cookie": r"cfid|cftoken"}},
    },
    "framework": {
        "Laravel":     {"header": {"set-cookie": r"laravel_session"}, "html": r"laravel"},
        "Django":      {"header": {"set-cookie": r"csrftoken|django"}, "html": r"csrfmiddlewaretoken"},
        "Ruby on Rails":{"header": {"set-cookie": r"_rails|_session_id", "x-powered-by": r"rails"}},
        "Express":     {"header": {"x-powered-by": r"express"}},
        "Spring":      {"html": r"spring", "header": {"x-application-context": r".+"}},
        "Flask":       {"header": {"server": r"werkzeug"}},
        "CodeIgniter": {"header": {"set-cookie": r"ci_session"}},
        "Symfony":     {"header": {"set-cookie": r"symfony"}, "html": r"symfony"},
        "Next.js":     {"html": r"__next|_next/static", "header": {"x-powered-by": r"next\.js"}},
        "Nuxt.js":     {"html": r"__nuxt|_nuxt/"},
        "ASP.NET MVC": {"header": {"x-aspnetmvc-version": r".+"}},
    },
    "cms": {
        "WordPress":   {"html": r"wp-content|wp-includes|/wp-json", "header": {"x-powered-by": r"w3\s?total\s?cache"}},
        "Joomla":      {"html": r"joomla|/media/jui/", "header": {"x-content-encoded-by": r"joomla"}},
        "Drupal":      {"html": r"drupal|/sites/default/files", "header": {"x-generator": r"drupal", "x-drupal-cache": r".+"}},
        "Magento":     {"html": r"magento|/skin/frontend|mage/", "header": {"set-cookie": r"frontend="}},
        "Shopify":     {"html": r"shopify|cdn\.shopify", "header": {"x-shopify-stage": r".+"}},
        "Wix":         {"html": r"wix\.com|_wixcss_", "header": {"x-wix-request-id": r".+"}},
        "Ghost":       {"html": r"ghost|/ghost/", "header": {"x-powered-by": r"express"}},
        "PrestaShop":  {"html": r"prestashop", "header": {"set-cookie": r"prestashop"}},
        "TYPO3":       {"html": r"typo3|/typo3conf/"},
        "Blogger":     {"html": r"blogger\.com|blogspot"},
    },
    "js_library": {
        "jQuery":      {"html": r"jquery[.-]?[\d.]*\.js|jquery\.min\.js|jquery\.js"},
        "React":       {"html": r"react[.-]?[\d.]*\.js|react-dom|_reactroot|data-reactroot"},
        "Vue.js":      {"html": r"vue[.-]?[\d.]*\.js|vue\.min\.js|__vue__|data-v-"},
        "Angular":     {"html": r"angular[.-]?[\d.]*\.js|ng-version|ng-app|\[ng"},
        "Bootstrap":   {"html": r"bootstrap[.-]?[\d.]*\.(css|js)|bootstrap\.min"},
        "Lodash":      {"html": r"lodash[.-]?[\d.]*\.js|lodash\.min"},
        "Moment.js":   {"html": r"moment[.-]?[\d.]*\.js|moment\.min"},
        "D3.js":       {"html": r"d3[.-]?[\d.]*\.js|d3\.min|d3\.v\d"},
        "Font Awesome":{"html": r"font-?awesome|fa-[a-z]+"},
        "Tailwind CSS":{"html": r"tailwind|tw-[a-z]+"},
        "Alpine.js":   {"html": r"alpine[.-]?[\d.]*\.js|x-data="},
        "GSAP":        {"html": r"gsap|greensock"},
    },
    "cdn": {
        "Cloudflare":  {"header": {"server": r"cloudflare", "cf-ray": r".+"}},
        "Akamai":      {"header": {"server": r"akamai", "x-akamai-transformed": r".+"}},
        "Fastly":      {"header": {"x-served-by": r"fastly", "x-fastly-request-id": r".+"}},
        "CloudFront":  {"header": {"x-amz-cf-id": r".+", "via": r"cloudfront"}},
        "Sucuri":      {"header": {"x-sucuri-id": r".+", "server": r"sucuri"}},
        "KeyCDN":      {"header": {"server": r"keycdn"}},
        "MaxCDN":      {"header": {"x-cdn": r"maxcdn"}},
        "jsDelivr":    {"html": r"cdn\.jsdelivr\.net"},
        "Google CDN":  {"html": r"ajax\.googleapis\.com"},
        "cdnjs":       {"html": r"cdnjs\.cloudflare\.com"},
    },
    "waf": {
        "Cloudflare WAF": {"header": {"cf-ray": r".+", "server": r"cloudflare"}},
        "Sucuri WAF":     {"header": {"x-sucuri-id": r".+", "x-sucuri-cache": r".+"}},
        "Imperva/Incapsula": {"header": {"x-iinfo": r".+", "set-cookie": r"incap_ses|visid_incap"}},
        "Akamai WAF":     {"header": {"server": r"akamaighost"}},
        "F5 BIG-IP":      {"header": {"server": r"big-?ip", "set-cookie": r"bigipserver"}},
        "Barracuda":      {"header": {"server": r"barracuda"}},
        "ModSecurity":    {"header": {"server": r"mod_security|modsecurity"}},
        "AWS WAF":        {"header": {"x-amzn-requestid": r".+", "x-amz-cf-id": r".+"}},
        "Wordfence":      {"html": r"wordfence", "header": {"x-wf-": r".+"}},
    },
    "analytics": {
        "Google Analytics":  {"html": r"google-analytics\.com|gtag\(|ga\('create'|_gaq"},
        "Google Tag Manager":{"html": r"googletagmanager\.com|gtm\.js|dataLayer"},
        "Hotjar":            {"html": r"hotjar\.com|hjSetting"},
        "Facebook Pixel":    {"html": r"connect\.facebook\.net|fbq\("},
        "Mixpanel":          {"html": r"mixpanel"},
        "Segment":           {"html": r"segment\.com|analytics\.js"},
        "Matomo/Piwik":      {"html": r"matomo|piwik"},
    },
}


# =============================================================
# FINGERPRINT ENGINE
# =============================================================
class TechFingerprint:
    """Deteksi teknologi dari HTTP response (header + HTML)."""

    def analyze(self, headers: dict, html: str = "",
                cookies: str = "") -> dict:
        """
        Analisa satu response.

        Args:
            headers: dict HTTP response headers (case-insensitive keys)
            html: body HTML (opsional)
            cookies: string Set-Cookie (opsional, atau ambil dari headers)

        Returns dict:
            {kategori: [list teknologi terdeteksi]}
        """
        # Normalisasi header keys ke lowercase
        h = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
        html_low = (html or "").lower()

        # Set-Cookie bisa dari param atau header
        if not cookies:
            cookies = h.get("set-cookie", "")
        cookies = cookies.lower()

        detected = {}

        for category, techs in _SIGNATURES.items():
            found = []
            for tech_name, patterns in techs.items():
                if self._match(patterns, h, html_low, cookies):
                    found.append(tech_name)
            if found:
                detected[category] = found

        return detected

    def _match(self, patterns: dict, headers: dict,
               html: str, cookies: str) -> bool:
        """Cek apakah signature cocok. Cukup 1 pattern match = detected."""
        # Header patterns
        header_pats = patterns.get("header", {})
        for hkey, hpat in header_pats.items():
            hkey = hkey.lower()
            # Cek di header spesifik
            if hkey in headers:
                if re.search(hpat, headers[hkey], re.IGNORECASE):
                    return True
            # set-cookie kadang perlu cek terpisah
            if hkey == "set-cookie" and cookies:
                if re.search(hpat, cookies, re.IGNORECASE):
                    return True

        # HTML pattern
        html_pat = patterns.get("html")
        if html_pat and html:
            if re.search(html_pat, html, re.IGNORECASE):
                return True

        return False

    def analyze_multiple(self, responses: list) -> dict:
        """
        Analisa banyak response, gabungkan hasilnya.

        Args:
            responses: list of dict {headers, content}

        Returns dict {kategori: [tech unik]}
        """
        aggregated = {}
        for resp in responses:
            headers = resp.get("headers", {})
            html    = resp.get("content", "")
            result  = self.analyze(headers, html)
            for cat, techs in result.items():
                aggregated.setdefault(cat, set()).update(techs)

        # Convert set -> sorted list
        return {cat: sorted(techs) for cat, techs in aggregated.items()}

    @staticmethod
    def extract_version(html: str, tech: str) -> str:
        """
        Coba ekstrak versi teknologi dari HTML (best-effort).
        Contoh: jQuery v3.6.0, Bootstrap 5.1.3
        """
        patterns = {
            "jQuery":    r"jquery[/-]?v?(\d+\.\d+\.\d+)",
            "Bootstrap": r"bootstrap[/-]?v?(\d+\.\d+\.\d+)",
            "React":     r"react[/-]?v?(\d+\.\d+\.\d+)",
            "Vue.js":    r"vue[/-]?v?(\d+\.\d+\.\d+)",
            "Angular":   r"ng-version=\"(\d+\.\d+\.\d+)",
            "WordPress": r"wordpress\s+(\d+\.\d+(?:\.\d+)?)",
        }
        pat = patterns.get(tech)
        if pat and html:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                return m.group(1)
        return ""

    def summarize(self, detected: dict) -> str:
        """Format hasil deteksi jadi string ringkas untuk log."""
        if not detected:
            return "No technology detected"
        parts = []
        priority = ["server", "language", "framework", "cms",
                    "js_library", "cdn", "waf", "analytics"]
        for cat in priority:
            if cat in detected:
                techs = ", ".join(detected[cat])
                label = cat.replace("_", " ").title()
                parts.append(f"{label}: {techs}")
        return " | ".join(parts)
