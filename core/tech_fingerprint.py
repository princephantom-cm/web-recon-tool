import requests
import re
from typing import Dict, List

TECH_SIGNATURES = {
    # CMS
    "WordPress":        ["wp-content", "wp-includes", "wp-json", "wordpress"],
    "Joomla":           ["joomla", "/components/com_", "mosConfig"],
    "Drupal":           ["drupal", "sites/default", "Drupal.settings"],
    "Ghost":            ["ghost-theme", "content=\"Ghost"],
    "Shopify":          ["cdn.shopify.com", "shopify.com/s/files"],
    "Magento":          ["magento", "mage/cookies"],
    "Wix":              ["wix.com", "X-Wix-Published-Version"],
    "Squarespace":      ["squarespace.com", "static.squarespace.com"],

    # Frameworks
    "React":            ["react.development.js", "react.production.min.js", "__REACT", "_reactFiber", "react-root"],
    "Next.js":          ["/_next/static", "__NEXT_DATA__", "next/dist"],
    "Vue.js":           ["vue.min.js", "vue.js", "__vue__", "data-v-"],
    "Angular":          ["ng-version", "angular.min.js", "ng-app", "angular/core"],
    "Nuxt.js":          ["__nuxt", "_nuxt/", "window.__NUXT__"],
    "Svelte":           ["__svelte", "svelte-"],
    "Django":           ["csrfmiddlewaretoken", "django", "__django"],
    "Laravel":          ["laravel_session", "laravel", "XSRF-TOKEN"],
    "Ruby on Rails":    ["x-runtime", "x-powered-by: phusion passenger", "_rails"],
    "ASP.NET":          ["__viewstate", "asp.net", "x-aspnet-version", "x-aspnetmvc-version"],
    "Express.js":       ["x-powered-by: express"],
    "Flask":            ["werkzeug", "flask"],
    "FastAPI":          ["fastapi", "x-process-time"],
    "Spring Boot":      ["x-application-context", "spring"],

    # Servers
    "Apache":           ["apache"],
    "Nginx":            ["nginx"],
    "IIS":              ["microsoft-iis", "x-powered-by: asp.net"],
    "Cloudflare":       ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "Varnish":          ["x-varnish", "via: varnish"],
    "LiteSpeed":        ["litespeed", "x-litespeed-cache"],
    "Caddy":            ["caddy"],

    # Languages
    "PHP":              ["x-powered-by: php", ".php", "phpsessid"],
    "Python":           ["python", "wsgi"],
    "Java":             ["jsessionid", "java", ".jsp", ".do"],
    "Node.js":          ["x-powered-by: express", "node.js"],

    # CDN / Security
    "AWS CloudFront":   ["x-amz-cf-id", "cloudfront.net", "x-amz-request-id"],
    "AWS S3":           ["s3.amazonaws.com", "x-amz-bucket"],
    "Akamai":           ["akamai", "x-akamai-transformed"],
    "Fastly":           ["x-served-by", "fastly"],
    "Sucuri":           ["x-sucuri-id", "sucuri"],
    "Imperva":          ["x-iinfo", "incapsula", "visid_incap"],

    # Analytics / Marketing
    "Google Analytics": ["google-analytics.com", "gtag(", "ga('create"],
    "Google Tag Manager":["googletagmanager.com", "gtm.js"],
    "HubSpot":          ["hubspot", "hs-scripts.com"],
    "Intercom":         ["intercom", "widget.intercom.io"],

    # JS Libraries
    "jQuery":           ["jquery.min.js", "jquery.js", "jquery-"],
    "Bootstrap":        ["bootstrap.min.css", "bootstrap.css", "bootstrap.min.js"],
    "Tailwind CSS":     ["tailwindcss", "tailwind.min.css"],
    "Font Awesome":     ["font-awesome", "fontawesome"],
    "Lodash":           ["lodash.min.js", "lodash.js"],

    # Databases (exposed)
    "MySQL":            ["mysql_connect", "mysqli_"],
    "MongoDB":          ["mongodb://", "mongoclient"],
    "Redis":            ["redis://", "redis-server"],

    # Other
    "Webpack":          ["webpack", "__webpack_require__"],
    "GraphQL":          ["graphql", "/graphql", "__schema"],
    "Elasticsearch":    ["elasticsearch", "_search", "_cluster/health"],
    "Kubernetes":       ["kubernetes", "k8s"],
    "Docker":           ["docker", ".docker.io"],
}

# Headers to check for tech hints
INTERESTING_HEADERS = [
    "Server", "X-Powered-By", "X-Generator", "X-Drupal-Cache",
    "X-WordPress-Cache", "X-Shopify-Stage", "Via", "CF-Ray",
    "X-Varnish", "X-Amz-Cf-Id", "X-Iinfo", "X-Sucuri-ID",
    "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime",
    "X-Application-Context", "X-Litespeed-Cache"
]


def check_meta_tags(body: str) -> List[str]:
    """Extract generator meta tags"""
    found = []
    matches = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
    matches += re.findall(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', body, re.IGNORECASE)
    for m in matches:
        found.append(m.strip())
    return found


def check_script_srcs(body: str) -> List[str]:
    """Extract script src URLs"""
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)


def check_link_hrefs(body: str) -> List[str]:
    """Extract link href URLs"""
    return re.findall(r'<link[^>]+href=["\']([^"\']+)["\']', body, re.IGNORECASE)


def fingerprint_target(url: str) -> Dict:
    if not url.startswith("http"):
        url = f"https://{url}"

    detected = []
    headers_info = {}
    server = ""
    powered_by = ""

    try:
        response = requests.get(
            url,
            timeout=12,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        headers = dict(response.headers)
        body = response.text
        body_lower = body.lower()

        server = headers.get("Server", "")
        powered_by = headers.get("X-Powered-By", "")

        # Collect all header values for matching
        all_header_values = " ".join(
            f"{k.lower()}: {v.lower()}" for k, v in headers.items()
        )

        # Collect script/link sources
        script_srcs = " ".join(check_script_srcs(body)).lower()
        link_hrefs = " ".join(check_link_hrefs(body)).lower()
        meta_generators = check_meta_tags(body)

        # Combined search surface
        search_surface = f"{body_lower} {all_header_values} {script_srcs} {link_hrefs}"

        # Match signatures
        for tech, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in search_surface:
                    if tech not in detected:
                        detected.append(tech)
                    break

        # Add meta generator hits
        for gen in meta_generators:
            gen_clean = gen.split("/")[0].strip()
            if gen_clean and gen_clean not in detected:
                detected.append(gen_clean)

        # Collect interesting headers
        headers_info = {}
        for h in INTERESTING_HEADERS:
            val = headers.get(h, "")
            if val:
                headers_info[h] = val

        # Always include basics
        headers_info["Server"] = server
        headers_info["X-Powered-By"] = powered_by
        headers_info["Content-Type"] = headers.get("Content-Type", "")
        headers_info["X-Frame-Options"] = headers.get("X-Frame-Options", "")
        headers_info["Strict-Transport-Security"] = headers.get("Strict-Transport-Security", "")
        headers_info["Content-Security-Policy"] = headers.get("Content-Security-Policy", "")

        return {
            "url": url,
            "status_code": response.status_code,
            "detected_technologies": detected,
            "headers": headers_info,
            "meta_generators": meta_generators
        }

    except Exception as e:
        return {
            "url": url,
            "status_code": None,
            "detected_technologies": [],
            "headers": {},
            "error": str(e)
        }