from urllib.parse import urlparse


class DomainFilter:
    def __init__(self, target_domain: str, include_subdomains: bool = True):
        """
        Args:
            target_domain: domain target, misal 'example.com' atau 'sub.example.com'
            include_subdomains: jika True, subdomain juga diterima (sub.example.com, api.example.com, dll)
        """
        self.target = self._normalize_domain(target_domain)
        self.include_subdomains = include_subdomains

        # Domain yang selalu diblok (internal/loopback saja)
        self.blocked_domains = {
            "localhost", "127.0.0.1", "0.0.0.0", "::1",
        }

    def _normalize_domain(self, domain: str) -> str:
        """Strip protokol, path, trailing slash dari domain."""
        domain = domain.lower().strip()
        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0]  # buang path
        domain = domain.split("?")[0]  # buang query
        return domain

    # =========================
    # ✅ VALIDASI SINGLE URL
    # =========================
    def is_valid(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()

            if not netloc:
                return False

            # Buang port jika ada
            host = netloc.split(":")[0]

            # Cek blocked
            if host in self.blocked_domains:
                return False

            # Exact match
            if host == self.target:
                return True

            # Subdomain match
            if self.include_subdomains:
                if host.endswith("." + self.target):
                    return True

            return False

        except Exception:
            return False

    # =========================
    # 🔍 FILTER LIST
    # =========================
    def filter(self, endpoints: list) -> list:
        results = []
        for ep in endpoints:
            if self.is_valid(ep):
                results.append(ep)
        return list(set(results))

    # =========================
    # 🔗 FILTER + RELATIVE PATH BUILDER
    # =========================
    def filter_and_build(self, endpoints: list) -> list:
        """
        Filter endpoint, dan untuk path relative (misal /api/v1/users)
        otomatis gabungkan dengan domain target.
        Returns list URL lengkap yang valid.
        """
        results = set()
        base = f"https://{self.target}"

        for ep in endpoints:
            ep = ep.strip()
            if not ep:
                continue

            if ep.startswith("/"):
                # Path relative → gabung dengan domain target
                results.add(base + ep)
            elif ep.startswith("http"):
                # URL lengkap → filter biasa
                if self.is_valid(ep):
                    results.add(ep)

        return list(results)

    # =========================
    # 🌐 EXTRACT SUBDOMAINS
    # =========================
    def extract_subdomains(self, endpoints: list) -> list:
        """
        Dari list URL, extract semua subdomain unik yang ditemukan
        untuk target domain ini.
        """
        subdomains = set()
        for ep in endpoints:
            try:
                parsed = urlparse(ep)
                host = parsed.netloc.lower().split(":")[0]
                if host.endswith("." + self.target) and host != self.target:
                    subdomains.add(host)
            except Exception:
                continue
        return list(subdomains)

    # =========================
    # 📊 FILTER WITH STATS
    # =========================
    def filter_with_stats(self, endpoints: list) -> dict:
        """
        Filter dan return statistik hasilnya.
        """
        valid = []
        invalid = []
        subdomains_found = set()

        for ep in endpoints:
            if self.is_valid(ep):
                valid.append(ep)
                try:
                    host = urlparse(ep).netloc.lower().split(":")[0]
                    if host != self.target:
                        subdomains_found.add(host)
                except Exception:
                    pass
            else:
                invalid.append(ep)

        return {
            "valid": list(set(valid)),
            "invalid": list(set(invalid)),
            "subdomains": list(subdomains_found),
            "summary": {
                "total": len(endpoints),
                "valid": len(valid),
                "invalid": len(invalid),
                "subdomains_found": len(subdomains_found),
            }
        }
