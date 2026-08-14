import json
import os
import datetime
from utils.logger import Logger
from utils.helpers import status_label, truncate, deduplicate


class OutputFormatter:

    # =========================
    # 📊 SUMMARY
    # =========================
    @staticmethod
    def print_summary(target: str, scan_stats: dict):
        """Print ringkasan hasil scan."""
        print()
        Logger.section("SCAN SUMMARY")
        print(f"  Target          : {target}")
        print(f"  Scan Time       : {Logger.timestamp()}")
        print()

        src = scan_stats.get("source_results", {})
        if src:
            print(f"  GitHub files    : {src.get('github', 0)}")
            print(f"  GitLab files    : {src.get('gitlab', 0)}")
            print(f"  Bitbucket files : {src.get('bitbucket', 0)}")
            print()

        ep = scan_stats.get("endpoints", {})
        if ep:
            print(f"  Endpoints extracted : {ep.get('total_extracted', 0)}")
            print(f"  After filter        : {ep.get('after_filter', 0)}")
            print(f"  Validated           : {ep.get('validated', 0)}")
            print(f"  Unique response     : {ep.get('unique_response', 0)}")
            print()

        pm = scan_stats.get("parameters", {})
        if pm:
            print(f"  Parameters found    : {pm.get('total', 0)}")
            print(f"  Sensitive params    : {pm.get('sensitive', 0)}")
        print()

    # =========================
    # 🔍 ENDPOINT RESULTS (4-WAY)
    # =========================
    @staticmethod
    def print_results(classified_data: dict, raw_results: list = None):
        """
        Print hasil klasifikasi endpoint dengan pemisahan 4-way:
          - private_open   ⚠️ private tapi TERBUKA (temuan paling menarik)
          - public_open    ✅ public, accessible
          - private_closed 🔒 private, tertutup (401/403)
          - public_closed  ⚪ public, tapi tertutup

        Fallback ke legacy 3-way (public/hidden/sensitive) jika key baru tidak ada.
        """
        # Build index dari raw untuk lookup detail
        detail_index = {}
        if raw_results:
            for r in raw_results:
                detail_index[r.get("url")] = r

        # Deteksi apakah data sudah pakai skema 4-way
        has_new_schema = any(k in classified_data for k in
            ("private_open", "public_open", "private_closed", "public_closed"))

        if has_new_schema:
            categories = [
                ("private_open",   "⚠️  PRIVATE-OPEN  — Endpoint sensitif TERBUKA (prioritas tinggi)"),
                ("public_open",    "✅ PUBLIC-OPEN    — Endpoint umum, accessible"),
                ("private_closed", "🔒 PRIVATE-CLOSED — Endpoint sensitif tapi terkunci (401/403)"),
                ("public_closed",  "⚪ PUBLIC-CLOSED  — Endpoint umum, tidak ditemukan (404) atau tertutup"),
            ]
        else:
            # Legacy 3-way fallback
            categories = [
                ("sensitive", "🔴 SENSITIVE ENDPOINTS"),
                ("hidden",    "🟡 HIDDEN ENDPOINTS (401/403)"),
                ("public",    "🟢 PUBLIC ENDPOINTS (200)"),
                ("redirect",  "🔵 REDIRECT ENDPOINTS"),
            ]

        any_found = False
        for key, title in categories:
            items = classified_data.get(key, [])
            if not items:
                continue
            any_found = True
            Logger.section(f"{title} ({len(items)})")
            for url in sorted(items):
                detail = detail_index.get(url, {})
                status  = detail.get("status_code", "")
                length  = detail.get("content_length", "")
                redir   = detail.get("redirect_url", "")
                server  = detail.get("server", "")

                extra_parts = []
                if length:
                    extra_parts.append(f"len:{length}")
                if server:
                    extra_parts.append(f"server:{server}")
                if redir:
                    extra_parts.append(f"→ {truncate(redir, 50)}")
                extra = "  " + "  ".join(extra_parts) if extra_parts else ""

                if status:
                    Logger.finding(status, url, extra)
                else:
                    print(f"  {url}{extra}")
            print()

        if not any_found:
            Logger.warn("No endpoints to display")

    # =========================
    # ⚠️ DUPLICATE REPORT
    # =========================
    @staticmethod
    def print_duplicate_report(dup_analysis: dict):
        if not dup_analysis:
            return

        s = dup_analysis.get("summary", {})
        if not s.get("exact_duplicates") and not s.get("similar_pairs"):
            return

        Logger.section("⚠️  DUPLICATE / SIMILAR ENDPOINT ANALYSIS")
        print(f"  Unique responses    : {s.get('unique', 0)}")
        print(f"  Exact duplicates    : {s.get('exact_duplicates', 0)}")
        print(f"  Similar pairs       : {s.get('similar_pairs', 0)}")
        print()

        grps = dup_analysis.get("duplicate_groups", [])
        if grps:
            print("  🔴 IDENTICAL RESPONSE GROUPS:")
            for i, grp in enumerate(grps, 1):
                print(f"    Group {i}:")
                for url in grp:
                    print(f"      - {url}")
            print()

        pairs = dup_analysis.get("similar_pairs", [])
        if pairs:
            print("  🟡 SIMILAR PAIRS:")
            for pair in pairs:
                sim = pair.get("similarity", 0)
                print(f"    [{sim:.0%}] {pair.get('url_a')}")
                print(f"          └─ {pair.get('url_b')}")
            print()

        warnings = dup_analysis.get("warnings", {})
        if warnings:
            print("  ⚠️  WARNINGS:")
            for url, msg in warnings.items():
                Logger.warning_duplicate(msg)
                print(f"       {url}")
        print()

    # =========================
    # 🔑 PARAMETER RESULTS
    # =========================
    @staticmethod
    def print_parameters(param_data: dict):
        Logger.section(f"PARAMETERS ({param_data.get('total', 0)})")

        sensitive = param_data.get("sensitive", [])
        if sensitive:
            print("  🔴 Sensitive:")
            for p in sorted(sensitive):
                print(f"    - {p}")
            print()

        cats = param_data.get("by_category", {})
        for cat, params in cats.items():
            if not params:
                continue
            non_sensitive = [p for p in params if p not in sensitive]
            if not non_sensitive:
                continue
            print(f"  [{cat.upper()}]")
            for p in sorted(non_sensitive):
                print(f"    - {p}")
            print()

        qs = param_data.get("query_string_template", "")
        if qs:
            print(f"  Query template : {qs}")
        print()

    # =========================
    # 🏷️ SCORED ENDPOINTS
    # =========================
    @staticmethod
    def print_scored(scored: list, top: int = 15):
        if not scored:
            return
        Logger.section(f"TOP {top} HIGH-INTEREST ENDPOINTS (by score)")
        for item in scored[:top]:
            score = item.get("score", 0)
            ep    = item.get("endpoint", "")
            bar   = "█" * min(score, 10)
            print(f"  [{score:>2}] {bar:<10}  {ep}")
        print()

    # =========================
    # 💾 SAVE TO FILE
    # =========================
    @staticmethod
    def save_txt(path: str, classified_data: dict, param_data: dict = None,
                 dup_analysis: dict = None, target: str = ""):
        """Simpan hasil ke .txt dengan format yang rapi."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
            with open(path, "w", encoding="utf-8") as f:
                f.write("# ╔══════════════════════════════════════════════════╗\n")
                f.write("# ║      ShadowPath - Endpoint Discovery Results      ║\n")
                f.write("# ╚══════════════════════════════════════════════════╝\n")
                f.write(f"# Target      : {target}\n")
                f.write(f"# Total Found : {sum(len(v) for v in classified_data.values())}\n")
                f.write("#\n\n")

                # Deteksi skema baru vs legacy
                has_new_schema = any(k in classified_data for k in
                    ("private_open", "public_open", "private_closed", "public_closed"))

                if has_new_schema:
                    sections = [
                        ("private_open",   "[PRIVATE-OPEN]   Endpoint sensitif TERBUKA — prioritas tinggi"),
                        ("public_open",    "[PUBLIC-OPEN]    Endpoint umum, accessible"),
                        ("private_closed", "[PRIVATE-CLOSED] Endpoint sensitif tertutup (401/403)"),
                        ("public_closed",  "[PUBLIC-CLOSED]  Endpoint umum tapi tidak accessible (404)"),
                    ]
                else:
                    sections = [
                        ("sensitive", "[SENSITIVE] Auth/Token/Key Endpoints"),
                        ("hidden",    "[HIDDEN]    Status 401/403"),
                        ("public",    "[PUBLIC]    Status 200"),
                        ("redirect",  "[REDIRECT]  301/302"),
                    ]
                for key, title in sections:
                    items = classified_data.get(key, [])
                    if not items:
                        continue
                    f.write(f"# {'═' * 44}\n")
                    f.write(f"# {title} ({len(items)})\n")
                    f.write(f"# {'═' * 44}\n")
                    for ep in sorted(items):
                        f.write(ep + "\n")
                    f.write("\n")

                # Duplicate warnings
                if dup_analysis:
                    warnings = dup_analysis.get("warnings", {})
                    if warnings:
                        f.write(f"# {'═' * 44}\n")
                        f.write("# [DUPLICATE WARNINGS]\n")
                        f.write(f"# {'═' * 44}\n")
                        for url, msg in warnings.items():
                            f.write(f"# {msg}\n")
                            f.write(f"# URL: {url}\n")
                        f.write("\n")

                # Parameters
                if param_data and param_data.get("all"):
                    f.write(f"# {'═' * 44}\n")
                    f.write(f"# [PARAMETERS] ({param_data.get('total', 0)})\n")
                    f.write(f"# {'═' * 44}\n")
                    for p in sorted(param_data.get("all", [])):
                        f.write(p + "\n")
                    qs = param_data.get("query_string_template", "")
                    if qs:
                        f.write(f"\n# Query template: {qs}\n")

            Logger.success(f"Saved: {path}")
            return True
        except Exception as e:
            Logger.error(f"Failed to save TXT: {e}")
            return False

    @staticmethod
    def save_json(path: str, scan_result: dict):
        """Simpan full scan result ke JSON."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None

            # Tambah timestamp ke result
            scan_result.setdefault("meta", {})
            scan_result["meta"]["saved_at"] = datetime.datetime.now().isoformat()

            with open(path, "w", encoding="utf-8") as f:
                json.dump(scan_result, f, indent=2, ensure_ascii=False)
            Logger.success(f"Saved: {path}")
            return True
        except Exception as e:
            Logger.error(f"Failed to save JSON: {e}")
            return False

    # =========================
    # 🖨️ LEGACY COMPAT
    # =========================
    @staticmethod
    def print_section(title: str, data: list):
        """Backward compat — print section sederhana."""
        print("=" * 45)
        print(f"{title} ({len(data)})")
        print("=" * 45)
        for item in sorted(data):
            print(f"  {item}")
        print()

    @staticmethod
    def save_to_file(path: str, classified_data: dict):
        """Backward compat — simple save."""
        OutputFormatter.save_txt(path, classified_data)
