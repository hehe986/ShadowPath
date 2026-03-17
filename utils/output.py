from utils.logger import Logger


class OutputFormatter:

    @staticmethod
    def print_summary(target, github_count, total_endpoints):

        print()
        Logger.info(f"Target              : {target}")
        Logger.info(f"GitHub Results      : {github_count} files")
        Logger.info(f"Extracted Endpoints : {total_endpoints}")
        print()

    @staticmethod
    def print_section(title, data):

        print("=" * 40)
        print(f"{title} ({len(data)})")
        print("=" * 40)
        print()

        for item in sorted(data):
            print(item)

        print()

    @staticmethod
    def print_results(classified_data):

        public = classified_data.get("public", [])
        hidden = classified_data.get("hidden", [])

        if public:
            OutputFormatter.print_section("PUBLIC ENDPOINTS", public)

        if hidden:
            OutputFormatter.print_section("HIDDEN ENDPOINTS", hidden)

    @staticmethod
    def print_parameters(param_data):

        print("=" * 40)
        print(f"PARAMETERS ({param_data.get('total', 0)})")
        print("=" * 40)
        print()

        for p in sorted(param_data.get("all", [])):
            print(p)

        print()

    @staticmethod
    def save_to_file(path, classified_data):

        try:
            with open(path, "w") as f:

                f.write("=== PUBLIC ===\n")
                for ep in classified_data.get("public", []):
                    f.write(ep + "\n")

                f.write("\n=== HIDDEN ===\n")
                for ep in classified_data.get("hidden", []):
                    f.write(ep + "\n")

        except Exception as e:
            Logger.error(f"Failed to save file: {e}")