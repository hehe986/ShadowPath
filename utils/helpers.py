import re


def clean_url(url):

    if not url:
        return None

    url = url.strip()

    # hapus double slash
    url = re.sub(r'(?<!:)//+', '/', url)

    return url


def normalize_domain(domain):

    domain = domain.lower().strip()

    domain = domain.replace("http://", "")
    domain = domain.replace("https://", "")
    domain = domain.split("/")[0]

    return domain


def deduplicate(data):

    return list(set(data))


def sort_list(data):

    return sorted(data)


def is_valid_string(s, min_length=3):

    if not s:
        return False

    return len(s.strip()) >= min_length