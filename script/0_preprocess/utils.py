import tldextract
from Levenshtein import distance as levenshtein
import re
import numpy as np

def isRevDNS(s):
    return "in-addr.arpa" in s or "ip6.arpa" in s
    
def extract_base_name(s):
    #normalize:
    if s[-1] != ".":
        s += "."
    parts = s.split(".")
    dombase = ".".join(s.split(".")[1:])
    
    if isRevDNS(s):
        return dombase
    if s[-1] == "." and len(parts) == 4:
        return dombase
    try:
        ext = tldextract.extract(s)
        if len(ext.top_domain_under_public_suffix)==0:
            return dombase
        else:
            return f"{ext.top_domain_under_public_suffix}."            
    except:
        return dombase

def rename_www_df(df):
    if "base_name" in df.columns:
        df = df.rename(columns={"base_name": "basename"})
    if "probe_fqdn" in df.columns:
        df = df.rename(columns={"probe_fqdn": "query_name"})
    
    if "rtype" in df.columns:
        df = df.rename(columns={"rtype": "query_type"})
        
    if "nsec_next_owner_name" in df.columns:
        df = df.rename(columns={"nsec_next_owner_name": "nsec_next_domain_name"})
    return df

def isCFpattern(rname, nextname):
    rname = rname.lower()
    nextname = nextname.lower()
    return f"\\000.{rname}" == nextname
    
def normalize_dns_name(domain_string):
    """
    Normalizes a DNS label/name by:
    1. Removing escaped octets (e.g., \255, \000).
    2. Retaining only LDH (Letter, Digit, Hyphen) characters.
    """
    if not domain_string:
        return ""

    # 1. Strip escaped octets: matches a backslash followed by exactly 3 digits
    # We use a raw string r'...' to handle the backslashes correctly in Python
    stripped_string = re.sub(r'\\\d{3}', '', domain_string)

    # 2. Retain only Letters, Digits, and Hyphens
    # [^...] is a "negated set", so it replaces anything NOT in that set with an empty string
    normalized_string = re.sub(r'[^a-zA-Z0-9\-\.]', '', stripped_string).lower()
    # 3. STRIP LEADING/TRAILING DOTS
    # This ensures "foo.com" and ".foo.com" split into the same label list
    normalized_string = normalized_string.strip('.')

    return normalized_string

def compare_labels_from_right(d1: str, d2: str, threshold=100):
    d1 = normalize_dns_name(d1)
    d2 = normalize_dns_name(d2)

    labels1 = d1.split('.')
    labels2 = d2.split('.')

    labels1_rev = labels1[::-1]
    labels2_rev = labels2[::-1]

    #results = []
    dist = 0
    for i in range(max(len(labels1_rev), len(labels2_rev))):
        l1 = labels1_rev[i] if i < len(labels1_rev) else None
        l2 = labels2_rev[i] if i < len(labels2_rev) else None

        if l1 is None:
            dist *= 10
            dist += levenshtein("", l2)
        elif l2 is None:
            dist *= 10
            dist += levenshtein(l1, "")
        else:
            dist *= 10
            dist += levenshtein(l1, l2)
    return min(threshold, dist)

def base32hex_to_int(b32hex_str):
    """Converts a Base32hex string (NSEC3 hash) to a large integer."""
    # RFC 4648 Section 7: Base32hex Alphabet
    alphabet = "0123456789abcdefghijklmnopqrstuv"
    char_map = {char: i for i, char in enumerate(alphabet)}
    
    # Clean string (NSEC3 names are case-insensitive)
    b32hex_str = b32hex_str.lower().strip()
    
    num = 0
    for char in b32hex_str:
        if char not in char_map:
            raise ValueError(f"Invalid Base32hex character found: {char}")
        # Each character represents 5 bits
        num = (num << 5) | char_map[char]
    return num

def calculate_log_distance(distance):
    if distance is None:
        return None
    if distance <= 0:
        return 0
    # Use log10 for "human readable" scale or log2 for "bit" scale
    return np.log10(float(distance))
    
def calculate_nsec3_distance(owner_hash, next_owner_hash, datatype="openintel"):
    """Calculates the numerical gap between two NSEC3 hashes."""
    try:
        val1 = base32hex_to_int(owner_hash)
        #val2 = base32hex_to_int(next_owner_hash)
        if datatype != "openintel":
            val2 = base32hex_to_int(next_owner_hash)
        else:
            val2 = int(next_owner_hash.lower(),16)
        # NSEC3 is a circular chain. If next_owner < owner, it wrapped around the zone.
        if val2 < val1:
            distance = val1 - val2
        else:
            distance = val2 - val1
    except:
        distance = None
    return distance


def extract_base(name):
    match = re.search(r'awsdns-\d+', name)
    if match:
        return "awsdns"
    match = re.search(r'ultradns\d+', name)
    if match:
        return "ultradns"

    match = re.search(r'dnsimple(?:-|\d+)?', name)
    if match:
        return "dnsimple"
        
    if re.search(r'^cdmon', name):
        return "cdmon"
    return name
    
def get_ns_dom(ns_l):
    ns_set = set()
    if ns_l is not None:
        for ns in ns_l:
            dom = tldextract.extract(ns).domain
            dom = extract_base(dom)
            ns_set.add(dom)
    return ns_set