import polars as pl
import pandas as pd
import os
import glob
import re
import json
import pyarrow
import dns.dnssec
import dns.name
from utils import *
from config import *
"""
find wildcard stats and domain that has wildcard.
currently omit the saving domain list due to data release policy.
uncomment below `write file` code to save the domain name in a list.
"""

datestr = "20260406"

def hasNXNAME(nsec_owner_rrset_types):
    return "TYPE128" in nsec_owner_rrset_types

def dns_canonical_compare(name1, name2):
    # 1. Split into labels and reverse (right-to-left) "a.b.com" -> ["com", "b", "a"]
    labels1 = name1.lower().strip('.').split('.')[::-1]
    labels2 = name2.lower().strip('.').split('.')[::-1]
    
    for l1, l2 in zip(labels1, labels2):
        if l1 == l2:
            continue
        # RFC 4034: Shorter labels come first
        if len(l1) != len(l2):
            return len(l1) - len(l2)
        # Same length: Compare octet by octet
        return (l1 > l2) - (l1 < l2)
    
    # If all shared labels match, the one with fewer labels is smaller
    return len(labels1) - len(labels2)

def is_name_covered(owner, next_name, target):
    """
    Checks if 'target' is in the gap between 'owner' and 'next_name'
    using DNS canonical ordering.
    """
    # dns_canonical_compare returns:
    # < 0 if a < b
    # > 0 if a > b
    # 0 if a == b
    
    # 1. Check if the target is exactly one of the boundaries
    if dns_canonical_compare(target, owner) == 0 or \
       dns_canonical_compare(target, next_name) == 0:
        return False

    # 2. Determine if this is a standard record or the wrap-around record
    if dns_canonical_compare(owner, next_name) < 0:
        # Standard Case: Owner < Next (e.g., 'a' to 'c')
        # Target must be between them: owner < target < next
        return dns_canonical_compare(owner, target) < 0 and \
               dns_canonical_compare(target, next_name) < 0
    else:
        # Wrap-around Case: Owner > Next (e.g., 'z' to 'apex')
        # Target is covered if it's AFTER owner OR BEFORE next
        return dns_canonical_compare(target, owner) > 0 or \
               dns_canonical_compare(target, next_name) < 0

def nsec3_hash(name, algorithm, iterations, salt):
    """
    Compute NSEC3 hash of a domain name.
    Returns Base32Hex NSEC3 hash string.
    """

    # dnspython accepts dns.name.Name
    domain = dns.name.from_text(name).canonicalize()

    # Convert salt
    if salt is None or salt == "-" or salt == "":
        salt_bytes = b""
    elif isinstance(salt, bytes):
        salt_bytes = salt
    elif isinstance(salt, str):
        salt_bytes = bytes.fromhex(salt)
    else:
        raise TypeError(f"Unsupported salt type: {type(salt)}")

    return dns.dnssec.nsec3_hash(
        domain=domain,
        salt=salt_bytes,
        iterations=iterations,
        algorithm=algorithm,
    )

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
            return None
            #raise ValueError(f"Invalid Base32hex character found: {char}")
        # Each character represents 5 bits
        num = (num << 5) | char_map[char]
    return num
    
def filter_nsec_wildcard(nsecdf):
    ## nodata responses
    nsec_nodata = nsecdf[nsecdf["status_code"]==0]
    print("NSEC NODATA DF Shape:", nsec_nodata.shape)

    ## has nxname
    nsec_nodata["hasNXNAME"] = nsec_nodata["nsec_owner_rrset_types"].map(hasNXNAME)
    
    # nsec cde with NXNAME domains
    nsec_cde_nxdom = set(nsec_nodata[nsec_nodata["hasNXNAME"]]["base_name"])
    print("NSEC domains w. NXNAME:", len(nsec_cde_nxdom))

     # nsec cde without NXNAME domains
    nsec_nodata_nonx = nsec_nodata[nsec_nodata["hasNXNAME"]==False]
    print("NSEC domains w.o. NXNAME:", nsec_nodata_nonx.shape)

    # check if wildcard is specifically mentioned in response name or next domain name
    wildcard_dom = set(
    nsec_nodata_nonx.loc[nsec_nodata_nonx["response_name"].str.contains(r"\*", regex=True, na=False) |
    nsec_nodata_nonx["nsec_next_domain_name"].str.contains(r"\*", regex=True, na=False), "base_name"])
    print("NSEC domains w. wildcard:",len(wildcard_dom))
    
    # domains that without wildcard being mentioned
    nsec_nodata_nonx_wc = nsec_nodata_nonx[~nsec_nodata_nonx["base_name"].isin(wildcard_dom)].copy()
    print("NSEC domains w.o. wildcard:",nsec_nodata_nonx_wc.shape)

    nsec_nodata_nonx_wc["isWildcardCovered"] = [
        is_name_covered(resp, next_name, f"*.{base}")
        for resp, next_name, base in zip(
            nsec_nodata_nonx_wc["response_name"],
            nsec_nodata_nonx_wc["nsec_next_domain_name"],
            nsec_nodata_nonx_wc["base_name"],
        )]

    nsec_nodata_denywc_dom = set(nsec_nodata_nonx_wc.loc[nsec_nodata_nonx_wc["isWildcardCovered"],"base_name"])
    print("NSEC domains deny wildcard:", len(nsec_nodata_denywc_dom))

    nsec_wc_dom = set(nsec_nodata_nonx["base_name"].unique()) - nsec_nodata_denywc_dom - nsec_cde_nxdom
    print("NSEC total domains potentially serve wildcard:", len(nsec_wc_dom))
    
    return nsec_wc_dom, {"nsec_nodata_dom": len(set(nsec_nodata_nonx["base_name"])), 
                         "nsec_nxname_dom": len(nsec_cde_nxdom), 
                         "nsec_wildcard_ack": len(wildcard_dom), 
                         "nsec_wildcard_deny": len(nsec_nodata_denywc_dom), 
                         "nsec_wildcard_toquery": len(nsec_wc_dom)}

def wildcard_covered(rname, wildcard, nname):
    if rname is None or wildcard is None or nname is None:
        return False
    if rname < wildcard < nname:
        return True
    return False

def wildcard_ack(rname, wildcard, nname):
    if rname is None or wildcard is None or nname is None:
        return False
    return rname == wildcard or nname == wildcard


def filter_nsec3_wildcard(nsec3):
    
    nsec3_nodata = nsec3.loc[nsec3["status_code"]==0]
    nsec3_nodata["wildcard"] = nsec3_nodata["base_name"].apply(lambda x: f"*.{x}")
    nsec3_nodata_openintel = nsec3_nodata[nsec3_nodata["source"]=="openintel"]

    nsec3_nodata_openintel = nsec3_nodata[nsec3_nodata["source"]=="openintel"]
    nsec3_nodata_scan = nsec3_nodata[nsec3_nodata["source"]=="scan"]
    ## total nsec3
    nsec3_nodata_dom = set(nsec3_nodata["base_name"].unique())
    print("NSEC3 Nodata :", len(nsec3_nodata_dom))
    ## openintel
    nsec3_nodata_openintel["wildcard_hash"] = nsec3_nodata_openintel.apply(lambda x: nsec3_hash(x['wildcard'], 
                                            int(x['nsec3_hash_algorithm']), int(x['nsec3_iterations']), 
                                            str(x['nsec3_salt'][2:])), axis=1)
    

    
    nsec3_nodata_openintel["rname"] = nsec3_nodata_openintel["response_name"].apply(lambda x: x.split(".")[0])
    nsec3_nodata_openintel["nname"] = nsec3_nodata_openintel["nsec3_next_domain_name_hash"].apply(lambda x: x[2:])
    nsec3_nodata_openintel["rname_int"] = nsec3_nodata_openintel.apply(lambda x: base32hex_to_int(x['rname']), axis=1)
    nsec3_nodata_openintel["wildcard_int"] = nsec3_nodata_openintel.apply(lambda x: base32hex_to_int(x['wildcard_hash']), axis=1)
    nsec3_nodata_openintel["nname_int"] = nsec3_nodata_openintel.apply(lambda x: int(x['nname'],16), axis=1)
    nsec3_nodata_openintel['denywildcard'] = nsec3_nodata_openintel.apply(lambda x: wildcard_covered(x['rname_int'],
                                                                                x['wildcard_int'],
                                                                                x['nname_int']), axis=1)
    
    nsec3_nodata_openintel["ackwildcard"] = nsec3_nodata_openintel.apply(lambda x: wildcard_ack(x['rname_int'],
                                                                                x['wildcard_int'],
                                                                                x['nname_int']), axis=1)

    nsec3_nodata_scan["rname"] = nsec3_nodata_scan["response_name"].apply(lambda x: x.split(".")[0])
    nsec3_nodata_scan["nname"] = nsec3_nodata_scan["nsec3_next_domain_name_hash"].apply(lambda x: x)
    nsec3_nodata_scan["rname_int"] = nsec3_nodata_scan.apply(lambda x: base32hex_to_int(x['rname']), axis=1)
    nsec3_nodata_scan["nname_int"] = nsec3_nodata_scan.apply(lambda x: base32hex_to_int(x['nname']), axis=1)
    nsec3_nodata_scan["wildcard_hash"] = nsec3_nodata_scan.apply(lambda x: nsec3_hash(x['wildcard'], 
                                            int(x['nsec3_hash_algorithm']), int(x['nsec3_iterations']), 
                                            str(x['nsec3_salt'])), axis=1)
    nsec3_nodata_scan["wildcard_int"] = nsec3_nodata_scan.apply(lambda x: base32hex_to_int(x['wildcard_hash']), axis=1)
    nsec3_nodata_scan['denywildcard'] = nsec3_nodata_scan.apply(lambda x: wildcard_covered(x['rname_int'],
                                                                                x['wildcard_int'],
                                                                                x['nname_int']), axis=1)
    
    nsec3_nodata_scan["ackwildcard"] = nsec3_nodata_scan.apply(lambda x: wildcard_ack(x['rname_int'],
                                                                                x['wildcard_int'],
                                                                                x['nname_int']), axis=1)

    nsec3_nodata_final = pd.concat([nsec3_nodata_openintel, nsec3_nodata_scan], ignore_index=True)
    
    nsec3_nodata_denywc = nsec3_nodata_final[nsec3_nodata_final['denywildcard']]
    nsec3_nodata_denywc_dom = set(nsec3_nodata_denywc["base_name"].unique())
    print("NSEC3 Deny Wildcard:", len(nsec3_nodata_denywc_dom))

    nsec3_nodata_ackwc = nsec3_nodata_final[nsec3_nodata_final['ackwildcard']]
    nsec3_nodata_ackwc_dom = set(nsec3_nodata_ackwc["base_name"].unique())
    print("NSEC3 Ack Wildcard:", len(nsec3_nodata_ackwc_dom))


    nsec3_wc_dom = nsec3_nodata_dom - nsec3_nodata_denywc_dom
    print("NSEC3 Wildcard Domain:", len(nsec3_nodata_denywc_dom))

    return nsec3_wc_dom, {"nsec3_nodata_dom": len(nsec3_nodata_dom), 
                         "nsec3_wildcard_ack": len(nsec3_nodata_ackwc_dom),
                          "nsec3_wildcard_deny": len(nsec3_nodata_denywc_dom),
                          "nsec3_wildcard_toquery": len(nsec3_wc_dom)}

    

    
stats = pd.DataFrame()
for zone in zones:
    print(f"filter zone: {zone}")
    datadir = f"{DATAROOT}/processed/{datestr}/{zone}"
    resdir = "res/wildcard"
    os.makedirs(datadir, exist_ok=True)
    
    nsec_df = pd.read_parquet(
        f"{DATAROOT}/processed/{datestr}/{zone}/20260406_nsec_ns_everything.parquet")
    
    print("NSEC shape:", nsec_df.shape)
    nsec3_df = pd.read_parquet(
        f"{DATAROOT}/processed/{datestr}/{zone}/20260406_nsec3_ns_everything.parquet")
    print("NSEC3 shape:", nsec3_df.shape)

    print("filter nsec wildcard...")
    nsec_wildcard_dom, nsec_stats = filter_nsec_wildcard(nsec_df)
    print("total nsec wildcard domains:", len(nsec_wildcard_dom))
    print("nsec_stats:", nsec_stats)
    print("****\nnsec wildcard domains:", len(nsec_wildcard_dom), "%", len(nsec_wildcard_dom)/nsec_df.shape[0]*100)

    nsec3_wildcard_dom, nsec3_stats = filter_nsec3_wildcard(nsec3_df)
    
    print("nsec3 nodata domains:", len(nsec3_wildcard_dom), "%", len(nsec3_wildcard_dom)/nsec3_df.shape[0]*100)    
    total_wc_dom = nsec3_wildcard_dom.union(nsec_wildcard_dom)
    #total_wc_dom_l = list(total_wc_dom)
    #total_wc_dom_l.sort()
    
    nsec_stats["NSEC3_nodata_dom"] = nsec3_stats["nsec3_nodata_dom"]
    nsec_stats["nsec3_wildcard_deny"] = nsec3_stats["nsec3_wildcard_deny"]
    nsec_stats["nsec3_wildcard_ack"] = nsec3_stats["nsec3_wildcard_ack"]
    nsec_stats["nsec3_wildcard_toquery"] = nsec3_stats["nsec3_wildcard_toquery"]
    nsec_stats["Total_wildcard_dom"] = len(total_wc_dom)
    nsec_stats["zone"] = zone
    
    tmpstats =  pd.DataFrame.from_dict([nsec_stats])
    stats = pd.concat([stats, tmpstats], ignore_index=True)
    print("Total Wildcard Domains:", len(total_wc_dom))

    """
    uncomment below to save the domain lists to query
    """
    #print("writing nsec list:")
    #with open(os.path.join(resdir, f"{datestr}_{zone}_nsec_wc.txt"), "w") as file:
    #    file.writelines([f"{dom}\n" for dom in nsec_wildcard_dom])

    #print("writing nsec3 list:")
    #with open(os.path.join(resdir, f"{datestr}_{zone}_nsec3_wc.txt"), "w") as file:
    #    file.writelines([f"{dom}\n" for dom in nsec3_wildcard_dom])
    
print(stats)
stats.to_csv(os.path.join(resdir,f"{datestr}_wildcard_stats.csv"), index=False)
