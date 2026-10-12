import polars as pl
import pandas as pd
import os
import glob
import re
import json
import pyarrow
from config import *
from utils import *


def parse_dns_response(resp_str_l):
    adflag = 0
    nsec_l = []
    nsec3_l = []
    if len(resp_str_l) == 0:
        resp_str = ""
    else:
        resp_str = resp_str_l[0]
        
    for line in resp_str.splitlines():
        line = line.strip()
        if not line:
            continue

        # Check AD flag
        if line.startswith("flags "):
            flags = line.split()
            adflag = 1 if "AD" in flags else 0

        # Collect NSEC / NSEC3 records
        parts = line.split()
        if len(parts) >= 4 and parts[3] == "NSEC":
            nsec_l.append(line)
        elif len(parts) >= 4 and parts[3] == "NSEC3":
            nsec3_l.append(line)

    return {
        "adflag": adflag,
        "nsec_l": nsec_l,
        "nsec3_l": nsec3_l,
    }
    
def parse_nsec_line(line: str):
    """
    Parse a single NSEC record line.

    Returns:
        dict with keys:
            - owner_name
            - next_owner_name
            - rrset_bitmap (list)
        or None if not a valid NSEC line
    """
    if not line:
        return None

    parts = line.strip().split()

    # Basic validation
    if len(parts) < 6 or parts[3] != "NSEC":
        return None

    owner_name = parts[0]
    next_owner_name = parts[4]
    rrset_bitmap = parts[5:]

    return {
        "owner_name": owner_name,
        "next_owner_name": next_owner_name,
        "rrset_bitmap": rrset_bitmap,
    }

def parse_nsec3_line(line: str):
    """
    Parse a single NSEC3 record line.

    Expected format:
    owner ttl IN NSEC3 hash_alg flags iterations salt next_hashed_owner bitmap...

    Returns:
        dict with keys:
            - owner_name
            - next_owner_name
            - parameters (dict: hash_alg, flags, iterations, salt)
            - rrset_bitmap (list)
        or None if not a valid NSEC3 line
    """
    if not line:
        return None

    parts = line.strip().split()

    # Basic validation
    if len(parts) < 9 or parts[3] != "NSEC3":
        return None

    owner_name = parts[0]

    try:
        hash_alg = int(parts[4])
        flags = int(parts[5])
        iterations = int(parts[6])
    except ValueError:
        return None

    salt = parts[7]
    next_owner_name = parts[8]
    rrset_bitmap = parts[9:] if len(parts) > 9 else []

    return {
        "owner_name": owner_name,
        "next_owner_name": next_owner_name,
        "hash_alg": hash_alg,
        "flags": flags,
        "iterations": iterations,
        "salt": salt,
        "rrset_bitmap": rrset_bitmap,
    }

def extract_soa_mname(dns_response: str) -> str | None:
    """
    Extract the SOA MNAME (primary nameserver) from a DNS response string.
    
    Args:
        dns_response (str): Raw DNS response text.
        
    Returns:
        str | None: The SOA MNAME if found, otherwise None.
    """
    for line in dns_response.splitlines():
        parts = line.split()
        
        # Look for an SOA record line
        if len(parts) >= 7 and parts[3] == "SOA":
            # SOA format:
            # name TTL IN SOA MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM
            return parts[4]
    
    return None

def extract_soa_ownername(dns_response: str) -> str | None:
    """
    Extract the SOA MNAME (primary nameserver) from a DNS response string.
    
    Args:
        dns_response (str): Raw DNS response text.
        
    Returns:
        str | None: The SOA MNAME if found, otherwise None.
    """
    for line in dns_response.splitlines():
        parts = line.split()
        
        # Look for an SOA record line
        if len(parts) >= 7 and parts[3] == "SOA":
            # SOA format:
            # name TTL IN SOA MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM
            return parts[0]
    return None

    
def parse_soa_data(df):
    if "base_name" in df.columns:
        df = df.rename(columns={"base_name": "basename"})
    df["responses_l"] = df["responses"].apply(len)
    df = df[df["responses_l"]>0]
    df["responses"] = df["responses"].apply(lambda x: x[0])
    df["ns_address"] = df["responses"].map(extract_soa_mname)
    df = df.drop(columns=["responses"])
    return df
    
    
def parse_probe_data(df):
    if "base_name" in df.columns:
        df = df.rename(columns={"base_name": "basename"})
    df["parsed"] = df["responses"].map(parse_dns_response)
    df["ad_flag"] = df["parsed"].apply(lambda x: x["adflag"])
    df["nsec_resp"] = df["parsed"].apply(lambda x: x["nsec_l"])
    df["nsec3_resp"] = df["parsed"].apply(lambda x: x["nsec3_l"])
    df["nsec_resp_l"] = df["nsec_resp"].apply(len)
    df["nsec3_resp_l"] = df["nsec3_resp"].apply(len)
    df_nsec = df[df["nsec_resp_l"]>0]
    df_nsec3 = df[df["nsec3_resp_l"]>0]
    
    # nsec parsing
    df_nsec["response_type"] = "NSEC"
    df_nsec = df_nsec.explode("nsec_resp")
    df_nsec["parsed_nsec_d"] = df_nsec["nsec_resp"].map(parse_nsec_line)
    df_nsec["response_name"] = df_nsec["parsed_nsec_d"].apply(lambda x: x['owner_name'])
    
    df_nsec["ns_address"] = df_nsec["responses"].apply(lambda x: extract_soa_mname(x[0]))
    df_nsec["soa_owner"] = df_nsec["responses"].apply(lambda x: extract_soa_ownername(x[0]))

    df_nsec["nsec_next_owner_name"] = df_nsec["parsed_nsec_d"].apply(lambda x: x['next_owner_name'])
    df_nsec["nsec_owner_rrset_types"] = df_nsec["parsed_nsec_d"].apply(lambda x: x['rrset_bitmap'])
    df_nsec = df_nsec.drop(columns=["parsed", "responses", "nsec_resp", "nsec3_resp", 
                                    "nsec_resp_l", "nsec3_resp_l", "parsed_nsec_d"])

    #nsec3 parsing
    df_nsec3 = df[df["nsec3_resp_l"]>0]
    df_nsec3["response_type"] = "NSEC3"
    df_nsec3 = df_nsec3.explode("nsec3_resp")
    df_nsec3["parsed_nsec_d"] = df_nsec3["nsec3_resp"].map(parse_nsec3_line)
    df_nsec3["ns_address"] = df_nsec3["responses"].apply(lambda x: extract_soa_mname(x[0]))

    df_nsec3["response_name"] = df_nsec3["parsed_nsec_d"].apply(lambda x: x['owner_name'])
    df_nsec3["nsec3_next_domain_name_hash"] = df_nsec3["parsed_nsec_d"].apply(lambda x: x['next_owner_name'])
    df_nsec3["nsec3_hash_algorithm"] = df_nsec3["parsed_nsec_d"].apply(lambda x: x['hash_alg'])
    df_nsec3["nsec3_flags"] = df_nsec3["parsed_nsec_d"].apply(lambda x: x['flags'])
    df_nsec3["nsec3_iterations"] = df_nsec3["parsed_nsec_d"].apply(lambda x: x['iterations'])
    df_nsec3["nsec3_salt"] = df_nsec3["parsed_nsec_d"].apply(lambda x: x['salt'])
    df_nsec3["nsec3_owner_rrset_types"] = df_nsec3["parsed_nsec_d"].apply(lambda x: x['rrset_bitmap'])
    df_nsec3 = df_nsec3.drop(columns=["parsed", "responses", "nsec_resp", "nsec3_resp", 
                                    "nsec_resp_l", "nsec3_resp_l", "parsed_nsec_d"])
    
    return df_nsec, df_nsec3

    
datestr = "20260406"
zones = ['umbrella','tranco','radar','majestic', 'com', 'net', 'org']
totalstats = pd.DataFrame()

for zone in zones:
    print(zone)
    with open(f"res/wildcard/{datestr}_{zone}_nsec_wc.txt", "r") as file:
        doms = file.readlines()
    print(doms[0])
    nsec_dom = set([dom.rstrip(".\n") for dom in doms])
    
    with open(f"res/wildcard/{datestr}_{zone}_nsec3_wc.txt", "r") as file:
        doms = file.readlines()
    print(doms[0])
    nsec3_dom = set([dom.rstrip(".\n") for dom in doms])
    total_doms = nsec_dom.union(nsec3_dom)
    print("Total domains:", len(total_doms))

    datadir = f"{PROBROOT}/{zone}/{datestr}/subdomain_scan_nsec_raw"
    fl = glob.glob(os.path.join(datadir, "sub_scan_*"))
    fl.extend(glob.glob(f"{PROBROOT}/{zone}/{datestr}/sub_extra_scan/*afsdb*"))
    fl.sort()
    
    dfl = []
    for f in fl:
        print(f)
        df = pd.read_json(f, lines=True)
        dfl.append(df)
    totaldf = pd.concat(dfl)
    nsec_tmp = totaldf.loc[totaldf["basename"].isin(nsec_dom)]
    nsec3_tmp = totaldf.loc[totaldf["basename"].isin(nsec3_dom)]

    nsec_tmp.to_parquet(
        f"/{PROBROOT}/processed/{zone}/{datestr}/wildcard_scan_nsec_raw_total.parquet")
    nsec3_tmp.to_parquet(
        f"{PROBROOT}/processed/{zone}/{datestr}/wildcard_scan_nsec3_raw_total.parquet")
    print(nsec_tmp.shape)
    print(nsec3_tmp.shape)

    #totalstats = pd.concat([totalstats, pd.DataFrame.from_dict([tmpstats])])

#totalstats.to_csv("../res/wildcard_finalstats/subdomain_query_raw_stats.csv", index=False)