import polars as pl
import pandas as pd
import os
import glob
import re
import json
import pyarrow
from config import *
from utils import *

"""
This script parse WWW AFSDB probing scan output.
It assumes that popularity list scannings are in {PROBROOT}/{zone}/{datestr}/www_scan_nsec
zone scannings are in {PROBROOT}/{zone}/{datestr}/www_scan_nsec_final, 
This is not ideal set up. The reason is that for zone file I set up two instance for scanning, so I have multiple scan subfolders. For simplicity, scan using one vm and save everything in www_scan_nsec in future. 

"""

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
    df_nsec["nsec_next_owner_name"] = df_nsec["parsed_nsec_d"].apply(lambda x: x['next_owner_name'])
    df_nsec["nsec_owner_rrset_types"] = df_nsec["parsed_nsec_d"].apply(lambda x: x['rrset_bitmap'])
    df_nsec = df_nsec.drop(columns=["parsed", "responses", "nsec_resp", "nsec3_resp", 
                                    "nsec_resp_l", "nsec3_resp_l", "parsed_nsec_d"])

    #nsec3 parsing
    df_nsec3 = df[df["nsec3_resp_l"]>0]
    df_nsec3["response_type"] = "NSEC3"
    df_nsec3 = df_nsec3.explode("nsec3_resp")
    df_nsec3["parsed_nsec_d"] = df_nsec3["nsec3_resp"].map(parse_nsec3_line)

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

for zone in zones:
    print(f"filter zone: {zone}")
    if zone in POPLIST:
        datadir = f"{PROBROOT}/{zone}/{datestr}/www_scan_nsec"
    else:   
        datadir = f"{PROBROOT}/{zone}/{datestr}/www_scan_nsec_final"

    savedir = f"{PROBROOT}/{zone}/{datestr}/www_scan_nsec_parsed"
    finaldir = f"{PROBROOT}/{zone}/{datestr}/"
    os.makedirs(savedir, exist_ok=True)
    print(datadir)
    fl = glob.glob(os.path.join(datadir, "*afsdb*"))
    fl.sort()
    print(fl)
    nsec_final = []
    nsec3_final = []
    for f in fl:
        basename = os.path.basename(f)
        print(f)
        fidx = basename.split(".json")[0].split("_")[-1]
        df = pd.read_json(f, lines=True)
        nsec, nsec3 = parse_probe_data(df)
        print("saving to", os.path.join(savedir, f"nsec_afsdb_{fidx}.parquet"))
        nsec_final.append(nsec)
        nsec3_final.append(nsec3)

    nsec_df = pd.concat(nsec_final)
    nsec3_df = pd.concat(nsec3_final)
    nsec_df.to_parquet(os.path.join(finaldir, f"{datestr}_www_nsec.parquet"))
    nsec3_df.to_parquet(os.path.join(finaldir, f"{datestr}_www_nsec3.parquet"))