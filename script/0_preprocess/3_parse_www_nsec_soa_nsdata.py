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
Parse SOA MNAME out
"""

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

    
def parse_soa_data(df):
    if "base_name" in df.columns:
        df = df.rename(columns={"base_name": "basename"})
    df["responses_l"] = df["responses"].apply(len)
    df = df[df["responses_l"]>0]
    df["responses"] = df["responses"].apply(lambda x: x[0])
    df["ns_address"] = df["responses"].map(extract_soa_mname)
    df = df.drop(columns=["responses"])
    return df

    
datestr = "20260406"

for zone in zones:
    print(f"filter zone: {zone}")
    if zone in POPLIST:
        datadir = f"{PROBROOT}/{zone}/{datestr}/www_scan_nsec"
    else:   
        datadir = f"{PROBROOT}/{zone}/{datestr}/www_scan_nsec_final"

    savedir = f"{PROBROOT}/{zone}/{datestr}/www_scan_nssoa_parsed"
    finaldir = f"{PROBROOT}/{zone}/{datestr}/"
    os.makedirs(savedir, exist_ok=True)
    print(datadir)
    fl = glob.glob(os.path.join(datadir, "*afsdb*"))
    fl.sort()
    print(fl)
    ns_final = []
    for f in fl:
        basename = os.path.basename(f)
        print(f)
        fidx = basename.split(".json")[0].split("_")[-1]
        df = pd.read_json(f, lines=True)
        df = parse_soa_data(df)
        print("saving to", os.path.join(savedir, f"www_soa_{fidx}.parquet"))
        ns_final.append(df)

    ns_df = pd.concat(ns_final)
    ns_df.to_parquet(os.path.join(finaldir, f"{datestr}_www_soa_ns_final.parquet"))
