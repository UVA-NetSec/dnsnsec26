import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
import tldextract
import re
import os
import numpy as np
from utils import *
from config import zones, POPLIST, DATAROOT, PROBROOT



"""
This script assumes that openintel nsec/3 is in DATAROOT and the probe data is in PROBROOT
This script merge the probe data and original openintel data into a unified dataframe for future analysis.

Config datestr to process.
"""


datestr = "20260406"


def normalize_scan(tmpdf, odf, dtype="nsec"):
    tmpdf = tmpdf.rename(columns={"basename":"base_name", "probe_fqdn":"query_name",
                                 "rtype":"query_type"})
    tmpdf["base_name"] = tmpdf["base_name"].apply(lambda x: f"{x}.")
    tmpdf["query_name"] = tmpdf["query_name"].apply(lambda x: f"{x}.")
    tmpdf["query_name"] = tmpdf["query_name"].apply(lambda x: re.sub(
    r"\d+-nonexistence-\d+-dnsquery",
    "123-nonexistant-dnsjedi-456",
    x))
    tmpdf["status_code"] = tmpdf["status"].apply(lambda x: 0 if x == "NODATA" else 3)
    tmpdf["ns_address"] = tmpdf["ns_address"].apply(lambda x: [x])
    
    if dtype=="nsec":
        tmpdf = tmpdf.rename(columns={"nsec_next_owner_name":"nsec_next_domain_name"})
        tmpdf["nsec_owner_rrset_types"] = tmpdf["nsec_owner_rrset_types"].apply(lambda x: " ".join(x)) 
    else:
        tmpdf = tmpdf.rename(columns={"nsec3_next_owner_name":"nsec3_next_domain_name"})
        tmpdf["nsec3_owner_rrset_types"] = tmpdf["nsec3_owner_rrset_types"].apply(lambda x: " ".join(x))
    dropc = []
    for c in tmpdf.columns:
        if c not in odf.columns:
            dropc.append(c)
    tmpdf = tmpdf.drop(columns=dropc)
    return tmpdf


for zone in zones:
    print(zone)
    tmpdf = pd.read_parquet(f"{PROBROOT}/{zone}/{datestr}/apex_scan_parsed/20260406_apex_scan_nsec.parquet")
    openintel = f"{DATAROOT}/processed/{datestr}/{zone}/20260406_nsec_ns.parquet"
    odf = pd.read_parquet(openintel)
    odf["source"] = "openintel"
    tmpdf_n = normalize_scan(tmpdf, odf)
    tmpdf_n["source"] = "scan"
    print(tmpdf_n.shape[0])
    alldf = pd.concat([odf, tmpdf_n])
    alldf = alldf.drop(columns=["response_ttl"])
    alldf.to_parquet(f"{DATAROOT}/processed/{datestr}/{zone}/20260406_nsec_ns_everything.parquet")


for zone in zones:
    print(zone)
    tmpdf = pd.read_parquet(f"{PROBROOT}/{zone}/{datestr}/apex_scan_parsed/20260406_apex_scan_nsec3.parquet")
    openintel = f"{DATAROOT}/processed/{datestr}/{zone}/20260406_nsec3_ns.parquet"
    odf = pd.read_parquet(openintel)
    odf["source"] = "openintel"
    tmpdf_n = normalize_scan(tmpdf, odf, dtype="nsec3")
    print(tmpdf_n.shape[0])
    tmpdf_n["source"] = "scan"
    alldf = pd.concat([odf, tmpdf_n])
    alldf = alldf.drop(columns=["response_ttl"])
    alldf.to_parquet(f"{DATAROOT}/processed/{datestr}/{zone}/20260406_nsec3_ns_everything.parquet")