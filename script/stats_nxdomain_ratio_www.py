import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
from config import *

"""
stats nxdomain ratio for www subdomains
"""
datestr = "20260406"
zones = ["com", "net", "org", 'umbrella','tranco','radar','majestic']

stats = pd.DataFrame()
for zone in zones:
    print(zone)
    nsec = pd.read_parquet(f"{PROBROOT}/processed/{zone}/{datestr}/{datestr}_www_nsec_namedist.parquet", columns=["query_name", "status"])
    nsec3 = pd.read_parquet(f"{PROBROOT}/processed/{zone}/{datestr}/{datestr}_www_nsec3_namedist.parquet", columns=["query_name", "status"])
    
    tnsec = nsec.drop_duplicates(["query_name"])
    tnsec3 = nsec3.drop_duplicates(["query_name"])
    tmpstats_nsec = tnsec["status"].value_counts().reset_index()
    tmpstats_nsec3 = tnsec3["status"].value_counts().reset_index()
    
    tmpstats_nsec["total"] = tnsec["query_name"].nunique()
    tmpstats_nsec["perc"] = tmpstats_nsec["count"]/tmpstats_nsec["total"]
    tmpstats_nsec["zone"]=zone
    tmpstats_nsec["type"]="nsec"

    tmpstats_nsec3["total"] = tnsec3["query_name"].nunique()
    tmpstats_nsec3["perc"] = tmpstats_nsec3["count"]/tmpstats_nsec3["total"]
    tmpstats_nsec3["zone"] = zone
    tmpstats_nsec3["type"]="nsec3"
    stats = pd.concat([stats, tmpstats_nsec, tmpstats_nsec3])
stats.to_csv(f"res/{datestr}_www_nxdomain_ratio.csv", index=False)
