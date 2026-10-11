import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
from config import *

"""
check if ad flag is set for apex
"""

datestr = "20260406"
zones = ["com", "net", "org", 'umbrella','tranco','radar','majestic']

stats = pd.DataFrame()
for zone in zones:
    print("Processing Zone:", zone)
    datadir = f"{DATAROOT}/{datestr}/{zone}/"
    savedir = f"{DATAROOT}/processed/{datestr}/{zone}"
    resdir = f"res"
    os.makedirs(resdir, exist_ok=True)
    
    nsec_df = pd.read_parquet(os.path.join(savedir, "20260406_nsec_ns_everything.parquet"), columns=["query_name", "ad_flag"])
    nsec3_df = pd.read_parquet(os.path.join(savedir, "20260406_nsec3_ns_everything.parquet"), columns=["query_name", "ad_flag"])

    nsec_stats = nsec_df.drop_duplicates(["query_name"])["ad_flag"].value_counts().to_dict()
    nsec_stats["Zone"] = zone
    nsec_stats["Type"] = "NSEC"
    nsec3_stats = nsec3_df.drop_duplicates(["query_name"])["ad_flag"].value_counts().to_dict()
    nsec3_stats["Zone"] = zone
    nsec3_stats["Type"] = "NSEC3"
    
    tmpstats = pd.concat([pd.DataFrame.from_dict([nsec_stats]), pd.DataFrame.from_dict([nsec3_stats])])
    print(tmpstats)
    stats = pd.concat([stats, tmpstats], ignore_index=True)

stats.to_csv(os.path.join(resdir,f"{datestr}_adflag_stats.csv"), index=False)