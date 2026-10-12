import polars as pl
import pandas as pd
import os
import glob
import re
import json
import pyarrow
from config import *
from utils import *
    
datestr = "20260406"

stats = pd.DataFrame()
for zone in zones:
    print(zone)
    with open(f"res/wildcard/{datestr}_{zone}_nsec_wc.txt", "r") as file: 
        nsecdom = file.readlines()
    nsecdom_s = set([dom.rstrip(".\n")for dom in nsecdom])
    print(len(nsecdom_s))
    with open(f"res/wildcard/{datestr}_{zone}_nsec3_wc.txt", "r") as file: 
        nsec3dom = file.readlines()
    nsec3dom_s = set([dom.rstrip(".\n")for dom in nsec3dom])
    print(len(nsec3dom_s))
    
    total_doms = nsecdom_s.union(nsec3dom_s)

    nsec_raw = pd.read_parquet(f"{PROBROOT}/processed/{zone}/{datestr}/{datestr}_www_nsec_namedist.parquet")
    nsec3_raw = pd.read_parquet(f"{PROBROOT}/processed/{zone}/{datestr}/{datestr}_www_nsec3_namedist.parquet")

    nsec_raw_target = nsec_raw.loc[nsec_raw["basename"].isin(total_doms)]
    nsec3_raw_target = nsec3_raw.loc[nsec3_raw["basename"].isin(total_doms)]
    nsec_raw_target.to_parquet(f"{PROBROOT}/processed/{zone}/{datestr}/{datestr}_www_nsec_namedist_final.parquet")
    nsec3_raw_target.to_parquet(f"{PROBROOT}/processed/{zone}/{datestr}/{datestr}_www_nsec3_namedist_final.parquet")
    totaldf = pd.concat([nsec_raw_target[["query_name"]], nsec3_raw_target[["query_name"]]])
    totaldf_resolved = totaldf["query_name"].nunique()
    
    stats = pd.concat([stats, pd.DataFrame.from_dict([{
        "zone":zone, 
        "totalwc": len(total_doms), "totalwww": totaldf_resolved, "perc": totaldf_resolved/len(total_doms)
    }])])
stats.to_csv("res/wildcard/subdomain_query_stats.csv", index=False)