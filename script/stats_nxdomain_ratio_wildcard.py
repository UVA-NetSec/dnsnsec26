import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
from wildcardutils import *
from config import *

"""
stats nxdomain ratio for www subdomains
"""
datestr = "20260406"



stats = pd.DataFrame()
for zone in zones:
    print(zone)
    stats = pd.DataFrame()
for zone in zones:
    print(zone)
    total = pd.read_parquet(f"{PROBROOT}/processed/{zone}/{datestr}/{datestr}_wc_total.parquet")
    t_noerr = filter_errdf(total)
    t_noerr = parse_nsecdata(t_noerr)
    t_noerr = get_nsec_count(t_noerr)
    t_noerr = t_noerr.drop_duplicates(["probe_fqdn"])
    tnsec, tnsec3 = split_nsec_data(t_noerr)
    tnsec = tnsec.drop_duplicates(["probe_fqdn"])
    tnsec3 = tnsec3.drop_duplicates(["probe_fqdn"])
    tmpstats_nsec = tnsec["status"].value_counts().reset_index()
    tmpstats_nsec3 = tnsec3["status"].value_counts().reset_index()
    
    tmpstats_nsec["total"] = tnsec["probe_fqdn"].nunique()
    tmpstats_nsec["perc"] = tmpstats_nsec["count"]/tmpstats_nsec["total"]
    tmpstats_nsec["zone"]=zone
    tmpstats_nsec["type"]="nsec"

    tmpstats_nsec3["total"] = tnsec3["probe_fqdn"].nunique()
    tmpstats_nsec3["perc"] = tmpstats_nsec3["count"]/tmpstats_nsec3["total"]
    tmpstats_nsec3["zone"] = zone
    tmpstats_nsec3["type"]="nsec3"
    stats = pd.concat([stats, tmpstats_nsec, tmpstats_nsec3])
stats.to_csv(f"res/{datestr}_wildcard_nxdomain_ratio.csv", index=False)