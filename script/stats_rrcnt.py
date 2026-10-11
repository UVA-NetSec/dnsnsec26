import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
from config import *


"""
write rr count status to file.
"""

datestr = "20260406"
zones = ["com", "net", "org", 'umbrella','tranco','radar','majestic']


def filterdf(files, filtered_col, fcol, fstr):
    filtered = (
        pl.scan_parquet(files)
        .select(filtered_col)
        .filter(pl.col(fcol)==fstr)
        .collect()
    )
    return filtered

stats = pd.DataFrame()
for zone in zones:
    print("Processing Zone:", zone)
    datadir = f"{DATAROOT}/{datestr}/{zone}/"
    savedir = f"{DATAROOT}/processed/{datestr}/{zone}"
    resdir = f"res"
    os.makedirs(resdir, exist_ok=True)
    
    nsec_df = pd.read_parquet(os.path.join(savedir, "20260406_nsec_ns_everything.parquet"), columns=["query_name", "query_type"])
    nsec3_df = pd.read_parquet(os.path.join(savedir, "20260406_nsec3_ns_everything.parquet"), columns=["query_name", "query_type"])
    nsec_rrcnt = nsec_df.groupby("query_name")["query_type"].count().value_counts().to_dict()
    nsec3_rrcnt = nsec3_df.groupby("query_name")["query_type"].count().value_counts().to_dict()

    nsec_rrdf = pd.DataFrame({"Count":nsec_rrcnt})
    nsec_rrdf["Type"] = "NSEC"
    nsec_rrdf["Perc"] = nsec_rrdf["Count"] /  nsec_rrdf["Count"].sum()
    nsec_rrdf = nsec_rrdf.reset_index()
    nsec_rrdf = nsec_rrdf.rename(columns={"index":"cnt of RRs"})
    
    nsec3_rrdf = pd.DataFrame({"Count":nsec3_rrcnt})
    nsec3_rrdf["Type"] = "NSEC3"
    nsec3_rrdf["Perc"] = nsec3_rrdf["Count"] /  nsec3_rrdf["Count"].sum()
    nsec3_rrdf = nsec3_rrdf.reset_index()
    nsec3_rrdf = nsec3_rrdf.rename(columns={"index":"cnt of RRs"})
    
    rrcntdf = pd.concat([nsec_rrdf, nsec3_rrdf])
    rrcntdf["Zone"] = zone
    rrcntdf = rrcntdf.sort_values(["Type","cnt of RRs",])
    
    stats = pd.concat([stats,rrcntdf], ignore_index=True)

stats.to_csv(os.path.join(resdir,f"{datestr}_rrcnt_stats.csv"), index=False)