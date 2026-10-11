import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
import tldextract
from utils import *
from config import zones, POPLIST, DATAROOT

"""
This script filtered nsec/3 related resource records.
config datestr to process data from different day. 
"""

datestr = "20260406"

nsec3_cols = ['query_type',
 'query_name',
 'response_type',
 'response_name',
 'response_ttl',
 'status_code',
 'ad_flag', 'nsec_next_domain_name',
 'nsec_owner_rrset_types',
 'nsec3_hash_algorithm',
 'nsec3_flags',
 'nsec3_iterations',
 'nsec3_salt',
 'nsec3_next_domain_name_hash',
 'nsec3_owner_rrset_types',
 'nsec3param_hash_algorithm',
 'nsec3param_flags',
 'nsec3param_iterations',
 'nsec3param_salt']

nsec_cols = ['query_type',
 'query_name',
 'response_type',
 'response_name',
 'response_ttl',
 'status_code',
 'ad_flag', 'nsec_next_domain_name',
 'nsec_owner_rrset_types']

ns_cols = ['query_type',
 'query_name', 
 'response_type',
 'response_name',
 'status_code','ns_address']

def filterdf(files, filtered_col, fcol, fstr):
    filtered = (
        pl.scan_parquet(files)
        .select(filtered_col)
        .filter(pl.col(fcol)==fstr)
        .collect()
    )
    return filtered

    
for zone in zones:
    datadir = f"{DATAROOT}/{datestr}/{zone}/"
    savedir = f"{DATAROOT}/processed/{datestr}/{zone}"
    os.makedirs(savedir, exist_ok=True)
    
    fl = glob.glob(os.path.join(datadir, "*.gz.parquet"))
    fl.sort()
    print("reading fl:", fl)
    print("scanning NS RR...")
    nsdf = (pl.scan_parquet(fl).select(ns_cols)
        .filter(
            (pl.col("query_type") == "NS") &
            (pl.col("response_type") == "NS") &
            (pl.col("ns_address").is_not_null())
        ).with_columns(pl.col("query_name")
            .str.split(".").list.slice(1).list.join(".")
            .alias("base_name")
        ).collect()
        )
    print("writing NS DF...", len(nsdf))
    nsdf.write_parquet(os.path.join(savedir, f"{datestr}_ns.parquet"))

    print("scanning NSEC DF...")
    nsecdf = (pl.scan_parquet(fl).select(nsec_cols)
    .filter((pl.col("response_type") == "NSEC"))
    .with_columns(
            pl.col("query_name")
            .str.split(".")
            .list.slice(1)
            .list.join(".")
            .alias("base_name")
        )
    .collect()
    )
    print("writing NSEC DF", len(nsecdf))
    
    nsecdf.write_parquet(os.path.join(savedir,f"{datestr}_nsec.parquet"))
    
    print("scanning NSEC3 DF...")
    nsec3df = (pl.scan_parquet(fl).select(nsec3_cols)
    .filter((pl.col("response_type") == "NSEC3"))
    .with_columns(
            pl.col("query_name")
            .str.split(".")
            .list.slice(1)
            .list.join(".")
            .alias("base_name")
        )
    .collect()
    )
    print("writing NSEC3 DF", len(nsec3df))
    nsec3df.write_parquet(os.path.join(savedir,f"{datestr}_nsec3.parquet"))
