import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
from config import *

"""
stats: domain count
"""

datestr = "20260406"
zones = ["com", "net", "org", 'umbrella','tranco','radar','majestic']
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

stats = pd.DataFrame()
for zone in zones:
    print("Processing Zone:", zone)
    datadir = f"{DATAROOT}/{datestr}/{zone}/"
    savedir = f"{DATAROOT}/processed/{datestr}/{zone}"
    resdir = f"res"
    os.makedirs(resdir, exist_ok=True)
    fl = glob.glob(os.path.join(datadir, "*.gz.parquet"))
    fl.sort()
    print("scanning SOA...")
    soa_cnt = (pl.scan_parquet(fl).select(["query_type", "response_type", "soa_mname", "query_name"])
        .filter(
            (pl.col("query_type") == "SOA") &
            (pl.col("response_type") == "SOA") &
            (pl.col("soa_mname").is_not_null())
        )
        .select(pl.col("query_name").n_unique())
        .collect()
    )    
    print("Total SOA domain count:", soa_cnt)
    dnskey_cnt = (
    pl.scan_parquet(fl)
    .select(['query_type','query_name', 'response_type','response_name','status_code','dnskey_flags'])
    .filter(
        (pl.col("query_type") == "DNSKEY") &
        (pl.col("response_type") == "DNSKEY") &
        (pl.col("dnskey_flags").is_not_null())
    )
    .select(pl.col("query_name").n_unique())
    .collect()
    )
    print("Total DNSKEY domain count:", dnskey_cnt)

    nsec_cnt = (
    pl.scan_parquet(os.path.join(savedir,f"20260406_nsec_ns_everything.parquet"))
    .select(pl.col("query_name").n_unique())
    .collect()
    )
    
    print("Total NSEC count:", nsec_cnt)
    nsec3_cnt = (
    pl.scan_parquet(os.path.join(savedir,f"20260406_nsec3_ns_everything.parquet"))
    .select(pl.col("query_name").n_unique())
    .collect()
    )
    print("Total NSEC3 count:", nsec3_cnt)
    tmpstats =  pd.DataFrame.from_dict([{"zone":zone, "soa":soa_cnt["query_name"][0], "dnskey":dnskey_cnt["query_name"][0], 
                              "nsec": nsec_cnt["query_name"][0], "nsec3":nsec3_cnt["query_name"][0]}])
    stats = pd.concat([stats,tmpstats], ignore_index=True)

stats.to_csv(os.path.join(resdir,f"{datestr}_domcnt_stats.csv"), index=False)