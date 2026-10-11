import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name


"""
domain counts for www
"""

datestr = "20260406"
zones = ["com", "net", "org", 'umbrella','tranco','radar','majestic']

stats = pd.DataFrame()
for zone in zones:
    print("Processing Zone:", zone)
    datadir = f"{PROBROOT}/{zone}/{datestr}/www_scan_nsec_parsed"
    resdir = f"res"

    os.makedirs(resdir, exist_ok=True)
    fl = glob.glob(os.path.join(datadir, "nsec_afsdb*.parquet"))
    fl.sort()
    with open(f"/p/keyinfra/nsecdata/openintel/processed/{datestr}/{zone}/{datestr}_dnskey_names.txt", "r") as file:
        doml = file.readlines()
    dnskey_cnt = len(doml)
    dnskey_dom = set([dom.rstrip("\n").rstrip(".") for dom in doml])
    
    nsec_cnt = (
    pl.scan_parquet(fl).filter(pl.col("basename").is_in(dnskey_dom))
    .select(pl.col("probe_fqdn").n_unique())
    .collect()
    )
    print("Total NSEC count:", nsec_cnt)

    fl = glob.glob(os.path.join(datadir, "nsec3_afsdb*.parquet"))
    fl.sort()

    nsec3_cnt = (
    pl.scan_parquet(fl).filter(pl.col("basename").is_in(dnskey_dom))
    .select(pl.col("probe_fqdn").n_unique())
    .collect()
    )
    print("Total NSEC3 count:", nsec3_cnt)

    tmpstats =  pd.DataFrame.from_dict([{"zone":zone, "dnskey":dnskey_cnt, 
                              "nsec": nsec_cnt["probe_fqdn"][0], "nsec3":nsec3_cnt["probe_fqdn"][0]}])
    stats = pd.concat([stats,tmpstats], ignore_index=True)

stats.to_csv(os.path.join(resdir,f"{datestr}_www_domcnt_stats.csv"), index=False)