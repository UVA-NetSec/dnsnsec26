import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
import tldextract
import re
from utils import *
from config import *

"""
top ns providers for www subdomains
"""

datestr = "20260406"
zones = ["com", "net", "org", 'umbrella','tranco','radar','majestic']
    
def get_ns_dom(ns):
    dom = None
    if ns is not None:
        dom = tldextract.extract(ns).domain
        dom = extract_base(dom)
    return dom

def get_popular_ns(df, datatype="sub"):
    df["ns_str"] = df["ns_address"].apply(lambda x: get_ns_dom(x))
    if datatype == "sub":
        df = df[["probe_fqdn", "ns_address", "ns_str"]].drop_duplicates(["probe_fqdn"])
        df_exp = df[["probe_fqdn","ns_str"]].explode("ns_str")
    else:
        df = df[["query_name", "ns_address", "ns_str"]].drop_duplicates(["query_name"])
        df_exp = df[["query_name","ns_str"]].explode("ns_str")
    nsdf = df_exp["ns_str"].value_counts().reset_index()
    return nsdf


stats = pd.DataFrame()
for zone in zones:
    print("Processing Zone:", zone)
    datadir = f"{PROBROOT}/{zone}/{datestr}/"
    savedir = f"{PROBROOT}/{zone}/{datestr}/"
    resdir = f"res/wwwNSes"
    os.makedirs(resdir, exist_ok=True)

    
    nsec_df = pd.read_parquet(os.path.join(savedir, "20260406_www_nsec_ns.parquet"), 
                              columns=["probe_fqdn", "ns_address", ])
    nsec3_df = pd.read_parquet(os.path.join(savedir, "20260406_www_nsec3_ns.parquet"), 
                               columns=["probe_fqdn", "ns_address", ])
    print(nsec_df)
    nsec_nsdf = get_popular_ns(nsec_df)
    print("nsec_nsdf", nsec_nsdf.shape)
    nsec3_nsdf = get_popular_ns(nsec3_df)
    print("nsec3_nsdf", nsec3_nsdf.shape)
    nsec_nsdf.to_csv(os.path.join(resdir,f"{datestr}_{zone}_nsec_top_ns.csv"), index=False)
    nsec3_nsdf.to_csv(os.path.join(resdir,f"{datestr}_{zone}_nsec3_top_ns.csv"), index=False)