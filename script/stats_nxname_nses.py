import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
import tldextract
import re
from config import *


datestr = "20260406"
zones = ["com", "net", "org", 'umbrella','tranco','radar','majestic']


def extract_base(name):
    match = re.search(r'awsdns-\d+', name)
    if match:
        return "awsdns"
    match = re.search(r'ultradns\d+', name)
    if match:
        return "ultradns"
    return name
    
def get_ns_dom(ns_l):
    ns_set = set()
    if ns_l is not None:
        for ns in ns_l:
            dom = tldextract.extract(ns).domain
            dom = extract_base(dom)
            ns_set.add(dom)
    return ns_set
def tostr(nsl):
    l = list(nsl)
    l.sort()
    return ",".join(l)
def get_popular_ns(df):
    df["ns_set"] = df["ns_address"].apply(lambda x: get_ns_dom(x))
    df["ns_set_l"] = df["ns_set"].map(len)
    df = df[["query_name","base_name", "ns_address", "ns_set", "ns_set_l"]].drop_duplicates(["query_name"])
    df["ns_str"] = df["ns_set"].apply(lambda x: tostr(x))
    #df_exp = df[["query_name","ns_set"]].explode("ns_set")
    nsdf = df["ns_str"].value_counts().reset_index()
    return nsdf

def hasNXNAME(nsec_owner_rrset_types):
    return "TYPE128" in nsec_owner_rrset_types
    
def get_nxname_dom(df, col):
    df["hasNXNAME"] = df[col].map(hasNXNAME)
    nxdf = df.groupby(["base_name"])[["hasNXNAME"]].agg(list).reset_index()
    nxdf["isNXNAME"] = nxdf["hasNXNAME"].map(any)
    nx_dom = set(nxdf[nxdf['isNXNAME']]["base_name"].values)
    return nx_dom

stats = pd.DataFrame()
for zone in zones:
    print("Processing Zone:", zone)
    datadir = f"{DATAROOT}/{datestr}/{zone}/"
    savedir = f"{DATAROOT}/processed/{datestr}/{zone}"
    resdir = f"res/NXNAME_NSes"
    os.makedirs(resdir, exist_ok=True)

    
    nsec_df = pd.read_parquet(os.path.join(savedir, "20260406_nsec_ns.parquet"), 
                              columns=["query_name", "nsec_owner_rrset_types", "ns_address", "base_name"])
    nsec3_df = pd.read_parquet(os.path.join(savedir, "20260406_nsec3_ns.parquet"), 
                               columns=["query_name", "nsec3_owner_rrset_types", "ns_address", "base_name"])

    nsec_dom = get_nxname_dom(nsec_df, "nsec_owner_rrset_types")
    nsec_df = nsec_df[nsec_df["base_name"].isin(nsec_dom)]
    nsec_nsdf = get_popular_ns(nsec_df)
    print("nsec_nsdf", nsec_nsdf.shape)

    nsec3_dom = get_nxname_dom(nsec3_df, "nsec3_owner_rrset_types")
    nsec3_df = nsec3_df[nsec3_df["base_name"].isin(nsec3_dom)]
    nsec3_nsdf = get_popular_ns(nsec3_df)
    print("nsec3_nsdf", nsec3_nsdf.shape)
    nsec_nsdf.to_csv(os.path.join(resdir,f"{datestr}_{zone}_nsec_top_ns.csv"), index=False)
    nsec3_nsdf.to_csv(os.path.join(resdir,f"{datestr}_{zone}_nsec3_top_ns.csv"), index=False)