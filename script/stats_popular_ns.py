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
get top ns providers for nsec/nsec3 apex
"""
datestr = "20260406"
zones = ["com", "net", "org", 'umbrella','tranco','radar','majestic']
    
def get_ns_dom(ns_l):
    ns_set = set()
    if ns_l is not None:
        for ns in ns_l:
            try:
                if ns is not None or ns != "":
                    dom = tldextract.extract(ns).domain
                    dom = extract_base(dom)
                    ns_set.add(dom)
            except:
                pass
    return ns_set

def get_popular_ns(df):
    df["ns_set"] = df["ns_address"].apply(lambda x: get_ns_dom(x))
    df["ns_set_l"] = df["ns_set"].map(len)
    df = df[["query_name","base_name", "ns_address", "ns_set", "ns_set_l"]].drop_duplicates(["query_name"])
    df_exp = df[["query_name","ns_set"]].explode("ns_set")
    nsdf = df_exp["ns_set"].value_counts().reset_index()
    return nsdf


stats = pd.DataFrame()
for zone in zones:
    print("Processing Zone:", zone)
    datadir = f"{DATAROOT}/{datestr}/{zone}/"
    savedir = f"{DATAROOT}/processed/{datestr}/{zone}"

    resdir = f"res/apexNSes"
    os.makedirs(resdir, exist_ok=True)

    nsec_df = pd.read_parquet(os.path.join(savedir, "20260406_nsec_ns_everything.parquet"),
                             columns=["query_name", "ns_address", "base_name"])
    nsec3_df = pd.read_parquet(os.path.join(savedir, "20260406_nsec3_ns_everything.parquet"),
                              columns=["query_name", "ns_address", "base_name"])
    print(nsec_df.tail())
    nsec_nsdf = get_popular_ns(nsec_df)
    print("nsec_nsdf", nsec_nsdf.shape)
    print(nsec3_df.tail())

    nsec3_nsdf = get_popular_ns(nsec3_df)
    print("nsec3_nsdf", nsec3_nsdf.shape)
    nsec_nsdf.to_csv(os.path.join(resdir,f"{datestr}_{zone}_nsec_top_ns.csv"), index=False)
    nsec3_nsdf.to_csv(os.path.join(resdir,f"{datestr}_{zone}_nsec3_top_ns.csv"), index=False)