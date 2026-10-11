import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
import tldextract
import re

datestr = "20260406"
zones = ["com", "net", "org", 'umbrella','tranco','radar','majestic']

def extract_base(name):
    match = re.search(r'awsdns-\d+', name)
    return "awsdns" if match else name
    
def get_ns_dom(ns_l):
    ns_set = set()
    if ns_l is not None:
        for ns in ns_l:
            dom = tldextract.extract(ns).domain
            dom = extract_base(dom)
            ns_set.add(dom)
    return ns_set

def get_popular_ns(df):
    df["ns_set"] = df["ns_address"].apply(lambda x: get_ns_dom(x))
    df["ns_set_l"] = df["ns_set"].map(len)
    df = df[["query_name","base_name", "ns_address", "ns_set", "ns_set_l"]].drop_duplicates(["query_name"])
    df_exp = df[["query_name","ns_set"]].explode("ns_set")
    nsdf = df_exp["ns_set"].value_counts().reset_index()
    return nsdf

def concat_df(fl, zone, filterdom):
    wcdfl = []
    for f in fl:
        print(f)
        tmpdf = pd.read_json(f, lines=True)
        if "basename" in tmpdf.columns:
            tmpdf["base_name"] = tmpdf["basename"].apply(lambda x: f"{x}.")
        
        if "queryname" in tmpdf.columns:
            tmpdf = tmpdf.rename(columns={"queryname": "probe_fqdn"})
        if "record_type" in tmpdf.columns:
            tmpdf = tmpdf.rename(columns={"record_type": "rtype"})
    
        if zone == "com":
            tmpdf = tmpdf[tmpdf["base_name"].isin(filterdom)]
        
        if "probe" in f:
            tmpdf["fqdn"] = tmpdf["probe_fqdn"].apply(lambda x: ".".join(x.split(".")[1:]))
            
        wcdfl.append(tmpdf)
    return wcdf
    
stats = pd.DataFrame()
for zone in zones:
    print("Processing Zone:", zone)
    datadir = f"{DATAROOT}/{datestr}/{zone}/"
    savedir = f"{DATAROOT}/processed/{datestr}/{zone}"
    resdir = f"res/NSes"
    os.makedirs(resdir, exist_ok=True)
    
    nsec_df = pd.read_parquet(os.path.join(savedir, "20260406_nsec_ns.parquet"), 
                              columns=["query_name", "ns_address", "base_name"])
    nsec3_df = pd.read_parquet(os.path.join(savedir, "20260406_nsec3_ns.parquet"), 
                               columns=["query_name", "ns_address", "base_name"])

    nsec_nsdf = get_popular_ns(nsec_df)
    print("nsec_nsdf", nsec_nsdf.shape)
    nsec3_nsdf = get_popular_ns(nsec3_df)
    print("nsec3_nsdf", nsec3_nsdf.shape)

    
    nsec_nsdf.to_csv(os.path.join(resdir,f"{datestr}_{zone}_nsec_top_ns.csv"), index=False)
    nsec3_nsdf.to_csv(os.path.join(resdir,f"{datestr}_{zone}_nsec3_top_ns.csv"), index=False)