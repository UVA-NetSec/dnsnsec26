import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
from config import *


"""
whitelies and cde counts for apex/www
"""

"""
helper functions
"""

def extract_base(name):
    match = re.search(r'awsdns-\d+', name)
    if match:
        return "awsdns"
    match = re.search(r'ultradns\d+', name)
    if match:
        return "ultradns"

    match = re.search(r'dnsimple(?:-|\d+)?', name)
    if match:
        return "dnsimple"
        
    if re.search(r'^cdmon', name):
        return "cdmon"
    return name
    
def get_ns_dom(ns_l):
    ns_set = set()
    if ns_l is not None:
        for ns in ns_l:
            dom = tldextract.extract(ns).domain
            dom = extract_base(dom)
            ns_set.add(dom)
    return ns_set
    
def nstostr(nsset):
    nsl = list(nsset)
    nsl.sort()
    return ",".join(nsl)

def ultradns_pattern(qname, rname, nname):
    randstr = qname.split(".")[0]
    nname_base = nname.split(".")[0]
    rname_base = rname.split(".")[0]
    #if rname_base == "~":
    #    rname_tail = rname.split(".")[1][-1:]
    #else:
    #    rname_tail = rname.split(".")[0][-1:]
    if "!" in nname:
        return True
    if rname_base == "*" and nname_base == "-":
        return True
    if "~" in rname:
        return True
    return False

def fastly_pattern(rname, nname):
    nname_base = nname.split(".")[0]
    rname_base = rname.split(".")[0]
    if nname_base == "-" and rname_base=="!~":
        return True
    return False

def wildcard_deny(rname, nname):
    nname_base = nname.split(".")[0]
    rname_base = rname.split(".")[0]
    if rname_base.startswith("\)") and nname_base.endswith("\000"):
        return True
    return False

def boundary(rname, nname):
    nname_base = nname.split(".")[0]
    rname_base = rname.split(".")[0]
    if rname_base.endswith("\\255") and nname_base.endswith("\\000"):
        return True
    return False

def isWhiteLies(qname, rname, nname, rdist, ndist):
    if rdist<2 and ndist<2:
        return True
    if ultradns_pattern(qname, rname, nname):
        return True
    if fastly_pattern(rname, nname) or wildcard_deny(rname, nname) or boundary(rname, nname):
        return True
    return False

datestr = "20260406"
zones = ["com", "net", "org", 'umbrella','tranco','radar','majestic']

stats = pd.DataFrame()
for zone in zones:
    print(f"filter zone: {zone}")
    print("Processing Zone:", zone)
    datadir = f"{DATAROOT}/processed/{datestr}/{zone}"
    resdir = f"res/"
    #os.makedirs(resdir, exist_ok=True)

    nsec_df = pd.read_parquet(os.path.join(datadir, f"{datestr}_nsec_namedist.parquet"))
    nsec_df_dom = nsec_df["query_name"].nunique()
    nsec_df_cde = nsec_df.loc[nsec_df["isCFPattern"]]
    nsec_df_cde_cnt = nsec_df_cde["query_name"].nunique()

    nsec_df_nocf = nsec_df.loc[nsec_df["isCFPattern"]==False]
    nsec_df_nocf["isWhiteLies"] = nsec_df_nocf.apply(lambda x:isWhiteLies(x["query_name"],
                                                        x["response_name"], x["nsec_next_domain_name"],
                                                        x["QRDist"], x["QNDist"]), axis=1)
    nsec_df_whitelies = nsec_df_nocf.loc[nsec_df_nocf["isWhiteLies"]]
    nsec_df_whitelies_cnt = nsec_df_whitelies["query_name"].nunique()

    tmpstats =  pd.DataFrame.from_dict([{"zone":zone, "nseccnt": nsec_df_dom, "whitelies":nsec_df_whitelies_cnt, 
                                        "cde": nsec_df_cde_cnt, "wl_perc": nsec_df_whitelies_cnt/nsec_df_dom,
                                        "cde_perc": nsec_df_cde_cnt/nsec_df_dom}])
    stats = pd.concat([stats, tmpstats], ignore_index=True)

stats.to_csv(os.path.join(resdir,f"{datestr}_nsec_cde_wl.csv"),index=False)

stats = pd.DataFrame()
for zone in zones:
    print(f"filter zone: {zone}")
    print("Processing Zone:", zone)
    datadir = f"{PROBROOT}/processed/{zone}/{datestr}/"
    resdir = f"res"
    #os.makedirs(resdir, exist_ok=True)

    nsec_df = pd.read_parquet(os.path.join(datadir, f"{datestr}_www_nsec_namedist.parquet"))
    nsec_df_dom = nsec_df["query_name"].nunique()
    nsec_df_cde = nsec_df.loc[nsec_df["isCFPattern"]]
    nsec_df_cde_cnt = nsec_df_cde["query_name"].nunique()

    nsec_df_nocf = nsec_df.loc[nsec_df["isCFPattern"]==False]
    nsec_df_nocf["isWhiteLies"] = nsec_df_nocf.apply(lambda x:isWhiteLies(x["query_name"],
                                                        x["response_name"], x["nsec_next_domain_name"],
                                                        x["QRDist"], x["QNDist"]), axis=1)
    nsec_df_whitelies = nsec_df_nocf.loc[nsec_df_nocf["isWhiteLies"]]
    nsec_df_whitelies_cnt = nsec_df_whitelies["query_name"].nunique()

    tmpstats =  pd.DataFrame.from_dict([{"zone":zone, "nseccnt": nsec_df_dom, "whitelies":nsec_df_whitelies_cnt, 
                                        "cde": nsec_df_cde_cnt, "wl_perc": nsec_df_whitelies_cnt/nsec_df_dom,
                                        "cde_perc": nsec_df_cde_cnt/nsec_df_dom}])
    stats = pd.concat([stats, tmpstats], ignore_index=True)

stats.to_csv(os.path.join(resdir,f"{datestr}_www_nsec_cde_wl.csv"),index=False)