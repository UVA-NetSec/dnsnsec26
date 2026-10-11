import polars as pl
import pandas as pd
import os
import glob
import re
import json
import pyarrow
from config import *
from utils import *

"""
Sometimes openIntel miss nsec/nsec3 data, i.e. domain has dnskey but do not find its corresponding nsec/3 scan data.
Currently, we do not know what's going on, but we conduct extra scanning for these apex.
This script filter out domains that has dnskey but no corresponding nsec/3 data.
We save the domain names and use the list to conduct auxiliary nsec/3 scan. 

This script is reading processed data in DATAROOT/processed. Run 0_*.py before run this code.
The domain list is saved in {DATAROOT}/processed/{datestr}/{zone}/*dnskey_missing_names.txt
"""


datestr = "20260406"

for zone in zones:
    print(f"filter zone: {zone}")
    resdir = f"{DATAROOT}/processed/{datestr}/{zone}"
    
    pathname = os.path.join(resdir, f"{datestr}_dnskey_names.txt")
    with open(pathname, "r") as f:
        names = f.readlines()
    print(len(names))
    
    dnskeynames = set([name.rstrip("\n") for name in names])

    nsecdf = pd.read_parquet(f"{DATAROOT}/processed/{datestr}/{zone}/20260406_nsec_ns.parquet")
    nsec3df = pd.read_parquet(f"{DATAROOT}/processed/{datestr}/{zone}/20260406_nsec3_ns.parquet")
    if zone not in POPLIST:
        nsecdf["base_name"] = nsecdf["query_name"].apply(lambda x: ".".join(x.split(".")[1:]))
        nsec3df["base_name"] = nsec3df["query_name"].apply(lambda x: ".".join(x.split(".")[1:]))

        totalnsecdom = set(nsecdf["base_name"].unique()).union(set(nsec3df["base_name"].unique()))
        toquery = dnskeynames - totalnsecdom
        print("Total toquery:", len(toquery))
    else:
        nsecdf["base_name"] = nsecdf["query_name"].apply(lambda x: extract_base_name(x))
        nsec3df["base_name"] = nsec3df["query_name"].apply(lambda x: extract_base_name(x))
        totalnsecdom = set(nsecdf["base_name"].unique()).union(set(nsec3df["base_name"].unique()))
        toquery = dnskeynames - totalnsecdom
        print("Total toquery:",  len(toquery))

    
    resfpath = os.path.join(resdir, f"{datestr}_{zone}_dnskey_missing_names.txt")
    with open(resfpath, "w") as f:
        for name in toquery:
            f.write(name + "\n")