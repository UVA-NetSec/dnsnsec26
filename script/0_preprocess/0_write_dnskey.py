import polars as pl
import pandas as pd
import os
import glob
import re
import json
import pyarrow
from utils import *
from config import zones, POPLIST, DATAROOT, PROBROOT


"""
This code write domains that has a DNSkey.
Read from {DATAROOT}/{datestr}/{zone}/, write to {DATAROOT}/processed/{datestr}/{zone}.
"""

datestr = "20260406"

for zone in zones:
    print(f"filter zone: {zone}")
    datadir = f"{DATAROOT}/{datestr}/{zone}/"
    resdir = f"{DATAROOT}/processed/{datestr}/{zone}"
    os.makedirs(datadir, exist_ok=True)
    fl = glob.glob(os.path.join(datadir, "*.gz.parquet"))
    fl.sort()

    dnskey = (
    pl.scan_parquet(fl)
    .select(['query_type','query_name', 'response_type','dnskey_flags'])
    .filter(
        (pl.col("query_type") == "DNSKEY") &
        (pl.col("response_type") == "DNSKEY") &
        (pl.col("dnskey_flags").is_not_null())
    )
    .collect()
    )
    if zone not in POPLIST:
        base_names = dnskey.select("query_name").unique()
        pathname = os.path.join(resdir, f"{datestr}_dnskey_names.txt")
        with open(pathname, "w") as f:
            for name in base_names["query_name"]:
                f.write(name + "\n")
    else:
        dnskey = dnskey.with_columns(
                    pl.col("query_name").map_elements(extract_base_name,return_dtype=pl.Utf8).alias("apex_name")
                )
        base_names = dnskey.select("apex_name").unique()
        pathname = os.path.join(resdir, f"{datestr}_dnskey_names.txt")
        with open(pathname, "w") as f:
            for name in base_names["apex_name"]:
                f.write(name + "\n")