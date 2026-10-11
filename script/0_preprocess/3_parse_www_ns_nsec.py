import polars as pl
import pandas as pd
import os
import glob
import re
import json
import pyarrow
from config import *

"""
Find ns information for www data.
"""

datestr = "20260406"

for zone in zones:
    print(f"filter zone: {zone}")
    datadir = f"{PROBROOT}/{zone}/{datestr}/"

    os.makedirs(datadir, exist_ok=True)
    
    nsec_df = pd.read_parquet(os.path.join(datadir, f"{datestr}_www_nsec.parquet"))
    print("NSEC shape:", nsec_df.shape)
    ns_df = pd.read_parquet(os.path.join(datadir, f"{datestr}_www_soa_ns_final.parquet"))
    

    nsec_df = nsec_df.merge(ns_df[["probe_fqdn", "ns_address"]], on="probe_fqdn", how="left")
    nsec_df.to_parquet(os.path.join(datadir,"20260406_www_nsec_ns.parquet"))

    nsec3_df = pd.read_parquet(os.path.join(datadir, f"{datestr}_www_nsec3.parquet"))
    print("NSEC3 shape:", nsec3_df.shape)
    nsec3_df = nsec3_df.merge(ns_df[["probe_fqdn", "ns_address"]], on="probe_fqdn", how="left")
    nsec3_df.to_parquet(os.path.join(datadir,"20260406_www_nsec3_ns.parquet"))

    