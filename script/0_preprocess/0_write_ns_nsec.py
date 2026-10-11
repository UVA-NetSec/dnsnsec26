import polars as pl
import pandas as pd
import os
import glob
import re
import json
import pyarrow
from config import zones, DATAROOT


"""
This script merge nsec/3 with their ns records.
config datestr to process data from different day. 
"""


datestr = "20260406"

for zone in zones:
    print(f"filter zone: {zone}")
    datadir = f"{DATAROOT}/processed/{datestr}/{zone}"
    os.makedirs(datadir, exist_ok=True)
    
    nsec_df = pl.scan_parquet(os.path.join(datadir, f"{datestr}_nsec.parquet")).collect()
    print("NSEC shape:", nsec_df.shape)
    ns_df = pl.scan_parquet(os.path.join(datadir, f"{datestr}_ns.parquet")).collect()

    gnsdf = (ns_df.group_by("query_name")
    .agg(
        pl.col("ns_address") # Polars implicitly creates a list here
    ))
    
    ns_filtered = gnsdf.join(nsec_df.select("base_name"), 
    left_on="query_name",   # Column name in ns_lookup
    right_on="base_name",   # Column name in nsecdf
    how="semi"
    )
    
    final_df = nsec_df.join(
    ns_filtered, 
    left_on="base_name",    # Column name in nsecdf
    right_on="query_name",  # Column name in ns_filtered
    how="left"
    )
    final_df.write_parquet(os.path.join(datadir,"20260406_nsec_ns.parquet"))

    nsec3_df = pl.scan_parquet(os.path.join(datadir, f"{datestr}_nsec3.parquet")).collect()
    print("NSEC3 shape:", nsec3_df.shape)

    ns3_filtered = gnsdf.join(nsec3_df.select("base_name"), 
    left_on="query_name",   # Column name in ns_lookup
    right_on="base_name",   # Column name in nsecdf
    how="semi"
    )
    
    final3_df = nsec3_df.join(
    ns3_filtered, 
    left_on="base_name",    # Column name in nsecdf
    right_on="query_name",  # Column name in ns_filtered
    how="left"
    )
    final3_df.write_parquet(os.path.join(datadir,"20260406_nsec3_ns.parquet"))
    