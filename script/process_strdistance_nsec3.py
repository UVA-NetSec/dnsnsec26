import polars as pl
import pandas as pd
import os
import glob
import re
import json
import pyarrow
from utils import *
from config import *

"""
compute nsec3 distance between owner name hash and next domain name hash for apex
"""

datestr = "20260406"
zones = ['com', 'net', 'org', 'umbrella','tranco','radar','majestic']

for zone in zones:
    print(f"filter zone: {zone}")
    print("Processing Zone:", zone)
    datadir = f"{DATAROOT}/{datestr}/{zone}/"
    savedir = f"{DATAROOT}/processed/{datestr}/{zone}"

    nsec3_df = pd.read_parquet(os.path.join(savedir, "20260406_nsec3_ns_everything.parquet"), 
                              columns=["query_name", "response_name", "nsec3_next_domain_name_hash", "status_code", "nsec3_owner_rrset_types", "ns_address"])

    nsec3_df["rname"] = nsec3_df["response_name"].apply(lambda x: x.split(".")[0])
    nsec3_df["nname"] = nsec3_df["nsec3_next_domain_name_hash"].apply(lambda x: x[2:])
    nsec3_df["dist"] = nsec3_df.apply(lambda x: str(calculate_nsec3_distance(x['rname'], x['nname'])), axis=1)
    nsec3_df.to_parquet(os.path.join(savedir,f"{datestr}_nsec3_namedist_everything.parquet"))
