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
compute nsec3 distance between owner name hash and next domain name hash for www
"""

datestr = "20260406"
zones = ['net', 'com', 'org', 'umbrella','tranco','radar','majestic']

for zone in zones:
    print(f"filter zone: {zone}")
    print("Processing Zone:", zone)
    datadir = f"{PROBROOT}/{zone}/{datestr}/"
    savedir = f"{PROBROOT}/processed/{zone}/{datestr}/"
    os.makedirs(savedir, exist_ok=True)


    nsec3_df = pd.read_parquet(os.path.join(datadir, "20260406_www_nsec3.parquet"))
    print(nsec3_df.columns)
    nsec3_df = rename_www_df(nsec3_df)

    nsec3_df["rname"] = nsec3_df["response_name"].apply(lambda x: x.split(".")[0])
    nsec3_df["dist"] = nsec3_df.apply(lambda x: str(calculate_nsec3_distance(x['rname'], x['nsec3_next_domain_name_hash'], datatype="www")), axis=1)
    nsec3_df.to_parquet(os.path.join(savedir,f"{datestr}_wc_nsec3_namedist.parquet"))
