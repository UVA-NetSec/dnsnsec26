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
compute nsec distance between owner name  and next owner name for www
"""

datestr = "20260406"
zones = ['com', 'net', 'org', 'umbrella','tranco','radar','majestic']


for zone in zones:
    print(f"filter zone: {zone}")
    print("Processing Zone:", zone)
    datadir = f"{DATAROOT}/{datestr}/{zone}/"
    savedir = f"{DATAROOT}/processed/{datestr}/{zone}"
    #resdir = f"res/NXNAME_NSes"
    #os.makedirs(resdir, exist_ok=True)

    nsec_df = pd.read_parquet(os.path.join(savedir, "20260406_nsec_ns_everything.parquet"))

    nsec_df["isCFPattern"] = nsec_df.apply(lambda x: isCFpattern(x['response_name'], x['nsec_next_domain_name']), axis=1)
    nsec_df["isSameQRname"] = nsec_df.apply(lambda x: x['query_name']== x['response_name'], axis=1)
    nsec_df["QRDist"] = nsec_df.apply(lambda x: compare_labels_from_right(x['query_name'], x['response_name']), axis=1)
    nsec_df["QNDist"] = nsec_df.apply(lambda x: compare_labels_from_right(x['query_name'], x['nsec_next_domain_name']), axis=1)
    nsec_df["NRDist"] = nsec_df.apply(lambda x: compare_labels_from_right(x['response_name'], x['nsec_next_domain_name']), axis=1)
    nsec_df.to_parquet(os.path.join(savedir,f"{datestr}_nsec_namedist_everything.parquet"))
