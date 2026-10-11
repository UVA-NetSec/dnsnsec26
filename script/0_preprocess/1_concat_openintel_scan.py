import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
import tldextract
import json
from parseutils import *
from config import zones, POPLIST, DATAROOT, PROBROOT

"""
Sometimes openIntel miss nsec/nsec3 data, i.e. domain has dns-sec configuration, 
but no corresponding nsec/nsec3 records. 
Currently, we do not know what's going on, but we conduct extra scanning for these apex.
This script concat our probe data into a unified dataframe for future analysis. 

Run write_openintel_missing_dnskey.py first, to get domains that need to be query and then scan the domain name and put the scan data in PROBROOT.
this script assumes that the probe data is in PROBROOT
"""


def write_chunk(data, fname):
    with open(fname, "w") as f:
        for line in data:
            f.write(json.dumps(line) + "\n")

datestr = "20260406"
subfolder = "apex_scan_parsed"

for zone in zones:
    print(zone)
    datadir = f"{PROBROOT}/{zone}/{datestr}/apex_scan_nsec"
    fl = glob.glob(f"{PROBROOT}/{zone}/{datestr}/apex_scan_nsec/*afsdb*")
    fl.sort()
    savedir = f"{PROBROOT}/{zone}/{datestr}/{subfolder}"
    os.makedirs(savedir, exist_ok=True)

    fl = glob.glob(f"{PROBROOT}/{zone}/{datestr}/apex_scan_nsec/*afsdb*")
    fl.sort()
    nsec_l = []
    nsec3_l = []
    all_l = []
    for f in fl:
        tmpdf = pd.read_json(f, lines=True)
        print("fpath:", f, "\ncolumns", tmpdf.columns)
        
        if "record_type" in tmpdf.columns:
            tmpdf = tmpdf.rename(columns={"record_type": "rtype"})
        if "base_name" in tmpdf.columns:
            tmpdf = tmpdf.rename(columns={"base_name": "basename"})
        if "queryname" in tmpdf.columns:
            tmpdf = tmpdf.rename(columns={"queryname": "probe_fqdn"})
            col = "probe_fqdn"
            tmpdf["fqdn"] = tmpdf["probe_fqdn"].apply(lambda x: ".".join(x.split(".")[1:]))
        
        if "fqdn" not in tmpdf.columns and "probe_fqdn" in tmpdf.columns:
            tmpdf["fqdn"] = tmpdf["probe_fqdn"].apply(lambda x: ".".join(x.split(".")[1:]))

        tmpnsec, tmpnsec3 = parse_probe_data(tmpdf)
        all_l.append(tmpdf)
        nsec_l.append(tmpnsec)
        nsec3_l.append(tmpnsec3)

    alldf = pd.concat(all_l)
    nsecdf = pd.concat(nsec_l)
    nsec3df = pd.concat(nsec3_l)
    alldf.to_parquet(os.path.join(savedir, f"{datestr}_apex_scan_everything.parquet"))
    nsecdf.to_parquet(os.path.join(savedir, f"{datestr}_apex_scan_nsec.parquet"))
    nsec3df.to_parquet(os.path.join(savedir, f"{datestr}_apex_scan_nsec3.parquet"))