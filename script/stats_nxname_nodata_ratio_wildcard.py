import polars as pl
import pandas as pd
import os
import glob
import dns.dnssec
import pyarrow
import dns.name
from config import *

"""
stats nodata-nxname ratio for wildcard
"""
datestr = "20260406"
rows = []

for zone in zones:
    print(zone)

    for record_type in ["nsec", "nsec3"]:
        bitmap_column = f"{record_type}_owner_rrset_types"

        df = pd.read_parquet(
            f"{PROBROOT}/processed/{zone}/{datestr}/"
            f"{datestr}_www_{record_type}_namedist_final.parquet",
            columns=["query_name", "status", bitmap_column],
        )

        total = df["query_name"].nunique()

        # Check every NODATA record before counting unique queries.
        nodata = df.loc[df["status"].eq("NODATA")]
        has_nxname = nodata[bitmap_column].apply(
            lambda types: (
                "TYPE128" in types.split()
                if isinstance(types, str)
                else "TYPE128" in types if types is not None else False
            )
        )

        count = nodata.loc[has_nxname, "query_name"].nunique()

        rows.append({
            "total": total,
            "count": count,
            "perc": count / total if total else 0.0,
            "zone": zone,
            "type": f"{record_type} (nodata-nxname)",
        })

stats = pd.DataFrame(rows)
print(stats)

os.makedirs("res", exist_ok=True)
stats.to_csv(
    f"res/{datestr}_wildcard_nodata_nxname_ratio.csv",
    index=False,
)