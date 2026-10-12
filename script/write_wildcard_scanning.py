import os
import pandas as pd
from config import *

datestr = "20260406"

def read_domain_names(path):
    with open(path, "r") as file:
        return {domain.rstrip(".\n") for domain in file}


def filter_candidate_domains(nsec_domains, nsec3_domains, apex_noa,
                             notfound, nsec_raw, nsec3_raw):
    raw_domains = set(nsec_raw["basename"].unique()).union(
        set(nsec3_raw["basename"].unique())
    )
    apex_true_noa = apex_noa - raw_domains
    return (
        nsec_domains - notfound - apex_true_noa,
        nsec3_domains - notfound - apex_true_noa,
    )


def create_wc_total(nsec_raw, nsec3_raw, nsec_found, nsec3_found):
    nsec_remaining = nsec_raw.loc[nsec_raw["basename"].isin(nsec_found)]
    nsec3_remaining = nsec3_raw.loc[nsec3_raw["basename"].isin(nsec3_found)]
    return pd.concat([nsec_remaining, nsec3_remaining])


def main():
    for zone in zones:
        print("Processing Zone:", zone)
        # Resolve these paths per zone rather than relying on notebook state.
        datadir = os.path.join(PROBROOT, zone, datestr)
        rawdir = os.path.join(PROBROOT, "processed", zone, datestr)
        nsec_domains = read_domain_names(
            os.path.join(candidate_dir, f"{datestr}_{zone}_nsec_wc.txt")
        )
        nsec3_domains = read_domain_names(
            os.path.join(candidate_dir, f"{datestr}_{zone}_nsec3_wc.txt")
        )
        errors = pd.read_json(os.path.join(datadir, "errors.jsonl"), lines=True)
        try:
            apex_noa = set(errors["basename"])
        except:
            apex_noa = set(errors["base_name"])
        notfound = read_domain_names(os.path.join(datadir, "not_found.txt"))
        notfound.update(read_domain_names(
            os.path.join(datadir, "sub_extra_scan", "not_found.txt")
        ))
        nsec_raw = pd.read_parquet(
            os.path.join(rawdir, "wildcard_scan_nsec_raw_total.parquet")
        )
        nsec3_raw = pd.read_parquet(
            os.path.join(rawdir, "wildcard_scan_nsec3_raw_total.parquet")
        )
        nsec_found, nsec3_found = filter_candidate_domains(
            nsec_domains, nsec3_domains, apex_noa, notfound, nsec_raw, nsec3_raw
        )
        wc_total = create_wc_total(nsec_raw, nsec3_raw, nsec_found, nsec3_found)
        output_path = os.path.join(PROBROOT, f"processed/{zone}/{datestr}", f"{datestr}_wc_total.parquet")
        wc_total.to_parquet(output_path)
        print(f"Wrote {len(wc_total)} scan rows to {output_path}")


if __name__ == "__main__":
    main()
