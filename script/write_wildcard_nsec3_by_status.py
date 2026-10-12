import os

import pandas as pd
from config import *

datestr = "20260406"

def parse_nsec3_line(line):
    parts = line.split()
    if len(parts) < 9 or parts[3] != "NSEC3":
        raise ValueError(f"Invalid NSEC3 record: {line}")
    return {
        "response_name": parts[0],
        "nsec3_next_domain_name_hash": parts[8],
        "nsec3_hash_algorithm": int(parts[4]),
        "nsec3_flags": int(parts[5]),
        "nsec3_iterations": int(parts[6]),
        "nsec3_salt": parts[7],
        "nsec3_owner_rrset_types": parts[9:],
    }


def parse_response(responses):
    # The notebook parses only the first response in each scan row.
    response = responses[0] if len(responses) else ""
    records = []
    ad_flag = 0
    ns_address = None
    soa_owner = None
    for line in response.splitlines():
        line = line.strip()
        parts = line.split()
        if line.startswith("flags "):
            ad_flag = int("AD" in parts)
        if len(parts) >= 7 and parts[3] == "SOA" and soa_owner is None:
            soa_owner = parts[0]
            ns_address = parts[4]
        if len(parts) >= 4 and parts[3] == "NSEC3":
            records.append(line)
    return {
        "ad_flag": ad_flag,
        "ns_address": ns_address,
        "soa_owner": soa_owner,
        "records": records,
    }


def parse_nsec3_data(total):
    df = total.loc[total["status"].isin(["NODATA", "NXDOMAIN"])].copy()
    df["base_name"] = df["basename"].map(lambda name: f"{name}.")
    parsed = df["responses"].map(parse_response)
    for column in ("ad_flag", "ns_address", "soa_owner"):
        df[column] = parsed.map(lambda response: response[column])
    df["apexIsAuth"] = df["base_name"] == df["soa_owner"]
    df["nsec3_resp"] = parsed.map(lambda response: response["records"])
    df = df.loc[df["nsec3_resp"].map(len) > 0].copy()
    df["response_type"] = "NSEC3"
    df = df.explode("nsec3_resp")
    records = df["nsec3_resp"].map(parse_nsec3_line)
    for column in (
        "response_name", "nsec3_next_domain_name_hash", "nsec3_hash_algorithm",
        "nsec3_flags", "nsec3_iterations", "nsec3_salt", "nsec3_owner_rrset_types",
    ):
        df[column] = records.map(lambda record: record[column])
    # Drop transient parser fields, including ones already present in wc_total.
    return df.drop(columns=[
        "parsed", "responses", "nsec_resp", "nsec3_resp",
        "nsec_resp_l", "nsec3_resp_l", "parsed_nsec_d",
    ], errors="ignore")


def main():
    for zone in zones:
        print("Processing Zone:", zone)
        datadir = os.path.join(PROBROOT, f"processed/{zone}/{datestr}")
        total = pd.read_parquet(
            os.path.join(datadir, f"{datestr}_wc_total.parquet")
        )
        nsec3 = parse_nsec3_data(total)
        for status, output_dir, suffix in (
            ("NODATA", datadir, "nodata"),
            ("NXDOMAIN", datadir, "nxdomain"),
        ):
            subset = nsec3.loc[nsec3["status"] == status].copy()
            output_path = os.path.join(output_dir, f"{datestr}_nsec3_{suffix}.parquet")
            subset.to_parquet(output_path)
            print(f"Wrote {len(subset)} NSEC3 records to {output_path}")


if __name__ == "__main__":
    main()
