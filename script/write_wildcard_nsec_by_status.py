import os
import pandas as pd
from config import *

datestr = "20260406"

def parse_nsec_line(line):
    parts = line.split()
    if len(parts) < 6 or parts[3] != "NSEC":
        raise ValueError(f"Invalid NSEC record: {line}")
    return {
        "response_name": parts[0],
        "nsec_next_owner_name": parts[4],
        "nsec_owner_rrset_types": parts[5:],
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
        if len(parts) >= 4 and parts[3] == "NSEC":
            records.append(line)
    return {
        "ad_flag": ad_flag,
        "ns_address": ns_address,
        "soa_owner": soa_owner,
        "records": records,
    }


def parse_nsec_data(total):
    df = total.loc[total["status"].isin(["NODATA", "NXDOMAIN"])].copy()
    df["base_name"] = df["basename"].map(lambda name: f"{name}.")
    parsed = df["responses"].map(parse_response)
    for column in ("ad_flag", "ns_address", "soa_owner"):
        df[column] = parsed.map(lambda response: response[column])
    df["apexIsAuth"] = df["base_name"] == df["soa_owner"]
    df["nsec_resp"] = parsed.map(lambda response: response["records"])
    df = df.loc[df["nsec_resp"].map(len) > 0].copy()
    df["response_type"] = "NSEC"
    df = df.explode("nsec_resp")
    records = df["nsec_resp"].map(parse_nsec_line)
    for column in (
        "response_name", "nsec_next_owner_name", "nsec_owner_rrset_types",
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
        nsec = parse_nsec_data(total)
        for status, output_dir, suffix in (
            ("NODATA", datadir, "nodata"),
            ("NXDOMAIN", datadir, "nxdomain"),
        ):
            subset = nsec.loc[nsec["status"] == status].copy()
            output_path = os.path.join(output_dir, f"{zone}_nsec_{suffix}.parquet")
            subset.to_parquet(output_path)
            print(f"Wrote {len(subset)} NSEC records to {output_path}")


if __name__ == "__main__":
    main()

