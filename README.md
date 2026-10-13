# dnsnsec26

Research artifacts for **Dissecting NSEC and NSEC3 Deployment in the Wild** (IMC 2026). 

This repo contains preprocessing and analysis scripts, saved CSV summaries, and reproduction notebooks. 

### Paper correction
---
Table 9 correction: The original paper interchanged the NSEC3 NODATA and NXDOMAIN percentages for Umbrella, Tranco, Radar, and Majestic due to initial excel copy and paste error. Swap the two values within each of these four rows, correcting eight cells in total. The reproduction notebook uses the correct column assignments. 

Table 6 correction: The rightmost column name should be NSEC3.

## Package Installation

Use **Python 3.10 or later**.

The project dependencies are defined in `pyproject.toml`. From the repository root, create and activate a virtual environment, upgrade `pip`, and install the project dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install .
```

### Jupyter Kernel Setup

After installing the project dependencies, register the virtual environment as a Jupyter kernel:

```bash
python -m ipykernel install \
    --user \
    --name dnsnsec26 \
    --display-name "Python (dnsnsec26)"
```

The kernel can then be selected in JupyterLab as:

```text
Python (dnsnsec26)
```

Start JupyterLab with:

```bash
jupyter lab
```

### Verifying the Environment

After installation, verify that the expected Python interpreter is active:

```bash
which python
python --version
```

The Python executable should point to the repository's `.venv` directory, for example:

```text
/path/to/repository/.venv/bin/python
```

## Reproduce tables from saved summaries
Open a notebook from the table below and run all cells in order. The table notebooks find the repository root from their working directory and load processed stats to reproduce the results. (The original stats in the paper were computed via excel, so these notebooks are newly written for viewing the stats. )


### Code functionality explaination

All stats filenames below are relative to `script/res/`. All producer commands use **`script/` as the working directory**: for example, `cd script`, then `python stats_domcnt.py`. Run paired scripts in the listed order, and run the corresponding notebook afterward. Producers require processed measurements; skip them when using the supplied CSVs.

| Paper item | Summary producer(s): run with `python <filename>` from `script/` | Notebook / final reproduction | Inputs and completeness |
| --- | --- | --- | --- |
| **Table 1: DNSSEC and NSEC/3 adoption** | [stats_domcnt.py](script/stats_domcnt.py), [stats_domcnt_www.py](script/stats_domcnt_www.py) | [table1_adoption.ipynb](notebook/table1_adoption.ipynb) | `20260406_domcnt_stats.csv`, `20260406_www_domcnt_stats.csv`. Computes DNSKEY/SOA and NSEC/3/DNSKEY percentages; exports counts and formatted table. |
| **Table 2: Validated responses** | [stats_authenticated.py](script/stats_authenticated.py), [stats_authenticated_www.py](script/stats_authenticated_www.py); Table 1 producers for denominators | [table2_validated_responses.ipynb](notebook/table2_validated_responses.ipynb) | `20260406_adflag_stats.csv`, `20260406_www_adflag_stats.csv`, both Table 1 summaries, and [pre-auxiliary reference counts](notebook/reference/20260406_openintel_pre_auxiliary_domcnt.csv). Displays corrected and historical calculations plus paper corrections. |
| **Table 3: NSEC/3 RRs per query** | [stats_rrcnt.py](script/stats_rrcnt.py), [stats_rrcnt_www.py](script/stats_rrcnt_www.py) | [table3_rr_counts.ipynb](notebook/table3_rr_counts.ipynb) | `20260406_rrcnt_stats.csv`, `20260406_www_rrcnt_stats.csv`. Percentages use all RR-count bins in each distribution; exports paper bins and omitted categories. |
| **Table 4: NXDOMAIN proportions** | [stats_nxdomain_ratio.py](script/stats_nxdomain_ratio.py), [stats_nxdomain_ratio_www.py](script/stats_nxdomain_ratio_www.py) | [table4_nxdomain_ratios.ipynb](notebook/table4_nxdomain_ratios.ipynb) | `20260406_nxdomain_ratio_stats.csv`, `20260406_www_nxdomain_ratio.csv`, Table 1 source summary, and [paper reference](notebook/reference/20260406_table4_paper_percentages.csv). Uses the general WWW population, not the restricted wildcard population. |
| **Table 5: Minimally covering NSEC patterns** | Related features: [process_strdistance.py](script/process_strdistance.py), [process_strdistance_www.py](script/process_strdistance_www.py); pattern predicates in [stats_nsec_wlcde.py](script/stats_nsec_wlcde.py) | - | Partial support. The published example/pattern catalog and provider associations were manually curated. |
| **Table 6: White Lies and CDE adoption** | [stats_nsec_wlcde.py](script/stats_nsec_wlcde.py), [stats_nsec3_wlcde.py](script/stats_nsec3_wlcde.py), after distance processing | [table6_variant_adoption.ipynb](notebook/table6_variant_adoption.ipynb) | `20260406_nsec_cde_wl.csv`, `20260406_www_nsec_cde_wl.csv`, `20260406_nsec3_cde_wl_everything.csv`, `20260406_nsec3_cde_wl_www_everything.csv`. Computes variant count / file's mechanism total. Producer filename adjustments are required; see below. |
| **Table 7: Providers' NXNAME deployment** | [stats_nxname_nses.py](script/stats_nxname_nses.py) | - | manually curated|
| **Table 8: Wildcard prevalence** | [write_wildcard_scandom_stats.py](script/write_wildcard_scandom_stats.py), plus Table 1 source producer | [table8_wildcard_prevalence.ipynb](notebook/table8_wildcard_prevalence.ipynb) | The current notebook reads **`wildcard/20260406_wildcard_stats.csv`**, and `20260406_domcnt_stats.csv`. `wildcard/20260406_wildcard_stats_new.csv` also exists but is not its current input. ACK/candidate percentages use source mechanism totals. |
| **Table 9: WWW wildcard-response distribution** | [stats_nxdomain_ratio_wildcard.py](script/stats_nxdomain_ratio_wildcard.py), [stats_nxname_nodata_ratio_wildcard.py](script/stats_nxname_nodata_ratio_wildcard.py), after wildcard preparation | [table9_wildcard_response_distribution.ipynb](notebook/table9_wildcard_response_distribution.ipynb) | `20260406_wildcard_nxdomain_ratio.csv`, `20260406_wildcard_nodata_nxname_ratio.csv`. Splits NSEC NODATA by NXNAME presence; NSEC3 keeps NXNAME within NODATA. The recommended notebook includes detailed paper comparisons and swap corrections; the alternative exports the simpler table into `notebook/results/`. |

### Paper figures

| Paper item | Code and run order | Inputs / missing work |
| --- | --- | --- |
| **Figure 3: Joint NSEC name-distance density** | Run `python process_strdistance*.py` from `script/`, then run the **NSEC Distance** section of [figure_openintel_strdistance_plot.ipynb](notebook/figure_openintel_strdistance_plot.ipynb) | External source `.com` distance Parquet. Set the notebook's `DATAROOT` and correct its input filename as described below. Produces NODATA/NXDOMAIN panels; paper layout and red annotations need manual assembly. |
| **Figure 6: NSEC3 interval-distance ECDF** | Run `python process_strdistance_nsec3.py` from `script/`, then run the **NSEC3 Distance** section of [figure_openintel_strdistance_plot.ipynb](notebook/figure_openintel_strdistance_plot.ipynb) | External source `.com` NSEC3 distance Parquet. Set `DATAROOT`, correct filename, and explicitly decide how to handle zero distances on the log axis. |


## Obtain initial raw data

### OpenINTEL snapshot

Please bbtain the OpenINTEL data directly. OpenINTEL lists zones data as closed datasets available by request on its [zone-based data page](https://openintel.nl/data/forward-dns/zone-based/). Obtain the popularity-list measurements from its [download index](https://openintel.nl/download/forward-dns/). 

Download all relevant Parquet parts. Store them as:

```text
<DATAROOT>/20260406/com/*.gz.parquet
<DATAROOT>/20260406/net/*.gz.parquet
<DATAROOT>/20260406/org/*.gz.parquet
<DATAROOT>/20260406/umbrella/*.gz.parquet
<DATAROOT>/20260406/tranco/*.gz.parquet
<DATAROOT>/20260406/radar/*.gz.parquet
<DATAROOT>/20260406/majestic/*.gz.parquet
```

### Auxiliary, WWW, and wildcard scan outputs

The probe data of popularity list will be partially release in our website. The zone data will only be released upon request when you have access to the direct zone file or the directon zone data collection from openIntel.  

## Process raw measurements

### Configure paths and date

Set absolute `DATAROOT` and `PROBROOT` paths in **both** [script/config.py](script/config.py) and [script/0_preprocess/config.py](script/0_preprocess/config.py). They are separate modules and currently contain empty strings. For example:

```python
DATAROOT = "/absolute/path/to/openintel"
PROBROOT = "/absolute/path/to/probes"
```

`zones` identifies all seven datasets; `POPLIST` identifies the four ranking datasets. Most scripts hardcode `datestr = "20260406"`, and many also hardcode the date inside filenames. For another snapshot, change every relevant date/path consistently. The scripts generally have no command-line arguments and execute their configured datasets at module load.

### Source preprocessing

Run from the repository root:

```bash
cd script/0_preprocess
python 0_write_apex_nsec.py
python 0_write_ns_nsec.py
python 0_write_dnskey.py
python 1_write_openintel_missing_dnskey.py
```

| Script | Result / next step |
| --- | --- |
| `0_write_apex_nsec.py` | Extracts NSEC, NSEC3, and NS to `<DATAROOT>/processed/20260406/<zone>/20260406_<type>.parquet`. |
| `0_write_ns_nsec.py` | Joins NS information; writes `20260406_nsec_ns.parquet` and `20260406_nsec3_ns.parquet`. |
| `0_write_dnskey.py` | Writes `20260406_dnskey_names.txt`; popular-list names are converted to apex targets. |
| `1_write_openintel_missing_dnskey.py` | Writes `20260406_<zone>_dnskey_missing_names.txt`. Despite its name, these targets **have DNSKEY but lack observed NSEC/3**. Collect auxiliary scans externally now. |

After placing auxiliary responses in the expected locations, continue from `script/0_preprocess/`:

```bash
python 1_concat_openintel_scan.py
python 2_merge_openintel_scan.py
```

The concatenation step writes parsed auxiliary data to `<PROBROOT>/<zone>/20260406/apex_scan_parsed/`. The merge step writes `20260406_nsec_ns_everything.parquet` and `20260406_nsec3_ns_everything.parquet` into the source processed directory. Most source statistics consume these merged files. Omitting auxiliary scans changes their populations and requires explicit changes to consumers; it is not the same reproduction path.

### WWW preprocessing and distance features

After collecting the WWW JSONL externally, run from `script/0_preprocess/`:

```bash
python 3_parse_www_nsec_data.py
python 3_parse_www_nsec_soa_nsdata.py
python 3_parse_www_ns_nsec.py
cd ..
mkdir -p res/wildcard
python process_strdistance.py
python process_strdistance_nsec3.py
python process_strdistance_www.py
python process_strdistance_nsec3_www.py
```

- `write_wildcard_scanning.py` references **`candidate_dir`**, which is not defined in the supplied config. Define it in `script/config.py`, for example `candidate_dir = "/absolute/path/to/dnsnsec26/script/res/wildcard"`, before running that script.


### Wildcard preparation

Run each step below from `script/`.


| Order | Command | Inputs and output |
| --- | --- | --- |
| 1 | `python write_wildcard_scandom_stats.py` | Reads merged source NSEC/3 records; writes `res/wildcard/20260406_wildcard_stats.csv` for Table 8. Enable its commented `with open(...)` blocks to also write `20260406_<zone>_nsec_wc.txt` and `20260406_<zone>_nsec3_wc.txt`. |
| 2 | `python write_concat_wildcard_raw.py` | Reads candidate lists and general WWW distance Parquets; writes `20260406_www_nsec_namedist_final.parquet`, `20260406_www_nsec3_namedist_final.parquet`, and `res/wildcard/subdomain_query_stats.csv` for Table 11. The `_final` files feed the NXNAME summary for Table 9. |
| 3 | `python write_parse_wildcard_raw.py` | Reads candidate lists and dedicated JSONL; writes `wildcard_scan_nsec_raw_total.parquet` and `wildcard_scan_nsec3_raw_total.parquet` under `<PROBROOT>/processed/<zone>/20260406/`. |
| 4 | `python write_wildcard_scanning.py` | Requires `candidate_dir` and exclusion files; filters scan candidates and combines data into `20260406_wc_total.parquet`. |
| 5 | `python stats_nxdomain_ratio_wildcard.py` | Parses/deduplicates `_wc_total.parquet`; writes `res/20260406_wildcard_nxdomain_ratio.csv`. |
| 6 | `python stats_nxname_nodata_ratio_wildcard.py` | Reads the `_www_<type>_namedist_final.parquet` files; counts `TYPE128` within NODATA and writes `res/20260406_wildcard_nodata_nxname_ratio.csv`. Run the Table 9 notebook afterward. |

Optional response-level exports: `python write_wildcard_nsec_by_status.py` and `python write_wildcard_nsec3_by_status.py` parse `_wc_total.parquet` into NODATA/NXDOMAIN record Parquets. The NSEC script names them `<zone>_nsec_nodata.parquet` / `<zone>_nsec_nxdomain.parquet`; the NSEC3 script names them `20260406_nsec3_nodata.parquet` / `20260406_nsec3_nxdomain.parquet`. Neither is required to run the summary Table 9 notebook.
