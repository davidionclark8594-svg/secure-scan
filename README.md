# Week 1 — Python + AppSec File Scanner

## What this tool does
This Python tool scans log/text files for security-related keywords (e.g., password, token, api key, sql, xss)
and generates a report.

## Project structure
- `src/file_scan.py` — scanner script
- `data/Sample_log.txt` — sample file to scan
- `reports/scan_report.txt` — generated report output

## How to run
From the project root (the `learning` folder), run:

```bash
python Week1/src/file_scan.py
