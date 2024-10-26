# Admin Login Finder Tool

This tool helps in finding admin login panels and attempting to bypass restrictions by checking common admin paths and subdomains. It supports different technologies like PHP, ASP, and general admin panels.

## Features
- Scans common admin paths for PHP and ASP-based applications.
- Checks subdomains like `admin.example.com`, `cpanel.example.com`, etc., for admin panels.
- Skips unreachable subdomains to avoid unnecessary scans.
- Detects false positives based on common error messages.

## Requirements

To run this tool, you'll need to have Python installed along with the following packages:

- `requests`
- `argparse`
- `colorama`

You can install the required packages using:
```bash
pip install -r requirements.txt
```
Run the tool with the following command:
```bash
python3 admin-finder.py https://www.example.com


