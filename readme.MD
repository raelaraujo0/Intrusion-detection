# Network Scanner

This project is a basic network scanning tool that uses `nmap` to scan devices on a specified network. It records found devices in an SQLite database and saves detailed logs in JSON files. The tool also performs port scans on detected devices, providing additional information about open ports.

## Requirements

- Python 3.6 or higher
- `nmap` installed
- `lxml` library for XML parsing
- SQLite for data storage

## Clone the repository

```bash
git clone https://github.com/raelaraujo0/Network-Scanner