import sys
import time
import subprocess
import xml.etree.ElementTree as etxml
import signal
from dbmanager import init_Db, isner_Scan_Record
from writelogjson import save_Json_Log
import os

port_risks = {
    'high': [22, 23, 445, 3389],
    'medium': [80, 443, 3306],
    'low': [631, 9100]
}

def classify_port(port):
    for risk, ports in port_risks.items():
        if port in ports:
            return risk
    return 'unknown'

def scan_ports(ip, conn):
    print(f"Scanning ports for IP: {ip}")
    output = subprocess.run(
        ["sudo", "nmap", "-p", "1-1024", ip],
        capture_output=True,
        text=True,
    )

    if output.returncode == 0:
        decoded_output = output.stdout
        print("\nPort Scan Results:\n")
        lines = decoded_output.splitlines()
        skip_line = False
        for line in lines:
            # Ignorar as linhas de cabeçalho do Nmap
            if line.startswith("Starting Nmap"):
                skip_line = True
                continue
            if skip_line and line.startswith("PORT"):
                skip_line = False
            if skip_line:
                continue

            if line.strip() and '/' in line:
                try:
                    port = int(line.split("/")[0].strip())
                    risk = classify_port(port)
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO port_records (ip, port, risk_level) VALUES (?, ?, ?)", (ip, port, risk))
                    conn.commit()
                    print(f"  Port {port} - Risk: {risk}")
                except ValueError as ve:
                    print(f"Skipping line due to parsing error: {line} - {ve}")
    else:
        print(f"Error scanning ports for {ip}")

def scanNetwork(network_range, conn):
    print("\n==============================================================")
    print(f"\nScanning network: {network_range}")
    
    output = subprocess.run(
        ["nmap", "-F", "-oX", "/tmp/scanlog.xml", network_range],
        capture_output=True,
        timeout=120  # Timeout de 120 segundos
    )
    
    if output.returncode == 0:
        tree = etxml.parse("/tmp/scanlog.xml")
        root = tree.getroot()
        scanned_ips = set()
        for host in root.findall("host"):
            ip = mac = vendor = "Unknown"
            for elem in host:
                if elem.tag == "address":
                    if elem.attrib["addrtype"] == "ipv4":
                        ip = elem.attrib["addr"]
                    elif elem.attrib["addrtype"] == "mac":
                        mac = elem.attrib["addr"]
                        vendor = elem.attrib.get("vendor", "Unknown")

            if ip != "Unknown" and mac != "Unknown" and ip not in scanned_ips:
                scanned_ips.add(ip)  # Marcar IP como escaneado
                print(f"\nDetected device - IP: {ip}, MAC: {mac}, Vendor: {vendor}")
                isner_Scan_Record(conn, ip, mac, vendor, time.strftime('%d-%m-%Y %H:%M:%S'))
                scan_data = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "timestamp": time.strftime('%d-%m-%Y %H:%M:%S')
                }
                save_Json_Log(scan_data)
                
                scan_ports(ip, conn)

def hexit(signal, frame):
    print("\nStopping network scan. Exiting...")
    sys.exit(0)

def main():
    if len(sys.argv) != 3:
        print("\nUsage: sudo python3 detect.py <network_range> <database_path>\n")
        print("Example:")
        print("  sudo python3 detect.py 123.456.78.9/00 meinedatenbank.db\n")
        sys.exit(1)

    network_range = sys.argv[1]
    db_name = sys.argv[2]
    
    db_path = os.path.join("../databases", db_name)
    conn = init_Db(db_path)

    signal.signal(signal.SIGINT, hexit)
    
    try:
        while True:
            scanNetwork(network_range, conn)
            time.sleep(6)

    except Exception as e:
        print(f"\nError: {e}")
    finally:
        print("\nSaving data to the database")
        conn.close()

if __name__ == "__main__":
    main()