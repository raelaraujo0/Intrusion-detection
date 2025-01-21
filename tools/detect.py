import sys
import time
import subprocess
import xml.etree.ElementTree as etxml
import signal
from dbmanager import init_Db, isner_Scan_Record
from writelogjson import save_Json_Log
import os

def scan_ports(ip):
    print(f"Scanning ports for IP: {ip}")
    output = subprocess.run(
        ["sudo", "nmap", "-p", "1-1024", ip],
        #-p: range p as portas

        capture_output = True
    )
    
    if output.returncode == 0:
        decoded_output = output.stdout.decode()
        print("\nPort Scan Results:\n")
        lines = decoded_output.splitlines()
        for line in lines:
            if line.startswith("PORT"):
                print(f"{line}")
            elif line.strip():
                print(f"  {line.strip()}")
    else:
        print(f"Error scanning ports for {ip}")

def scanNetwork(network_range, conn):
    print("\n==============================================================")
    print(f"\nScanning network: {network_range}")
    
    output = subprocess.run(
        ["nmap", "-v", "-sS", network_range, "-oX", "/tmp/scanlog.xml"],
        #-V:verbose
        capture_output=True
    ) #executa o nmap p varrer a rede e salvar em XML
    
    if output.returncode == 0:
        tree = etxml.parse("/tmp/scanlog.xml")
        root = tree.getroot()
        for host in root.findall("host"):
            ip = mac = vendor = "Unknown"
            for elem in host:
                if elem.tag == "address":
                    if elem.attrib["addrtype"] == "ipv4":
                        ip = elem.attrib["addr"]
                    elif elem.attrib["addrtype"] == "mac":
                        mac = elem.attrib["addr"]
                        vendor = elem.attrib.get("vendor", "Unknown")
        #EXTRACAO
            
            if ip != "Unknown" and mac != "Unknown":
                print(f"\nDetected device - IP: {ip}, MAC: {mac}, Vendor: {vendor}")
                isner_Scan_Record(conn, ip, mac, vendor, time.strftime('%d-%m-%Y %H:%M:%S'))
                scan_data = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "timestamp": time.strftime('%d-%m-%Y %H:%M:%S')
                }
                save_Json_Log(scan_data)
                
                scan_ports(ip)
                
                
def hexit(signal, frame):
    print("\nStopping network scan. Exiting...")
    sys.exit(0)
    #interrupcao

def main():
    if len(sys.argv) != 3:
        print("\nUsage: sudo python3 detect.py <network_range> <database_path>\n")
        print("Example:")
        print("  sudo python3 detect.py 123.456.78.9/00 meinedatenbank.db\n")
        sys.exit(1)
        #ajudinha

    network_range = sys.argv[1]
    db_name = sys.argv[2]
    
    db_path = os.path.join("../databases", db_name)
    conn = init_Db(db_path)
    #pega os argumentos do comando e inicializa conexao com db

    signal.signal(signal.SIGINT, hexit)
    
    try:
        while True:
            scanNetwork(network_range, conn)
            time.sleep(1)

    except Exception as e:
        print(f"\nError: {e}")
    finally:
        print("\nSaving data to the database")
        conn.close()

if __name__ == "__main__":
    main()