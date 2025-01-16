import sys
import time
import subprocess
import xml.etree.ElementTree as etxml
import signal
from dbmanager import initialize_db, insert_scan_record

def scan_network(network_range, conn):
    print(f"\nScanning network: {network_range}")

    output = subprocess.run(
        ["sudo", "nmap", "-v", "-sn", network_range, "-oX", "/tmp/scanlog.xml"],
        #-V:verbose, -sn:varredura de ping

        capture_output = True
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
                print(f"Detected device - IP: {ip}, MAC: {mac}, Vendor: {vendor}")
                insert_scan_record(conn, ip, mac, vendor, time.strftime('%d-%m-%Y %H:%M:%S'))
                

def hexit(signal, frame):
    print("\n Stopping network scan. Exiting...")
    sys.exit(0)
    #interrupcao

def main():
    if len(sys.argv) != 3:
        print("\nUsage: sudo python3 detect.py <network_range> <database_path>\n")
        print("Example:")
        print("  sudo python3 detect.py 192.168.18.0/24 database.db\n")
        sys.exit(1)
        #ajudinha

    network_range = sys.argv[1]
    db_path = sys.argv[2]
    conn = initialize_db(db_path)
    #pega os argumentos do comando e inicializa conexao com db

    signal.signal(signal.SIGINT, hexit)
    
    try:
        while True:
            scan_network(network_range, conn)
            time.sleep(15)

    except Exception as e:
        print(f"\n Error: {e}")
    finally:
        print("\n Saving data to the database")
        conn.close()

if __name__ == "__main__":
    main()