from scapy.all import *
from tqdm import tqdm
import time
import os


command = "figlet -f Poison TCP PORT SCANNER -c "
# Execute the command
result = os.system(command)
print(r"---------------------------------------------------------------------------")
print(r"                        By Rahul Saravanan and Rahul R")
print(r"---------------------------------------------------------------------------")



def scan_ports(host, ports):
    open_ports = []
    with tqdm(total=len(ports), desc="Scanning ports", unit="port") as pbar:
        for port in ports:
            response = sr1(IP(dst=host)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
            if response:
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                    open_ports.append(port)
            pbar.update(1)
    return open_ports
    
    

try:
    host = input("Enter the host address: ")
    print(r"---------------------------------------------------------------------------")
    option = input("1. Check a range of ports\n2. Specify ports to check\n\nEnter your choice (1 or 2): ")
    if option == "1":
        start_port = int(input("Enter the starting port number: "))
        end_port = int(input("Enter the ending port number: "))
        ports = range(start_port, end_port + 1)  # Scanning specified range of ports
        print("Loading...")
        open_ports = scan_ports(host, ports)
        if open_ports:
            print("Open ports:")
            for port in open_ports:
                print(f"Port {port} is open")
        else:
            print("No open ports found in the specified range.")
            


    elif option == "2":
        p = input("Enter the ports to scan (comma separated): ")
        ports = list(map(int, p.split(",")))
        for port in ports:
            print(r"---------------------------------------------------------------------------")
            print(f"Scanning port {port}")
            response = sr1(IP(dst=host)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
            if response:
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                    print(f"Port {port} is open")
                else:
                    print(f"Port {port} is closed")
            else:
                print(f"Port {port} is closed")
    else:
        print("Invalid option selected. Exiting...")
        exit()

except KeyboardInterrupt:
    print("\n\nScanning interrupted by user.")
except Exception as e:
    print(f"An error occurred: {e}")
