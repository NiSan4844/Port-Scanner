import nmap
import json
from datetime import datetime

# Initialize the Nmap Port Scanner
scanner = nmap.PortScanner()

# Define the target
target = input("Enter the IP address or hostname of the target: ")

# Define the ports to scan
port_range = input("Enter the port range to scan (e.g., 1-1024): ")

# Perform a service version and OS detection scan
def scan_target(target, port_range):
    try:
        print(f"Scanning {target} on ports {port_range} for service detection...\n")
        
        # Perform the scan with service version detection and OS detection
        scanner.scan(target, port_range, arguments="-A")
        
        scan_data = {
            "target": target,
            "scan_time": str(datetime.now()),
            "scan_results": []
        }
        
        for host in scanner.all_hosts():
            host_data = {
                "ip": host,
                "hostnames": scanner[host].hostname(),
                "state": scanner[host].state(),
                "ports": []
            }

            # Port and service detection
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    port_info = {
                        "port": port,
                        "state": scanner[host][proto][port]['state'],
                        "name": scanner[host][proto][port]['name'],
                        "product": scanner[host][proto][port].get('product', ''),
                        "version": scanner[host][proto][port].get('version', ''),
                        "extra_info": scanner[host][proto][port].get('extrainfo', '')
                    }
                    host_data["ports"].append(port_info)
            
            scan_data["scan_results"].append(host_data)
        
        return scan_data

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


# Save the scan results to a JSON file
def save_scan_results_to_file(scan_data, filename="scan_results.json"):
    try:
        with open(filename, "w") as f:
            json.dump(scan_data, f, indent=4)
        print(f"\nScan results saved to {filename}")
    except Exception as e:
        print(f"An error occurred while saving the file: {e}")


# Generate a detailed report from the scan data
def generate_report(scan_data, filename="scan_report.txt"):
    try:
        with open(filename, "w") as f:
            f.write(f"Scan Report for {scan_data['target']}\n")
            f.write(f"Scan Time: {scan_data['scan_time']}\n")
            f.write("-" * 50 + "\n")
            
            for host in scan_data["scan_results"]:
                f.write(f"IP: {host['ip']}\n")
                f.write(f"Hostnames: {host['hostnames']}\n")
                f.write(f"State: {host['state']}\n")
            

                f.write("Open Ports:\n")
                for port in host["ports"]:
                    f.write(f" - Port: {port['port']}, State: {port['state']}, Service: {port['name']}, Product: {port['product']}, Version: {port['version']}, Extra Info: {port['extra_info']}\n")
                
                f.write("-" * 50 + "\n")
        
        print(f"\nDetailed report saved to {filename}")
    except Exception as e:
        print(f"An error occurred while generating the report: {e}")


# Main function to run the scan and save results
def main():
    scan_data = scan_target(target, port_range)
    
    if scan_data:
        save_scan_results_to_file(scan_data)
        generate_report(scan_data)


if __name__ == "__main__":
    main()
