import tkinter as tk
from tkinter import filedialog, messagebox
import requests
import csv
import concurrent.futures

def get_ip_info(ip, token):
    base_url = "https://ipinfo.io/"
    try:
        response = requests.get(f"{base_url}{ip}?token={token}")
        data = response.json()
        
        isp_info = {
            'ip': data.get('ip', ''),
            'hostname': data.get('hostname', ''),
            'city': data.get('city', ''),
            'region': data.get('region', ''),
            'country': data.get('country', ''),
            'loc': data.get('loc', ''),
            'org': data.get('org', ''),
            'postal': data.get('postal', ''),
            'timezone': data.get('timezone', ''),
            'asn': data.get('asn', {}).get('asn', ''),
            'asn_name': data.get('asn', {}).get('name', ''),
            'asn_domain': data.get('asn', {}).get('domain', ''),
            'asn_route': data.get('asn', {}).get('route', ''),
            'asn_type': data.get('asn', {}).get('type', ''),
            'company_name': data.get('company', {}).get('name', ''),
            'company_domain': data.get('company', {}).get('domain', ''),
            'company_type': data.get('company', {}).get('type', ''),
            'privacy_vpn': data.get('privacy', {}).get('vpn', False),
            'privacy_proxy': data.get('privacy', {}).get('proxy', False),
            'privacy_tor': data.get('privacy', {}).get('tor', False),
            'privacy_relay': data.get('privacy', {}).get('relay', False),
            'privacy_hosting': data.get('privacy', {}).get('hosting', False),
            'privacy_service': data.get('privacy', {}).get('service', ''),
            'abuse_address': data.get('abuse', {}).get('address', ''),
            'abuse_country': data.get('abuse', {}).get('country', ''),
            'abuse_email': data.get('abuse', {}).get('email', ''),
            'abuse_name': data.get('abuse', {}).get('name', ''),
            'abuse_network': data.get('abuse', {}).get('network', ''),
            'abuse_phone': data.get('abuse', {}).get('phone', '')
        }
        return isp_info
    except Exception as e:
        print(f"Error retrieving information for IP {ip}: {e}")
        return {'ip': ip, 'error': str(e)}

def write_ip_details_to_csv(ip_details, output_file_path, mode='w', write_header=True):
    with open(output_file_path, mode, newline='') as csvfile:
        fieldnames = [
            'ip', 'hostname', 'city', 'region', 'country', 'loc', 'org', 'postal', 'timezone',
            'asn', 'asn_name', 'asn_domain', 'asn_route', 'asn_type',
            'company_name', 'company_domain', 'company_type',
            'privacy_vpn', 'privacy_proxy', 'privacy_tor', 'privacy_relay', 'privacy_hosting', 'privacy_service',
            'abuse_address', 'abuse_country', 'abuse_email', 'abuse_name', 'abuse_network', 'abuse_phone'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        for detail in ip_details:
            writer.writerow(detail)

def fetch_ip_details_concurrently(ip_addresses, token, output_file_path, max_workers=10):
    total_ips = len(ip_addresses)
    chunk_size = max(1, total_ips // 20)  # 5% of total IPs

    print(f"Total number of IPs to process: {total_ips}")
    print(f"Processing in chunks of: {chunk_size} IPs (5% of total)")

    details = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(get_ip_info, ip, token): ip for ip in ip_addresses}
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                data = future.result()
                details.append(data)
                completed += 1
                if completed % chunk_size == 0 or completed == total_ips:
                    write_ip_details_to_csv(details, output_file_path, mode='a', write_header=(completed <= chunk_size))
                    details = []  # Reset details after writing
                    print(f"Processed {completed} / {total_ips} IP addresses.")
            except Exception as e:
                print(f"Error processing IP {ip}: {e}")
                details.append({'ip': ip, 'error': str(e)})

    messagebox.showinfo("Information", f"IP details have been written to {output_file_path}")

def start_processing():
    token = token_entry.get()
    ip_addresses = ip_text.get("1.0", tk.END).strip().split('\n')
    
    if not token or not ip_addresses:
        messagebox.showerror("Error", "Please provide both IPinfo token and IP addresses.")
        return
    
    output_file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    if not output_file_path:
        return
    
    fetch_ip_details_concurrently(ip_addresses, token, output_file_path)

# Tkinter GUI setup
root = tk.Tk()
root.title("IpRecon by racerop")
root.geometry("600x500")
root.configure(bg="#2c3e50")

title_label = tk.Label(root, text="IpRecon by RacerOP", font=("Helvetica", 18, "bold"), bg="#2c3e50", fg="#ecf0f1")
title_label.pack(pady=20)

frame = tk.Frame(root, bg="#34495e")
frame.pack(pady=10, padx=20, fill="x")

tk.Label(frame, text="IPinfo Token:", font=("Helvetica", 12), bg="#34495e", fg="#ecf0f1").grid(row=0, column=0, padx=10, pady=10, sticky="e")
token_entry = tk.Entry(frame, width=50)
token_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(frame, text="IP Addresses (one per line):", font=("Helvetica", 12), bg="#34495e", fg="#ecf0f1").grid(row=1, column=0, padx=10, pady=10, sticky="ne")
ip_text = tk.Text(frame, width=50, height=15)
ip_text.grid(row=1, column=1, padx=10, pady=10)

process_button = tk.Button(root, text="Start Processing", command=start_processing, bg="#e74c3c", fg="#ecf0f1", font=("Helvetica", 12))
process_button.pack(pady=20)

root.mainloop()
