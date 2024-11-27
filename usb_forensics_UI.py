import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import hashlib
import json
import requests
import threading
from datetime import datetime
import csv
import subprocess
import re
import time
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self, requests_per_minute):
        self.requests_per_minute = requests_per_minute
        self.requests = []
    
    def wait_if_needed(self):
        """Check if we need to wait before making another request"""
        now = datetime.now()
        
        # Remove requests older than 1 minute
        self.requests = [req_time for req_time in self.requests 
                        if now - req_time < timedelta(minutes=1)]
        
        # If we've made too many requests in the last minute, wait
        if len(self.requests) >= self.requests_per_minute:
            # Calculate how long to wait
            oldest_request = min(self.requests)
            wait_time = 61 - (now - oldest_request).seconds  # 61 to be safe
            if wait_time > 0:
                return wait_time
        return 0

    def add_request(self):
        """Record a new request"""
        self.requests.append(datetime.now())

class USBForensicsTool:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Forensics Tool")
        self.root.geometry("800x600")
        
        # VirusTotal API Key (replace with your actual API key)
        self.api_key = "46b646ae16a3e6de224ad2b54ea6585a118d2904e26a41df9f8260f140c95f47"
        
        # Add control flags for analysis
        self.analysis_running = False
        self.stop_analysis = False
        self.analysis_thread = None
        
        # Add rate limiter
        self.vt_rate_limiter = RateLimiter(requests_per_minute=4)
        
        # Add status for waiting
        self.status_var = tk.StringVar(value="Ready")
        
        self.setup_gui()
        
    def setup_gui(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # USB Drive Selection
        ttk.Label(main_frame, text="Select USB Drive:").grid(row=0, column=0, sticky=tk.W)
        self.drive_var = tk.StringVar()
        self.drive_combo = ttk.Combobox(main_frame, textvariable=self.drive_var)
        self.drive_combo.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        # Refresh Drive List Button
        ttk.Button(main_frame, text="Refresh Drives", command=self.refresh_drives).grid(row=0, column=2)
        
        # Control Buttons Frame
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=1, column=0, columnspan=3, pady=10)
        
        # Start Analysis Button
        self.start_button = ttk.Button(control_frame, text="Start Analysis", command=self.start_analysis)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        # Stop Analysis Button
        self.stop_button = ttk.Button(control_frame, text="Stop Analysis", command=self.stop_analysis_handler, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Progress Bar and Status
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, length=300, mode='determinate', variable=self.progress_var)
        self.progress_bar.grid(row=2, column=0, columnspan=3, pady=10)
        
        # Status Label
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var)
        self.status_label.grid(row=3, column=0, columnspan=3)
        
        # Results Tree
        self.tree = ttk.Treeview(main_frame, columns=('File', 'Size', 'Hash', 'VT Status'), show='headings')
        self.tree.heading('File', text='File')
        self.tree.heading('Size', text='Size')
        self.tree.heading('Hash', text='SHA-256')
        self.tree.heading('VT Status', text='VirusTotal Status')
        self.tree.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Export Button
        ttk.Button(main_frame, text="Export Results", command=self.export_results).grid(row=5, column=0, columnspan=3, pady=10)
        
        # Initialize drives list
        self.refresh_drives()
    
    def get_linux_usb_drives(self):
        """Get list of USB drives on Linux using multiple detection methods"""
        drives = set()
        
        # Method 1: Using lsblk command
        try:
            output = subprocess.check_output(['lsblk', '-Pno', 'NAME,MOUNTPOINT,TRAN'], universal_newlines=True)
            for line in output.split('\n'):
                if 'usb' in line.lower():
                    mount = re.search(r'MOUNTPOINT="([^"]+)"', line)
                    if mount and mount.group(1) != '':
                        drives.add(mount.group(1))
        except subprocess.CalledProcessError:
            pass

        # Method 2: Check common mount points
        mount_points = [
            '/media',
            '/mnt',
            f'/run/media/{os.getenv("USER")}',
            f'/media/{os.getenv("USER")}'
        ]
        
        for mount_point in mount_points:
            if os.path.exists(mount_point):
                for item in os.listdir(mount_point):
                    full_path = os.path.join(mount_point, item)
                    if os.path.ismount(full_path):
                        drives.add(full_path)

        # Method 3: Using mount command
        try:
            output = subprocess.check_output(['mount'], universal_newlines=True)
            for line in output.split('\n'):
                if any(fs_type in line for fs_type in ['vfat', 'ntfs', 'exfat']):
                    mount_point = line.split(' on ')[-1].split(' ')[0]
                    if os.path.exists(mount_point):
                        drives.add(mount_point)
        except subprocess.CalledProcessError:
            pass

        # Method 4: Using /proc/mounts
        try:
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    if any(fs_type in line for fs_type in ['vfat', 'ntfs', 'exfat']):
                        mount_point = line.split()[1]
                        if os.path.exists(mount_point):
                            drives.add(mount_point)
        except Exception:
            pass

        return list(drives)

    def refresh_drives(self):
        """Refresh the list of available drives"""
        drives = []
        
        if os.name == 'nt':  # Windows
            from ctypes import windll
            bitmask = windll.kernel32.GetLogicalDrives()
            for letter in range(65, 91):  # A-Z
                if bitmask & (1 << (letter - 65)):
                    drives.append(chr(letter) + ":\\")
        else:  # Linux/Unix
            drives = self.get_linux_usb_drives()
            
            # Add error logging
            if not drives:
                print("Debug: No drives found")
                print(f"Current user: {os.getenv('USER')}")
                try:
                    print("Mount points content:")
                    subprocess.run(['mount'], check=True)
                    print("\nlsblk output:")
                    subprocess.run(['lsblk'], check=True)
                except Exception as e:
                    print(f"Debug error: {str(e)}")

        # Populate combobox with detected drives
        self.drive_combo['values'] = drives
        if drives:
            self.drive_combo.set(drives[0])
            print(f"Found drives: {drives}")  # Debug output
        else:
            messagebox.showwarning("Warning", "No mounted drives found. Please ensure a USB drive is properly connected and mounted.")
            print("No drives found in final check")  # Debug output

    def start_analysis(self):
        """Start the analysis in a separate thread"""
        if not self.analysis_running:
            self.analysis_running = True
            self.stop_analysis = False
            self.progress_var.set(0)
            self.start_button.configure(state=tk.DISABLED)
            self.stop_button.configure(state=tk.NORMAL)
            self.status_var.set("Analysis in progress...")
            self.analysis_thread = threading.Thread(target=self.analyze_drive, daemon=True)
            self.analysis_thread.start()

    def stop_analysis_handler(self):
        """Handle the stop analysis button click"""
        if self.analysis_running:
            self.stop_analysis = True
            self.status_var.set("Stopping analysis...")
            self.stop_button.configure(state=tk.DISABLED)


    def analyze_drive(self):
        """Analyze the selected drive"""
        try:
            drive_path = self.drive_var.get()
            if not os.path.exists(drive_path):
                messagebox.showerror("Error", "Selected drive not found")
                self.reset_analysis_state()
                return
            
            # Clear existing results
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Count total files
            total_files = 0
            for _, _, files in os.walk(drive_path):
                if self.stop_analysis:
                    break
                total_files += len(files)
            
            if self.stop_analysis:
                self.reset_analysis_state()
                return
            
            processed_files = 0
            
            for root, _, files in os.walk(drive_path):
                if self.stop_analysis:
                    break
                    
                for file in files:
                    if self.stop_analysis:
                        break
                        
                    filepath = os.path.join(root, file)
                    try:
                        # Update status
                        self.status_var.set(f"Processing: {file}")
                        
                        # Calculate file size and hash
                        file_size = os.path.getsize(filepath)
                        file_hash = self.calculate_file_hash(filepath)
                        
                        if self.stop_analysis:
                            break
                        
                        # Check VirusTotal with rate limiting
                        vt_status = self.check_virustotal(file_hash)
                        
                        # Add to results
                        self.tree.insert('', 'end', values=(
                            filepath,
                            f"{file_size:,} bytes",
                            file_hash,
                            vt_status
                        ))
                        
                        # Update progress
                        processed_files += 1
                        self.progress_var.set((processed_files / total_files) * 100)
                        self.root.update_idletasks()
                        
                    except Exception as e:
                        print(f"Error processing {filepath}: {str(e)}")
                        
            if self.stop_analysis:
                self.status_var.set("Analysis stopped by user")
            else:
                self.status_var.set("Analysis completed!")
                messagebox.showinfo("Complete", "Drive analysis completed!")
                
        finally:
            self.reset_analysis_state()
            
    def reset_analysis_state(self):
        """Reset the analysis state after completion or stopping"""
        self.analysis_running = False
        self.stop_analysis = False
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        self.progress_var.set(0)

    def calculate_file_hash(self, filepath):
        """Calculate the SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

   
    def check_virustotal(self, file_hash):
        """Check file hash against VirusTotal database"""
        if not self.api_key:
            return "No API key configured"

        wait_time = self.vt_rate_limiter.wait_if_needed()
        if wait_time > 0:
            self.status_var.set(f"Rate limit reached. Waiting {wait_time} seconds...")
            self.root.update_idletasks()
            time.sleep(wait_time)
            self.status_var.set("Resuming analysis...")
            
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            'apikey': self.api_key,
            'resource': file_hash
        }   
       
        try:
            # Add headers and timeout for better reliability
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }

            # Record this request
            self.vt_rate_limiter.add_request()
            response = requests.get(url, params=params, headers=headers, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if data.get('response_code') == 1:
                        positives = data.get('positives', 0)
                        total = data.get('total', 0)
                        return f"{positives}/{total} detections" if positives > 0 else "No detections"
                    elif data.get('response_code') == 0:
                        return "File not found in VT database"
                    else:
                        return f"Unknown response code: {data.get('response_code')}"
                except json.JSONDecodeError as e:
                    print(f"JSON parsing error: {str(e)}\nResponse content: {response.text}")
                    return "Invalid API response"
            elif response.status_code == 204:
                print("Rate limit exceeded despite waiting")
                return "API rate limit exceeded"
            elif response.status_code == 403:
                return "Invalid API key"
            else:
                print(f"API error: Status code {response.status_code}\nResponse: {response.text}")
                return f"API error: {response.status_code}"
                
        except requests.exceptions.Timeout:
            return "Request timed out"
        except requests.exceptions.RequestException as e:
            print(f"Request error: {str(e)}")
            return "Connection error"
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            return "Error checking VirusTotal"

    def export_results(self):
        """Export analysis results to a CSV file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['File', 'Size', 'SHA-256 Hash', 'VirusTotal Status'])
                    for row in self.tree.get_children():
                        writer.writerow(self.tree.item(row)['values'])
                messagebox.showinfo("Export Complete", f"Results exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export results: {str(e)}")

# Start the application
if __name__ == "__main__":
    root = tk.Tk()
    app = USBForensicsTool(root)
    root.mainloop()




# import tkinter as tk
# from tkinter import ttk, messagebox, filedialog
# import os
# import hashlib
# import json
# import requests
# import threading
# from datetime import datetime
# import csv
# import subprocess
# import re

# class USBForensicsTool:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("USB Forensics Tool")
#         self.root.geometry("800x600")
        
#         # VirusTotal API Key (replace with your actual API key)
#         self.api_key = "YOUR_VIRUSTOTAL_API_KEY"
        
#         self.setup_gui()
        
#     def setup_gui(self):
#         # Create main frame
#         main_frame = ttk.Frame(self.root, padding="10")
#         main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
#         # USB Drive Selection
#         ttk.Label(main_frame, text="Select USB Drive:").grid(row=0, column=0, sticky=tk.W)
#         self.drive_var = tk.StringVar()
#         self.drive_combo = ttk.Combobox(main_frame, textvariable=self.drive_var)
#         self.drive_combo.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
#         # Refresh Drive List Button
#         ttk.Button(main_frame, text="Refresh Drives", command=self.refresh_drives).grid(row=0, column=2)
        
#         # Start Analysis Button
#         ttk.Button(main_frame, text="Start Analysis", command=self.start_analysis).grid(row=1, column=0, columnspan=3, pady=10)
        
#         # Progress Bar
#         self.progress_var = tk.DoubleVar()
#         self.progress_bar = ttk.Progressbar(main_frame, length=300, mode='determinate', variable=self.progress_var)
#         self.progress_bar.grid(row=2, column=0, columnspan=3, pady=10)
        
#         # Results Tree
#         self.tree = ttk.Treeview(main_frame, columns=('File', 'Size', 'Hash', 'VT Status'), show='headings')
#         self.tree.heading('File', text='File')
#         self.tree.heading('Size', text='Size')
#         self.tree.heading('Hash', text='SHA-256')
#         self.tree.heading('VT Status', text='VirusTotal Status')
#         self.tree.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
#         # Export Button
#         ttk.Button(main_frame, text="Export Results", command=self.export_results).grid(row=4, column=0, columnspan=3, pady=10)
        
#         # Initialize drives list
#         self.refresh_drives()
    
#     def get_linux_usb_drives(self):
#         """Get list of USB drives on Linux using multiple detection methods"""
#         drives = set()
        
#         # Method 1: Using lsblk command
#         try:
#             output = subprocess.check_output(['lsblk', '-Pno', 'NAME,MOUNTPOINT,TRAN'], universal_newlines=True)
#             for line in output.split('\n'):
#                 if 'usb' in line.lower():
#                     mount = re.search(r'MOUNTPOINT="([^"]+)"', line)
#                     if mount and mount.group(1) != '':
#                         drives.add(mount.group(1))
#         except subprocess.CalledProcessError:
#             pass

#         # Method 2: Check common mount points
#         mount_points = [
#             '/media',
#             '/mnt',
#             f'/run/media/{os.getenv("USER")}',
#             f'/media/{os.getenv("USER")}'
#         ]
        
#         for mount_point in mount_points:
#             if os.path.exists(mount_point):
#                 for item in os.listdir(mount_point):
#                     full_path = os.path.join(mount_point, item)
#                     if os.path.ismount(full_path):
#                         drives.add(full_path)

#         # Method 3: Using mount command
#         try:
#             output = subprocess.check_output(['mount'], universal_newlines=True)
#             for line in output.split('\n'):
#                 if any(fs_type in line for fs_type in ['vfat', 'ntfs', 'exfat']):
#                     mount_point = line.split(' on ')[-1].split(' ')[0]
#                     if os.path.exists(mount_point):
#                         drives.add(mount_point)
#         except subprocess.CalledProcessError:
#             pass

#         # Method 4: Using /proc/mounts
#         try:
#             with open('/proc/mounts', 'r') as f:
#                 for line in f:
#                     if any(fs_type in line for fs_type in ['vfat', 'ntfs', 'exfat']):
#                         mount_point = line.split()[1]
#                         if os.path.exists(mount_point):
#                             drives.add(mount_point)
#         except Exception:
#             pass

#         return list(drives)

#     def refresh_drives(self):
#         """Refresh the list of available drives"""
#         drives = []
        
#         if os.name == 'nt':  # Windows
#             from ctypes import windll
#             bitmask = windll.kernel32.GetLogicalDrives()
#             for letter in range(65, 91):  # A-Z
#                 if bitmask & (1 << (letter - 65)):
#                     drives.append(chr(letter) + ":\\")
#         else:  # Linux/Unix
#             drives = self.get_linux_usb_drives()
            
#             # Add error logging
#             if not drives:
#                 print("Debug: No drives found")
#                 print(f"Current user: {os.getenv('USER')}")
#                 try:
#                     print("Mount points content:")
#                     subprocess.run(['mount'], check=True)
#                     print("\nlsblk output:")
#                     subprocess.run(['lsblk'], check=True)
#                 except Exception as e:
#                     print(f"Debug error: {str(e)}")

#         # Populate combobox with detected drives
#         self.drive_combo['values'] = drives
#         if drives:
#             self.drive_combo.set(drives[0])
#             print(f"Found drives: {drives}")  # Debug output
#         else:
#             messagebox.showwarning("Warning", "No mounted drives found. Please ensure a USB drive is properly connected and mounted.")
#             print("No drives found in final check")  # Debug output
    
#     def calculate_file_hash(self, filepath):
#         """Calculate SHA-256 hash of a file"""
#         sha256_hash = hashlib.sha256()
#         with open(filepath, "rb") as f:
#             for byte_block in iter(lambda: f.read(4096), b""):
#                 sha256_hash.update(byte_block)
#         return sha256_hash.hexdigest()
    
#     def check_virustotal(self, file_hash):
#         """Check file hash against VirusTotal"""
#         url = f"https://www.virustotal.com/vtapi/v2/file/report"
#         params = {
#             'apikey': self.api_key,
#             'resource': file_hash
#         }
#         try:
#             response = requests.get(url, params=params)
#             if response.status_code == 200:
#                 result = response.json()
#                 if result.get('response_code') == 1:
#                     return f"Detections: {result.get('positives')}/{result.get('total')}"
#                 return "Not found in VirusTotal"
#         except Exception as e:
#             return f"Error: {str(e)}"
#         return "Error checking VirusTotal"
    
#     def analyze_drive(self):
#         """Analyze the selected drive"""
#         drive_path = self.drive_var.get()
#         if not os.path.exists(drive_path):
#             messagebox.showerror("Error", "Selected drive not found")
#             return
        
#         # Clear existing results
#         for item in self.tree.get_children():
#             self.tree.delete(item)
        
#         total_files = sum([len(files) for _, _, files in os.walk(drive_path)])
#         processed_files = 0
        
#         for root, _, files in os.walk(drive_path):
#             for file in files:
#                 filepath = os.path.join(root, file)
#                 try:
#                     # Calculate file size and hash
#                     file_size = os.path.getsize(filepath)
#                     file_hash = self.calculate_file_hash(filepath)
                    
#                     # Check VirusTotal
#                     vt_status = self.check_virustotal(file_hash)
                    
#                     # Add to results
#                     self.tree.insert('', 'end', values=(
#                         filepath,
#                         f"{file_size:,} bytes",
#                         file_hash,
#                         vt_status
#                     ))
                    
#                     # Update progress
#                     processed_files += 1
#                     self.progress_var.set((processed_files / total_files) * 100)
#                     self.root.update_idletasks()
                    
#                 except Exception as e:
#                     print(f"Error processing {filepath}: {str(e)}")
        
#         messagebox.showinfo("Complete", "Drive analysis completed!")
    
#     def start_analysis(self):
#         """Start the analysis in a separate thread"""
#         self.progress_var.set(0)
#         threading.Thread(target=self.analyze_drive, daemon=True).start()
    
#     def export_results(self):
#         """Export results to CSV file"""
#         filename = filedialog.asksaveasfilename(
#             defaultextension=".csv",
#             filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
#         )
#         if filename:
#             with open(filename, 'w', newline='') as csvfile:
#                 writer = csv.writer(csvfile)
#                 writer.writerow(['File', 'Size', 'SHA-256', 'VirusTotal Status'])
#                 for item in self.tree.get_children():
#                     writer.writerow(self.tree.item(item)['values'])
#             messagebox.showinfo("Export Complete", "Results exported successfully!")

# if __name__ == "__main__":
#     root = tk.Tk()
#     app = USBForensicsTool(root)
#     root.mainloop()
# def analyze_drive(self):
    #     """Analyze the selected drive"""
    #     try:
    #         drive_path = self.drive_var.get()
    #         if not os.path.exists(drive_path):
    #             messagebox.showerror("Error", "Selected drive not found")
    #             self.reset_analysis_state()
    #             return
            
    #         # Clear existing results
    #         for item in self.tree.get_children():
    #             self.tree.delete(item)
            
    #         # Count total files
    #         total_files = 0
    #         for _, _, files in os.walk(drive_path):
    #             if self.stop_analysis:
    #                 break
    #             total_files += len(files)
            
    #         if self.stop_analysis:
    #             self.reset_analysis_state()
    #             return
            
    #         processed_files = 0
            
    #         for root, _, files in os.walk(drive_path):
    #             if self.stop_analysis:
    #                 break
                    
    #             for file in files:
    #                 if self.stop_analysis:
    #                     break
                        
    #                 filepath = os.path.join(root, file)
    #                 try:
    #                     # Update status
    #                     self.status_var.set(f"Processing: {file}")
                        
    #                     # Calculate file size and hash
    #                     file_size = os.path.getsize(filepath)
    #                     file_hash = self.calculate_file_hash(filepath)
                        
    #                     if self.stop_analysis:
    #                         break
                        
    #                     # Check VirusTotal
    #                     vt_status = self.check_virustotal(file_hash)
                        
    #                     # Add to results
    #                     self.tree.insert('', 'end', values=(
    #                         filepath,
    #                         f"{file_size:,} bytes",
    #                         file_hash,
    #                         vt_status
    #                     ))
                        
    #                     # Update progress
    #                     processed_files += 1
    #                     self.progress_var.set((processed_files / total_files) * 100)
    #                     self.root.update_idletasks()
                        
    #                 except Exception as e:
    #                     print(f"Error processing {filepath}: {str(e)}")
                        
    #         if self.stop_analysis:
    #             self.status_var.set("Analysis stopped by user")
    #         else:
    #             self.status_var.set("Analysis completed!")
    #             messagebox.showinfo("Complete", "Drive analysis completed!")
                
    #     finally:
    #         self.reset_analysis_state()

     # def check_virustotal(self, file_hash):
    #     """Check file hash against VirusTotal database"""
    #     url = f"https://www.virustotal.com/vtapi/v2/file/report?apikey={self.api_key}&resource={file_hash}"
    #     try:
    #         response = requests.get(url)
    #         data = response.json()
            
    #         if data['response_code'] == 1:
    #             positives = data.get('positives', 0)
    #             total = data.get('total', 0)
    #             return f"{positives}/{total} detections" if positives > 0 else "No detections"
    #         else:
    #             return "Not found"
    #     except Exception as e:
    #         print(f"VirusTotal API error: {str(e)}")
    #         return "Error"

     # url = "https://www.virustotal.com/vtapi/v2/file/report"
        # params = {
        #     'apikey': self.api_key,
        #     'resource': file_hash
        # }
        