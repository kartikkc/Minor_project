# # import usb.core
# # import usb.util
# # import os
# # import datetime

# # def detect_usb_devices():
# #     devices = usb.core.find(find_all=True)
# #     return [dev for dev in devices]

# # def get_device_info(device):
# #     return {
# #         "Vendor ID": hex(device.idVendor),
# #         "Product ID": hex(device.idProduct),
# #         "Manufacturer": usb.util.get_string(device, device.iManufacturer),
# #         "Product": usb.util.get_string(device, device.iProduct),
# #         "Serial Number": usb.util.get_string(device, device.iSerialNumber)
# #     }

# # def log_usb_event(device_info):
# #     timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
# #     log_entry = f"{timestamp} - USB device connected: {device_info}\n"
    
# #     with open("usb_events.log", "a") as log_file:
# #         log_file.write(log_entry)

# # def main():
# #     print("USB Forensics Tool")
# #     print("Monitoring for USB devices...")

# #     while True:
# #         devices = detect_usb_devices()
# #         for device in devices:
# #             info = get_device_info(device)
# #             log_usb_event(info)
# #             print(f"New USB device detected: {info}")

# # if __name__ == "__main__":
# #     main()

# import usb.core
# import usb.util
# import usb.backend.libusb1
# import os
# import datetime
# import sys

# # For Windows, specify the backend explicitly
# if sys.platform.startswith('win'):
#     backend = usb.backend.libusb1.get_backend(find_library=lambda x: "libusb-1.0.dll")
# # elif sys.platform.startswith()
# else:
#     backend = None

# def detect_usb_devices():
#     devices = usb.core.find(find_all=True, backend=backend)
#     return [dev for dev in devices]

# def get_device_info(device):
#     try:
#         manufacturer = usb.util.get_string(device, device.iManufacturer) if device.iManufacturer else "N/A"
#         product = usb.util.get_string(device, device.iProduct) if device.iProduct else "N/A"
#         serial_number = usb.util.get_string(device, device.iSerialNumber) if device.iSerialNumber else "N/A"
        
#         return {
#             "Vendor ID": hex(device.idVendor),
#             "Product ID": hex(device.idProduct),
#             "Manufacturer": manufacturer,
#             "Product": product,
#             "Serial Number": serial_number
#         }
#     except usb.core.USBError as e:
#         return {
#             "Vendor ID": hex(device.idVendor),
#             "Product ID": hex(device.idProduct),
#             "Error": str(e)
#         }


# def log_usb_event(device_info):
#     timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     log_entry = f"{timestamp} - USB device connected: {device_info}\n"
    
#     with open("usb_events.log", "a") as log_file:
#         log_file.write(log_entry)

# def main():
#     print("USB Forensics Tool")
#     print("Monitoring for USB devices...")

#     while True:
#         try:
#             devices = detect_usb_devices()
#             for device in devices:
#                 info = get_device_info(device)
#                 log_usb_event(info)
#                 print(f"USB device detected: {info}")
#         except usb.core.NoBackendError:
#             print("Error: No USB backend available. Make sure libusb is installed and accessible.")
#             break
#         except Exception as e:
#             print(f"An error occurred: {e}")
        
#         # Add a delay to avoid continuous polling
#         # print(usb.backend.libusb1.get_backend())
#         import time
#         time.sleep(10)

# if __name__ == "__main__":
#     main()



# import usb.core
# import usb.util

# def detect_usb_devices():
#     devices = usb.core.find(find_all=True)
    
#     for device in devices:
#         print(f"Device ID: {device.idVendor:04x}:{device.idProduct:04x}")
#         print(f"Manufacturer: {usb.util.get_string(device, device.iManufacturer)}")
#         print(f"Product: {usb.util.get_string(device, device.iProduct)}")
#         print(f"Serial Number: {usb.util.get_string(device, device.iSerialNumber)}")
#         print("---")

# if __name__ == "__main__":
#     detect_usb_devices()



import usb.core
import usb.util
import usb.backend.libusb1
import os
import datetime
import sys
import time

# For Windows, specify the backend explicitly
if sys.platform.startswith('win'):
    backend = usb.backend.libusb1.get_backend(find_library=lambda x: "libusb-1.0.dll")
else:
    backend = None

def is_storage_device(device):
    # Check if the device is a USB Mass Storage device
    # USB Mass Storage devices typically have class code 8
    if device.bDeviceClass == 8:
        return True
    
    # Some devices may have class code 0 and define the class in an interface
    for cfg in device:
        for intf in cfg:
            if intf.bInterfaceClass == 8:
                return True
    return False

def detect_usb_storage_devices():
    devices = usb.core.find(find_all=True, backend=backend)
    return [dev for dev in devices if is_storage_device(dev)]

def get_device_info(device):
    try:
        manufacturer = usb.util.get_string(device, device.iManufacturer) if device.iManufacturer else "N/A"
        product = usb.util.get_string(device, device.iProduct) if device.iProduct else "N/A"
        serial_number = usb.util.get_string(device, device.iSerialNumber) if device.iSerialNumber else "N/A"
        
        return {
            "Vendor ID": hex(device.idVendor),
            "Product ID": hex(device.idProduct),
            "Manufacturer": manufacturer,
            "Product": product,
            "Serial Number": serial_number
        }
    except usb.core.USBError as e:
        return {
            "Vendor ID": hex(device.idVendor),
            "Product ID": hex(device.idProduct),
            "Error": str(e)
        }

def log_usb_event(device_info):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - USB storage device connected: {device_info}\n"
    
    with open("usb_storage_events.log", "a") as log_file:
        log_file.write(log_entry)

def main():
    print("USB Storage Device Forensics Tool")
    print("Monitoring for USB storage devices...")

    known_devices = set()

    while True:
        try:
            devices = detect_usb_storage_devices()
            current_devices = set(dev.serial_number for dev in devices if dev.serial_number)
            
            # Check for new devices
            new_devices = current_devices - known_devices
            for device in devices:
                if device.serial_number in new_devices:
                    info = get_device_info(device)
                    log_usb_event(info)
                    print(f"New USB storage device detected: {info}")
            
            # Update known devices
            known_devices = current_devices

        except usb.core.NoBackendError:
            print("Error: No USB backend available. Make sure libusb is installed and accessible.")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
        
        time.sleep(1)

if __name__ == "__main__":
    main()


# import tkinter as tk
# from tkinter import ttk, messagebox, filedialog
# import os
# import hashlib
# import json
# import requests
# import threading
# from datetime import datetime
# import csv

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
#             drives = ["/media/" + x for x in os.listdir("/media/kartik")]
        
#         self.drive_combo['values'] = drives
#         if drives:
#             self.drive_combo.set(drives[0])
    
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