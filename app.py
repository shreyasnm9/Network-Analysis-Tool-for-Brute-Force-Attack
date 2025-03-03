import socket
import threading
from scapy.all import sniff, IP, TCP, UDP, conf
import tkinter as tk
from tkinter import scrolledtext, messagebox
from collections import defaultdict
from time import time
import smtplib
from email.mime.text import MIMEText

# Get the device IP address
def get_device_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# Get the loopback interface for packet sniffing
def get_loopback_interface():
    for iface in conf.ifaces.values():
        if "loopback" in iface.name.lower():
            return iface.name
    return None

# The target port for sniffing
target_ip = get_device_ip()
target_port = 5000

# Store detailed information for each packet
packet_details = {}
# Tracking packet counts and timestamps for DDoS and brute force detection
login_attempts = defaultdict(lambda: {'failed_count': 0, 'first_fail_time': 0, 'payloads': []})

# Thresholds for detection
BRUTE_FORCE_THRESHOLD = 5  # Number of failed attempts from the same IP in a short time
TIME_WINDOW = 10  # Time window in seconds (set to 10 seconds)


# Function to send email notifications
def send_notification_email(src_ip):
    sender_email = "changea86@gmail.com"  # Replace with your email
    receiver_email = "shreyas9201@gmail.com"  # Replace with the admin's email
    subject = "Brute Force Attack Detected"
    body = f"A brute force attack has been detected from IP: {src_ip}. Please take action."

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:  # Replace with your SMTP server
            server.starttls()
            server.login(sender_email, "dagm nryr swmo upwh")  # Replace with your email password
            server.sendmail(sender_email, receiver_email, msg.as_string())
        print("Notification email sent successfully.")
    except Exception as e:
        print(f"Failed to send notification email: {str(e)}")

# Function to update the text widget in Tkinter
def update_text_box(pkt_info, detailed=False, flagged=False, payload_info=None):
    if detailed:
        detailed_text_box.config(state=tk.NORMAL)
        detailed_text_box.delete(1.0, tk.END)
        detailed_text_box.insert(tk.END, pkt_info + "\n")
        if payload_info:
            detailed_text_box.insert(tk.END, "\nPayload: " + payload_info + "\n")
        detailed_text_box.config(state=tk.DISABLED)
    elif flagged:
        flagged_text_box.config(state=tk.NORMAL)
        flagged_text_box.insert(tk.END, pkt_info + "\n")
        flagged_text_box.config(state=tk.DISABLED)
    else:
        text_box.config(state=tk.NORMAL)
        text_box.insert(tk.END, pkt_info + "\n")
        text_box.config(state=tk.DISABLED)

# Decode payload if possible
def decode_payload(payload):
    try:
        return payload.decode('utf-8')
    except UnicodeDecodeError:
        return "[Non-UTF-8 or Binary Data]"

# Simulate login attempt check (to be replaced with real login logic)
def is_login_failed(payload):
    return "multiple failed" in payload.lower() or "invalid" in payload.lower() or "login unsuccessful" in payload.lower()

# Packet capture callback function
def packet_callback(pkt):
    if IP in pkt and (TCP in pkt or UDP in pkt):
        src_ip = pkt[IP].src
        src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
        
        if src_port == target_port or dst_port == target_port:
            protocol = 'TCP' if TCP in pkt else 'UDP'
            pkt_info = f"Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port} ({protocol})"
            detailed_info = f"Source: {src_ip}:{src_port}\n"
            detailed_info += f"Destination: {dst_ip}:{dst_port}\n"
            detailed_info += f"Protocol: {protocol}\n"
            detailed_info += "Payload:\n"
            
            if pkt.payload:
                payload = bytes(pkt[TCP].payload if TCP in pkt else pkt[UDP].payload)
                decoded_payload = decode_payload(payload)
                detailed_info += f"{decoded_payload}\n"
            else:
                detailed_info += "No payload\n"
            
            packet_details[pkt_info] = (detailed_info, decoded_payload)
            current_time = time()

            # Detect failed login attempts
            if is_login_failed(decoded_payload):
                login_attempts[src_ip]['payloads'].append(decoded_payload)
                if login_attempts[src_ip]['failed_count'] == 0:
                    login_attempts[src_ip]['first_fail_time'] = current_time
                login_attempts[src_ip]['failed_count'] += 1

                time_diff = current_time - login_attempts[src_ip]['first_fail_time']
                if login_attempts[src_ip]['failed_count'] >= BRUTE_FORCE_THRESHOLD and time_diff <= TIME_WINDOW:
                    update_text_box(f"Flagged: Possible brute force from {src_ip}", flagged=True)
                    send_notification_email(src_ip)  # Send notification email immediately
                elif time_diff > TIME_WINDOW:
                    login_attempts[src_ip]['failed_count'] = 1
                    login_attempts[src_ip]['first_fail_time'] = current_time
                    login_attempts[src_ip]['payloads'] = [decoded_payload]

            update_text_box(pkt_info, detailed=False)
            flagged_text_box.bind("<Button-1>", on_textbox_click)
            text_box.bind("<Button-1>", on_textbox_click)

# Function to handle click events on both text boxes
def on_textbox_click(event):
    try:
        widget = event.widget
        index = widget.index("@%s,%s" % (event.x, event.y))
        line = widget.get(f"{index} linestart", f"{index} lineend").strip()
        if line in packet_details:
            detailed_info, payload = packet_details[line]
            update_text_box(detailed_info, detailed=True, payload_info=payload)
    except tk.TclError:
        pass

# Function to start the packet sniffing
def start_sniffing():
    loopback_iface = get_loopback_interface()
    if loopback_iface:
        update_text_box(f"Starting capture for http://{target_ip}:{target_port} on interface: {loopback_iface}")
        sniff(iface=loopback_iface, filter=f"port {target_port}", prn=packet_callback, store=0)
    else:
        update_text_box("Loopback interface not found. Capturing on all interfaces.")
        sniff(filter=f"port {target_port}", prn=packet_callback, store=0)

# Function to run sniffing in a separate thread
def start_sniffing_thread():
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True  # Daemon thread will exit when the main program exits
    sniff_thread.start()

# Tkinter GUI setup
root = tk.Tk()
root.title("Network Traffic Capture")

# Create a frame to hold the three ScrolledText widgets
frame = tk.Frame(root)
frame.pack(pady=10)

# Create a ScrolledText widget for displaying captured packets (top half)
text_box = scrolledtext.ScrolledText(frame, height=10, width=120, state=tk.DISABLED, cursor="arrow")
text_box.grid(row=0, column=0, columnspan=2, padx=5, pady=5)

# Create a ScrolledText widget for displaying flagged network traffic (bottom left)
flagged_text_box = scrolledtext.ScrolledText(frame, height=10, width=60, state=tk.DISABLED, cursor="arrow")
flagged_text_box.grid(row=1, column=0, padx=5, pady=5)

# Create a ScrolledText widget for displaying detailed packet information (bottom right)
detailed_text_box = scrolledtext.ScrolledText(frame, height=10, width=60, state=tk.DISABLED, cursor="arrow")
detailed_text_box.grid(row=1, column=1, padx=5, pady=5)

# Create a Start Capture button
start_button = tk.Button(root, text="Start Capture", command=start_sniffing_thread)
start_button.pack(pady=10)

# Run the Tkinter loop
root.mainloop()
