import tkinter as tk
from tkinter import scrolledtext, simpledialog
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import threading

class NetworkPacketAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("AMAN Packet Sniffer")
        self.root.geometry("800x600")

        self.log = ""
        self.is_sniffing = False

        self.create_widgets()
        self.create_tags()

    def create_widgets(self):
        title_label = tk.Label(self.root, text="AMAN Packet Sniffer", font=("Helvetica", 16, "bold"), fg="darkblue")
        title_label.pack(pady=10)

        self.output_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=100, height=30, font=("Courier New", 10))
        self.output_text.pack(pady=10, padx=10)

        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        self.start_button = tk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing, bg="green", fg="white", font=("Helvetica", 12, "bold"))
        self.start_button.grid(row=0, column=0, padx=10)

        self.stop_button = tk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED, bg="red", fg="white", font=("Helvetica", 12, "bold"))
        self.stop_button.grid(row=0, column=1, padx=10)

        self.save_button = tk.Button(button_frame, text="Save Log", command=self.save_log, bg="blue", fg="white", font=("Helvetica", 12, "bold"))
        self.save_button.grid(row=0, column=2, padx=10)

        self.root.bind('<KeyPress-s>', self.save_log)

    def create_tags(self):
        self.output_text.tag_config("TCP", foreground="blue")
        self.output_text.tag_config("UDP", foreground="green")
        self.output_text.tag_config("IP", foreground="black")

    def packet_handler(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            pkt_info = ""
            tag_name = ""

            if protocol == 6 and TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                pkt_info = f"TCP Packet: {ip_src}:{src_port} --> {ip_dst}:{dst_port}\n"
                tag_name = "TCP"

            elif protocol == 17 and UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                pkt_info = f"UDP Packet: {ip_src}:{src_port} --> {ip_dst}:{dst_port}\n"
                tag_name = "UDP"

            else:
                pkt_info = f"IP Packet: {ip_src} --> {ip_dst}\n"
                tag_name = "IP"

            self.log += pkt_info
            start_index = self.output_text.index(tk.END)  # Get the start index of the inserted text
            self.output_text.insert(tk.END, pkt_info)
            end_index = self.output_text.index(tk.END)  # Get the end index of the inserted text
            self.output_text.tag_add(tag_name, start_index, end_index)  # Apply the tag to the new text
            self.output_text.see(tk.END)

    def start_sniffing(self):
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.daemon = True
        sniff_thread.start()

    def sniff_packets(self):
        sniff(filter="ip", prn=self.packet_handler, store=False, stop_filter=self.stop_sniffing_condition)

    def stop_sniffing_condition(self, packet):
        return not self.is_sniffing

    def stop_sniffing(self):
        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def save_log(self, event=None):
        filename = simpledialog.askstring("Save Log", "Enter filename to save log:")
        if filename:
            with open(filename, 'w') as file:
                file.write(self.log)
            self.output_text.insert(tk.END, f"\nLog saved to {filename}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkPacketAnalyzer(root)
    root.mainloop()
