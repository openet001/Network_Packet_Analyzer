# -*- coding: utf-8 -*-
from scapy.all import sniff, hexdump, conf, get_if_list, wrpcap
from scapy.arch.windows import get_windows_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import queue
import platform
import os

class PacketSniffer:
    def __init__(self, master):
        self.master = master
        self.master.title("Network Packet Analyzer")
        self.master.geometry("1100x750")
        
        # Store captured packets for export
        self.captured_packets = []
        self.filtered_packets = []
        self.filter_active = False
        
        # Create menu bar
        self.create_menu_bar()
        
        # Check for Npcap/WinPcap
        self.check_packet_capture_driver()
        
        # Packet queue for thread-safe GUI updates
        self.packet_queue = queue.Queue()
        
        # Create main frame
        self.main_frame = tk.Frame(master)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create interface selection frame
        self.interface_frame = tk.Frame(self.main_frame)
        self.interface_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(self.interface_frame, text="Network Interface:").pack(side=tk.LEFT, padx=5)
        
        # Get available network interfaces with friendly names
        self.ifaces = self.get_friendly_ifaces()
        self.selected_iface = tk.StringVar()
        
        # Create interface dropdown with friendly names
        self.iface_dropdown = ttk.Combobox(
            self.interface_frame, 
            textvariable=self.selected_iface,
            values=[f"{desc} ({name})" for name, desc in self.ifaces.items()],
            state="readonly",
            width=80
        )
        self.iface_dropdown.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Set default selection to first interface if available
        if self.ifaces:
            first_iface = next(iter(self.ifaces.items()))
            self.selected_iface.set(f"{first_iface[1]} ({first_iface[0]})")
        
        # Create filter frame
        self.filter_frame = tk.Frame(self.main_frame)
        self.filter_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(self.filter_frame, text="Source IP:").pack(side=tk.LEFT, padx=5)
        self.src_ip_entry = tk.Entry(self.filter_frame, width=15)
        self.src_ip_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(self.filter_frame, text="Destination IP:").pack(side=tk.LEFT, padx=5)
        self.dst_ip_entry = tk.Entry(self.filter_frame, width=15)
        self.dst_ip_entry.pack(side=tk.LEFT, padx=5)
        
        self.filter_button = tk.Button(self.filter_frame, text="Filter", command=self.apply_filter)
        self.filter_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_filter_button = tk.Button(self.filter_frame, text="Clear Filter", command=self.clear_filter)
        self.clear_filter_button.pack(side=tk.LEFT, padx=5)
        
        # Create Treeview with scrollbar
        self.tree_frame = tk.Frame(self.main_frame)
        self.tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.tree_scroll = ttk.Scrollbar(self.tree_frame)
        self.tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree = ttk.Treeview(self.tree_frame, yscrollcommand=self.tree_scroll.set)
        self.tree['columns'] = ('No.', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        self.tree.column('#0', width=0, stretch=tk.NO)
        self.tree.column('No.', anchor=tk.CENTER, width=50)
        self.tree.column('Source', anchor=tk.W, width=150)
        self.tree.column('Destination', anchor=tk.W, width=150)
        self.tree.column('Protocol', anchor=tk.CENTER, width=80)
        self.tree.column('Length', anchor=tk.CENTER, width=60)
        self.tree.column('Info', anchor=tk.W, width=500)
        
        self.tree.heading('No.', text='No.', anchor=tk.CENTER)
        self.tree.heading('Source', text='Source Address', anchor=tk.W)
        self.tree.heading('Destination', text='Destination Address', anchor=tk.W)
        self.tree.heading('Protocol', text='Protocol', anchor=tk.CENTER)
        self.tree.heading('Length', text='Length', anchor=tk.CENTER)
        self.tree.heading('Info', text='Info', anchor=tk.W)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree_scroll.config(command=self.tree.yview)
        
        # Enable multiple selection and copy
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Control-c>", self.copy_selection)
        self.tree.bind("<Button-3>", self.show_context_menu)
        
        # Create control buttons frame
        self.control_frame = tk.Frame(self.main_frame)
        self.control_frame.pack(fill=tk.X, pady=10)
        
        self.start_button = tk.Button(self.control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(self.control_frame, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.stop_button.config(state=tk.DISABLED)
        
        # Add Export button between Stop and Clear
        self.export_button = tk.Button(self.control_frame, text="Export PCAP", command=self.export_pcap)
        self.export_button.pack(side=tk.LEFT, padx=5)
        self.export_button.config(state=tk.DISABLED)
        
        self.clear_button = tk.Button(self.control_frame, text="Clear", command=self.clear_packets)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Packet counter
        self.packet_count = 0
        self.count_label = tk.Label(self.control_frame, text="Packets: 0")
        self.count_label.pack(side=tk.RIGHT, padx=10)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = tk.Label(self.main_frame, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X)
        
        self.sniffing = False
        self.thread = None
        
        # Periodically check for new packets in the queue
        self.master.after(100, self.process_packet_queue)
        
        # Create context menu
        self.create_context_menu()

    def create_menu_bar(self):
        """Create Windows-style menu bar"""
        menubar = tk.Menu(self.master)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export to Text...", command=self.export_to_text)
        file_menu.add_command(label="Export to CSV...", command=self.export_to_csv)
        file_menu.add_command(label="Export to PCAP...", command=self.export_pcap)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Copy", command=self.copy_selection, accelerator="Ctrl+C")
        edit_menu.add_command(label="Select All", command=self.select_all)
        edit_menu.add_command(label="Clear All", command=self.clear_packets)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.master.config(menu=menubar)

    def apply_filter(self):
        """Apply IP filter to captured packets"""
        src_ip = self.src_ip_entry.get().strip()
        dst_ip = self.dst_ip_entry.get().strip()
        
        if not src_ip and not dst_ip:
            messagebox.showwarning("Filter Error", "Please enter at least one IP address to filter")
            return
        
        self.filtered_packets = []
        for packet in self.captured_packets:
            if IP in packet:
                packet_src = packet[IP].src
                packet_dst = packet[IP].dst
                
                match_src = not src_ip or packet_src == src_ip
                match_dst = not dst_ip or packet_dst == dst_ip
                
                if match_src and match_dst:
                    self.filtered_packets.append(packet)
        
        self.filter_active = True
        self.update_display()
        self.status_var.set(f"Filter applied - Showing {len(self.filtered_packets)} packets")

    def clear_filter(self):
        """Clear the current filter"""
        self.filter_active = False
        self.src_ip_entry.delete(0, tk.END)
        self.dst_ip_entry.delete(0, tk.END)
        self.update_display()
        self.status_var.set("Filter cleared")

    def update_display(self):
        """Update the display based on current filter state"""
        # Clear current display
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Determine which packets to display
        packets_to_display = self.filtered_packets if self.filter_active else self.captured_packets
        
        # Update display
        self.packet_count = 0
        for packet in packets_to_display:
            if IP in packet:
                self.packet_count += 1
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                proto = packet[IP].proto
                length = len(packet)
                
                protocol_name = self.get_protocol_name(proto)
                info = self.get_packet_info(packet, proto)
                
                self.tree.insert('', tk.END, 
                                values=(self.packet_count, ip_src, ip_dst, 
                                        protocol_name, length, info))
        
        self.count_label.config(text=f"Packets: {self.packet_count}")

    def export_pcap(self):
        """Export captured packets to pcap file"""
        if not self.captured_packets:
            messagebox.showwarning("No Data", "No packets to export")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")],
            title="Export to PCAP File"
        )
        
        if not filename:
            return
            
        try:
            # Export all captured packets
            wrpcap(filename, self.captured_packets)
            self.status_var.set(f"Exported {len(self.captured_packets)} packets to {os.path.basename(filename)}")
            messagebox.showinfo("Export Successful", 
                              f"Successfully exported {len(self.captured_packets)} packets to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export pcap file: {e}")
            self.status_var.set("Export failed")

    def create_context_menu(self):
        """Create right-click context menu"""
        self.context_menu = tk.Menu(self.master, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self.copy_selection)
        self.context_menu.add_command(label="Export Selected", command=self.export_selected)
        self.context_menu.add_command(label="Export All to PCAP", command=self.export_pcap)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Clear All", command=self.clear_packets)

    def show_context_menu(self, event):
        """Show context menu on right-click"""
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def get_friendly_ifaces(self):
        """Get network interfaces with friendly descriptions"""
        if platform.system() == 'Windows':
            try:
                # Use Scapy's Windows-specific interface list
                win_ifaces = get_windows_if_list()
                return {iface['name']: iface['description'] for iface in win_ifaces}
            except Exception:
                pass
        
        # Fallback for non-Windows or if Windows method fails
        return {iface: iface for iface in get_if_list()}

    def check_packet_capture_driver(self):
        """Check if Npcap or WinPcap is installed"""
        if platform.system() != 'Windows':
            return
            
        try:
            if not conf.use_pcap and not conf.use_npcap:
                messagebox.showwarning(
                    "Warning", 
                    "WinPcap is deprecated. Please install Npcap from https://npcap.com/ "
                    "(select 'Install Npcap in WinPcap API-compatible Mode')"
                )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check packet capture driver: {e}")

    def start_sniffing(self):
        """Start packet sniffing in a separate thread"""
        if not self.selected_iface.get():
            messagebox.showerror("Error", "Please select a network interface first")
            return
            
        # Extract raw interface name from the friendly name display
        selected_display = self.selected_iface.get()
        iface_name = None
        for name, desc in self.ifaces.items():
            if f"{desc} ({name})" == selected_display:
                iface_name = name
                break
        
        if not iface_name:
            messagebox.showerror("Error", "Invalid interface selected")
            return
            
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set(f"Sniffing on {selected_display}...")
        
        # Clear previous packets if any
        self.clear_packets()
        
        # Start sniffing thread
        self.thread = threading.Thread(target=self.sniffer, args=(iface_name,), daemon=True)
        self.thread.start()

    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        # 只有在有捕获数据包时才保持Export按钮启用
        if len(self.captured_packets) > 0:
            self.export_button.config(state=tk.NORMAL)
        else:
            self.export_button.config(state=tk.DISABLED)
            
        self.status_var.set("Stopped")
        
        if self.thread:
            self.thread.join(timeout=2)

    def clear_packets(self):
        """Clear all packets from the treeview"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.packet_count = 0
        self.count_label.config(text=f"Packets: {self.packet_count}")
        self.captured_packets = []
        self.filtered_packets = []
        self.filter_active = False
        self.export_button.config(state=tk.DISABLED)
        self.src_ip_entry.delete(0, tk.END)
        self.dst_ip_entry.delete(0, tk.END)
        self.status_var.set("Ready")

    def sniffer(self, iface_name):
        """Packet sniffing function to run in a separate thread"""
        def packet_callback(packet):
            if not self.sniffing:
                return
            
            try:
                # Store the raw packet for potential export
                self.captured_packets.append(packet)
                # Put packet info in queue for GUI thread to process
                self.packet_queue.put(packet)
            except Exception as e:
                self.packet_queue.put(f"Error processing packet: {e}")

        try:
            # Start sniffing on selected interface with filter for IP packets
            sniff(
                iface=iface_name,
                prn=packet_callback, 
                store=False, 
                filter="ip"
            )
        except Exception as e:
            self.packet_queue.put(f"Sniffing error on {iface_name}: {e}")
            self.sniffing = False

    def process_packet_queue(self):
        """Process packets from the queue in the main thread"""
        try:
            while not self.packet_queue.empty():
                packet = self.packet_queue.get_nowait()
                
                if isinstance(packet, str):
                    # Handle error messages
                    self.status_var.set(packet)
                    continue
                
                if IP in packet:
                    # Always store the raw packet
                    self.captured_packets.append(packet)
                    
                    # Only display if no filter or matches filter
                    if not self.filter_active:
                        self.packet_count += 1
                        self.count_label.config(text=f"Packets: {self.packet_count}")
                        
                        ip_src = packet[IP].src
                        ip_dst = packet[IP].dst
                        proto = packet[IP].proto
                        length = len(packet)
                        
                        protocol_name = self.get_protocol_name(proto)
                        info = self.get_packet_info(packet, proto)
                        
                        self.tree.insert('', tk.END, 
                                        values=(self.packet_count, ip_src, ip_dst, 
                                                protocol_name, length, info))
                        
                        # Auto-scroll to the newest packet
                        self.tree.yview_moveto(1.0)
        
        except queue.Empty:
            pass
        
        # Schedule next check
        self.master.after(100, self.process_packet_queue)

    def get_protocol_name(self, proto):
        """Get protocol name from protocol number"""
        proto_dict = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            2: "IGMP",
            41: "IPv6",
            50: "ESP",
            51: "AH",
            89: "OSPF",
        }
        return proto_dict.get(proto, f"Proto {proto}")

    def get_packet_info(self, packet, proto):
        """Get additional info about the packet based on protocol"""
        try:
            if proto == 6 and TCP in packet:  # TCP
                flags = packet[TCP].flags
                flag_str = ""
                if flags & 0x01: flag_str += "FIN "
                if flags & 0x02: flag_str += "SYN "
                if flags & 0x04: flag_str += "RST "
                if flags & 0x08: flag_str += "PSH "
                if flags & 0x10: flag_str += "ACK "
                if flags & 0x20: flag_str += "URG "
                if flags & 0x40: flag_str += "ECE "
                if flags & 0x80: flag_str += "CWR "
                
                return f"{packet[TCP].sport} -> {packet[TCP].dport} [{flag_str.strip()}]"
                
            elif proto == 17 and UDP in packet:  # UDP
                return f"{packet[UDP].sport} -> {packet[UDP].dport}"
                
            elif proto == 1 and ICMP in packet:  # ICMP
                return f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
                
            else:
                return "Other IP packet"
                
        except Exception:
            return "Packet info not available"

    def hexdump_format(self, payload):
        """Format payload as hexdump"""
        try:
            return hexdump(payload, dump=True)
        except Exception:
            return "Unable to hexdump payload"

    def on_double_click(self, event):
        """Show detailed packet info when double-clicked"""
        item = self.tree.selection()[0]
        values = self.tree.item(item, "values")
        
        popup = tk.Toplevel(self.master)
        popup.title(f"Packet Details - Packet #{values[0]}")
        popup.geometry("800x600")
        
        # Create notebook for multiple views
        notebook = ttk.Notebook(popup)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Hexdump tab
        hexdump_frame = ttk.Frame(notebook)
        notebook.add(hexdump_frame, text="Hexdump")
        
        hexdump_text = scrolledtext.ScrolledText(
            hexdump_frame, wrap=tk.WORD, width=90, height=25
        )
        hexdump_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        hexdump_text.insert(tk.END, self.hexdump_format(values[5]))
        hexdump_text.config(state=tk.DISABLED)
        
        # Packet info tab
        info_frame = ttk.Frame(notebook)
        notebook.add(info_frame, text="Packet Info")
        
        info_text = scrolledtext.ScrolledText(
            info_frame, wrap=tk.WORD, width=90, height=25
        )
        info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        info = (
            f"Packet #{values[0]}\n"
            f"Source: {values[1]}\n"
            f"Destination: {values[2]}\n"
            f"Protocol: {values[3]}\n"
            f"Length: {values[4]} bytes\n\n"
            f"Additional Info:\n{values[5]}"
        )
        
        info_text.insert(tk.END, info)
        info_text.config(state=tk.DISABLED)

    def copy_selection(self, event=None):
        """Copy selected items to clipboard"""
        selected_items = self.tree.selection()
        if not selected_items:
            return
            
        clipboard_text = ""
        columns = self.tree['columns']
        
        # Add header
        headers = [self.tree.heading(col)['text'] for col in columns]
        clipboard_text += "\t".join(headers) + "\n"
        
        # Add selected rows
        for item in selected_items:
            values = self.tree.item(item, 'values')
            clipboard_text += "\t".join(str(v) for v in values) + "\n"
        
        # Copy to clipboard
        self.master.clipboard_clear()
        self.master.clipboard_append(clipboard_text.strip())
        self.status_var.set(f"Copied {len(selected_items)} items to clipboard")

    def select_all(self):
        """Select all items in the treeview"""
        self.tree.selection_set(self.tree.get_children())

    def export_to_text(self):
        """Export all packets to a text file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Export to Text File"
        )
        if not filename:
            return
            
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Write header
                columns = self.tree['columns']
                headers = [self.tree.heading(col)['text'] for col in columns]
                f.write("\t".join(headers) + "\n")
                
                # Write all rows
                for item in self.tree.get_children():
                    values = self.tree.item(item, 'values')
                    f.write("\t".join(str(v) for v in values) + "\n")
                    
            self.status_var.set(f"Exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {e}")

    def export_to_csv(self):
        """Export all packets to a CSV file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Export to CSV File"
        )
        if not filename:
            return
            
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Write header
                columns = self.tree['columns']
                headers = [self.tree.heading(col)['text'] for col in columns]
                f.write(",".join(f'"{h}"' for h in headers) + "\n")
                
                # Write all rows
                for item in self.tree.get_children():
                    values = self.tree.item(item, 'values')
                    f.write(",".join(f'"{v}"' for v in values) + "\n")
                    
            self.status_var.set(f"Exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {e}")

    def export_selected(self):
        """Export selected items to file"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select items to export")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Export Selected Packets"
        )
        if not filename:
            return
            
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Write header
                columns = self.tree['columns']
                headers = [self.tree.heading(col)['text'] for col in columns]
                
                if filename.endswith('.csv'):
                    f.write(",".join(f'"{h}"' for h in headers) + "\n")
                else:
                    f.write("\t".join(headers) + "\n")
                
                # Write selected rows
                for item in selected_items:
                    values = self.tree.item(item, 'values')
                    if filename.endswith('.csv'):
                        f.write(",".join(f'"{v}"' for v in values) + "\n")
                    else:
                        f.write("\t".join(str(v) for v in values) + "\n")
                    
            self.status_var.set(f"Exported {len(selected_items)} items to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {e}")

    def show_about(self):
        """Show about dialog"""
        about_text = """Network Packet Analyzer
        
Version: 1.0
Developed with Python and Scapy
Author: 847297@qq.com Chuck Chen
Features:
- Real-time packet capture
- Protocol analysis
- Export to text/CSV/PCAP
- Windows-style interface

© 2025 Network Tools"""
        messagebox.showinfo("About Network Packet Analyzer", about_text)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSniffer(root)
    root.mainloop()