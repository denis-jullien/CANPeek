#!/usr/bin/env python3
"""
CAN Bus Observer GUI - Similar to PCAN-View
Features:
- CAN frame reception and display
- Grouped view by CAN ID
- Trace view (chronological)
- DBC file loading and decoding
- Message filtering
- Statistics display
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
from datetime import datetime
from collections import defaultdict, deque
import queue
import can
import cantools
import struct

class CANBusObserver:
    def __init__(self, root):
        self.root = root
        self.root.title("CAN Bus Observer")
        self.root.geometry("1200x800")

        # CAN bus and DBC variables
        self.can_bus = None
        self.dbc_database = None
        self.is_connected = False
        self.receive_thread = None
        self.stop_thread = False

        # Data storage
        self.message_queue = queue.Queue()
        self.grouped_messages = defaultdict(lambda: {'count': 0, 'last_data': '', 'last_time': '', 'cycle_time': 0})
        self.trace_messages = deque(maxlen=1000)  # Keep last 1000 messages
        self.message_filters = set()  # CAN IDs to filter

        # Statistics
        self.total_messages = 0
        self.error_count = 0
        self.start_time = None

        self.setup_gui()
        self.start_message_processor()

    def setup_gui(self):
        # Main menu
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load DBC File", command=self.load_dbc_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Toolbar
        toolbar = ttk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=5, pady=2)

        # Connection frame
        conn_frame = ttk.LabelFrame(toolbar, text="Connection", padding=5)
        conn_frame.pack(side=tk.LEFT, padx=5)

        ttk.Label(conn_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W)
        self.interface_var = tk.StringVar(value="socketcan")
        interface_combo = ttk.Combobox(conn_frame, textvariable=self.interface_var,
                                     values=["socketcan", "pcan", "kvaser", "vector", "virtual"],
                                     width=12)
        interface_combo.grid(row=0, column=1, padx=5)

        ttk.Label(conn_frame, text="Channel:").grid(row=0, column=2, sticky=tk.W, padx=(10,0))
        self.channel_var = tk.StringVar(value="vcan0")
        channel_entry = ttk.Entry(conn_frame, textvariable=self.channel_var, width=10)
        channel_entry.grid(row=0, column=3, padx=5)

        ttk.Label(conn_frame, text="Bitrate:").grid(row=0, column=4, sticky=tk.W, padx=(10,0))
        self.bitrate_var = tk.StringVar(value="500000")
        bitrate_combo = ttk.Combobox(conn_frame, textvariable=self.bitrate_var,
                                   values=["125000", "250000", "500000", "1000000"],
                                   width=8)
        bitrate_combo.grid(row=0, column=5, padx=5)

        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=0, column=6, padx=10)

        # Control frame
        control_frame = ttk.LabelFrame(toolbar, text="Control", padding=5)
        control_frame.pack(side=tk.LEFT, padx=5)

        ttk.Button(control_frame, text="Clear", command=self.clear_messages).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="Reset Stats", command=self.reset_statistics).pack(side=tk.LEFT, padx=2)

        # Filter frame
        filter_frame = ttk.LabelFrame(toolbar, text="Filter", padding=5)
        filter_frame.pack(side=tk.LEFT, padx=5)

        ttk.Label(filter_frame, text="CAN ID:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=10)
        filter_entry.pack(side=tk.LEFT, padx=2)
        filter_entry.bind('<Return>', self.add_filter)
        ttk.Button(filter_frame, text="Add Filter", command=self.add_filter).pack(side=tk.LEFT, padx=2)

        # Status frame
        status_frame = ttk.Frame(toolbar)
        status_frame.pack(side=tk.RIGHT, padx=5)

        self.status_label = ttk.Label(status_frame, text="Status: Disconnected", foreground="red")
        self.status_label.pack()

        # Main content area
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Grouped view tab
        self.setup_grouped_tab()

        # Trace view tab
        self.setup_trace_tab()

        # Statistics tab
        self.setup_statistics_tab()

        # DBC tab
        self.setup_dbc_tab()

    def setup_grouped_tab(self):
        grouped_frame = ttk.Frame(self.notebook)
        self.notebook.add(grouped_frame, text="Grouped View")

        # Treeview for grouped messages
        columns = ("ID", "Type", "Length", "Data", "Cycle Time", "Count", "Last Seen")
        self.grouped_tree = ttk.Treeview(grouped_frame, columns=columns, show="headings", height=20)

        for col in columns:
            self.grouped_tree.heading(col, text=col)
            if col == "Data":
                self.grouped_tree.column(col, width=200)
            elif col == "ID":
                self.grouped_tree.column(col, width=80)
            else:
                self.grouped_tree.column(col, width=100)

        # Scrollbars
        v_scroll = ttk.Scrollbar(grouped_frame, orient=tk.VERTICAL, command=self.grouped_tree.yview)
        h_scroll = ttk.Scrollbar(grouped_frame, orient=tk.HORIZONTAL, command=self.grouped_tree.xview)
        self.grouped_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.grouped_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        grouped_frame.grid_rowconfigure(0, weight=1)
        grouped_frame.grid_columnconfigure(0, weight=1)

    def setup_trace_tab(self):
        trace_frame = ttk.Frame(self.notebook)
        self.notebook.add(trace_frame, text="Trace View")

        # Treeview for trace messages
        columns = ("Time", "ID", "Type", "Length", "Data", "Decoded")
        self.trace_tree = ttk.Treeview(trace_frame, columns=columns, show="headings", height=25)

        for col in columns:
            self.trace_tree.heading(col, text=col)
            if col == "Data":
                self.trace_tree.column(col, width=200)
            elif col == "Decoded":
                self.trace_tree.column(col, width=250)
            elif col == "Time":
                self.trace_tree.column(col, width=120)
            else:
                self.trace_tree.column(col, width=80)

        # Scrollbars
        v_scroll2 = ttk.Scrollbar(trace_frame, orient=tk.VERTICAL, command=self.trace_tree.yview)
        h_scroll2 = ttk.Scrollbar(trace_frame, orient=tk.HORIZONTAL, command=self.trace_tree.xview)
        self.trace_tree.configure(yscrollcommand=v_scroll2.set, xscrollcommand=h_scroll2.set)

        self.trace_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll2.grid(row=0, column=1, sticky="ns")
        h_scroll2.grid(row=1, column=0, sticky="ew")

        trace_frame.grid_rowconfigure(0, weight=1)
        trace_frame.grid_columnconfigure(0, weight=1)

    def setup_statistics_tab(self):
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="Statistics")

        # Statistics display
        stats_text = ttk.LabelFrame(stats_frame, text="Bus Statistics", padding=10)
        stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.stats_text = scrolledtext.ScrolledText(stats_text, height=20, font=("Courier", 10))
        self.stats_text.pack(fill=tk.BOTH, expand=True)

    def setup_dbc_tab(self):
        dbc_frame = ttk.Frame(self.notebook)
        self.notebook.add(dbc_frame, text="DBC Info")

        # DBC file info
        dbc_info = ttk.LabelFrame(dbc_frame, text="DBC Database", padding=10)
        dbc_info.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.dbc_text = scrolledtext.ScrolledText(dbc_info, height=20, font=("Courier", 10))
        self.dbc_text.pack(fill=tk.BOTH, expand=True)

    def load_dbc_file(self):
        file_path = filedialog.askopenfilename(
            title="Select DBC File",
            filetypes=[("DBC files", "*.dbc"), ("All files", "*.*")]
        )

        if file_path:
            try:
                self.dbc_database = cantools.database.load_file(file_path)
                self.update_dbc_info()
                messagebox.showinfo("Success", f"DBC file loaded successfully!\nMessages: {len(self.dbc_database.messages)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load DBC file:\n{str(e)}")

    def update_dbc_info(self):
        if not self.dbc_database:
            return

        info_text = f"DBC Database Information\n"
        info_text += f"{'='*50}\n\n"
        info_text += f"Total Messages: {len(self.dbc_database.messages)}\n"
        info_text += f"Total Nodes: {len(self.dbc_database.nodes)}\n\n"

        info_text += "Messages:\n"
        info_text += "-" * 30 + "\n"

        for message in self.dbc_database.messages:
            info_text += f"ID: 0x{message.frame_id:X} ({message.frame_id}) - {message.name}\n"
            info_text += f"  Length: {message.length} bytes\n"
            info_text += f"  Signals: {len(message.signals)}\n"
            for signal in message.signals:
                info_text += f"    - {signal.name}: {signal.start}-{signal.start + signal.length - 1} bits\n"
            info_text += "\n"

        self.dbc_text.delete(1.0, tk.END)
        self.dbc_text.insert(1.0, info_text)

    def toggle_connection(self):
        if not self.is_connected:
            self.connect_to_can()
        else:
            self.disconnect_from_can()

    def connect_to_can(self):
        try:
            interface = self.interface_var.get()
            channel = self.channel_var.get()
            bitrate = int(self.bitrate_var.get())

            if interface == "socketcan":
                self.can_bus = can.interface.Bus(channel=channel, bustype='socketcan')
            elif interface == "pcan":
                self.can_bus = can.interface.Bus(channel=channel, bustype='pcan', bitrate=bitrate)
            elif interface == "kvaser":
                self.can_bus = can.interface.Bus(channel=channel, bustype='kvaser', bitrate=bitrate)
            elif interface == "vector":
                self.can_bus = can.interface.Bus(channel=channel, bustype='vector', bitrate=bitrate)
            elif interface == "virtual":
                self.can_bus = can.interface.Bus(channel=channel, bustype='virtual')
            else:
                raise ValueError(f"Unsupported interface: {interface}")

            self.is_connected = True
            self.connect_btn.config(text="Disconnect")
            self.status_label.config(text="Status: Connected", foreground="green")
            self.start_time = time.time()

            # Start receiving thread
            self.stop_thread = False
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()

        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to CAN bus:\n{str(e)}")

    def disconnect_from_can(self):
        if self.can_bus:
            self.stop_thread = True
            if self.receive_thread:
                self.receive_thread.join(timeout=1)
            self.can_bus.shutdown()
            self.can_bus = None

        self.is_connected = False
        self.connect_btn.config(text="Connect")
        self.status_label.config(text="Status: Disconnected", foreground="red")

    def receive_messages(self):
        while not self.stop_thread and self.can_bus:
            try:
                message = self.can_bus.recv(timeout=0.1)
                if message:
                    self.message_queue.put(message)
            except Exception as e:
                if not self.stop_thread:  # Only log if not intentionally stopping
                    print(f"Error receiving message: {e}")
                    self.error_count += 1

    def start_message_processor(self):
        """Process messages from queue and update GUI"""
        try:
            while True:
                message = self.message_queue.get_nowait()
                self.process_message(message)
        except queue.Empty:
            pass

        # Schedule next update
        self.root.after(50, self.start_message_processor)

    def process_message(self, message):
        if not message:
            return

        # Apply filters
        if self.message_filters and message.arbitration_id not in self.message_filters:
            return

        self.total_messages += 1
        current_time = time.time()
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Update grouped view
        msg_id = message.arbitration_id
        data_str = ' '.join([f'{b:02X}' for b in message.data])

        # Calculate cycle time
        if msg_id in self.grouped_messages:
            last_time = self.grouped_messages[msg_id].get('timestamp', current_time)
            cycle_time = (current_time - last_time) * 1000  # Convert to ms
            self.grouped_messages[msg_id]['cycle_time'] = cycle_time

        self.grouped_messages[msg_id].update({
            'count': self.grouped_messages[msg_id]['count'] + 1,
            'last_data': data_str,
            'last_time': timestamp,
            'length': message.dlc,
            'timestamp': current_time
        })

        # Decode message if DBC is available
        decoded_info = ""
        if self.dbc_database:
            try:
                decoded_msg = self.dbc_database.decode_message(msg_id, message.data)
                decoded_info = ", ".join([f"{k}={v}" for k, v in decoded_msg.items()])
            except:
                decoded_info = "No decode info"

        # Add to trace
        self.trace_messages.append({
            'time': timestamp,
            'id': msg_id,
            'data': data_str,
            'length': message.dlc,
            'decoded': decoded_info
        })

        # Update GUI
        self.update_grouped_view()
        self.update_trace_view()
        self.update_statistics()

    def update_grouped_view(self):
        # Clear existing items
        for item in self.grouped_tree.get_children():
            self.grouped_tree.delete(item)

        # Add updated items
        for msg_id, info in sorted(self.grouped_messages.items()):
            msg_type = "Extended" if msg_id > 0x7FF else "Standard"
            cycle_time_str = f"{info['cycle_time']:.1f} ms" if info['cycle_time'] > 0 else "-"

            self.grouped_tree.insert("", tk.END, values=(
                f"0x{msg_id:X}",
                msg_type,
                info['length'],
                info['last_data'],
                cycle_time_str,
                info['count'],
                info['last_time']
            ))

    def update_trace_view(self):
        # Only add new messages to avoid rebuilding entire tree
        if len(self.trace_messages) > 0:
            latest_msg = self.trace_messages[-1]
            msg_type = "Extended" if latest_msg['id'] > 0x7FF else "Standard"

            self.trace_tree.insert("", 0, values=(  # Insert at top
                latest_msg['time'],
                f"0x{latest_msg['id']:X}",
                msg_type,
                latest_msg['length'],
                latest_msg['data'],
                latest_msg['decoded']
            ))

            # Limit displayed items
            children = self.trace_tree.get_children()
            if len(children) > 1000:
                self.trace_tree.delete(children[-1])

    def update_statistics(self):
        if not self.start_time:
            return

        elapsed_time = time.time() - self.start_time
        messages_per_sec = self.total_messages / elapsed_time if elapsed_time > 0 else 0

        # Count unique IDs
        unique_ids = len(self.grouped_messages)

        # Build statistics text
        stats = f"CAN Bus Statistics\n"
        stats += f"{'='*40}\n\n"
        stats += f"Connection Time: {elapsed_time:.1f} seconds\n"
        stats += f"Total Messages: {self.total_messages}\n"
        stats += f"Messages/Second: {messages_per_sec:.2f}\n"
        stats += f"Unique CAN IDs: {unique_ids}\n"
        stats += f"Error Count: {self.error_count}\n\n"

        stats += f"Message Distribution:\n"
        stats += f"{'-'*30}\n"

        # Sort by message count
        sorted_msgs = sorted(self.grouped_messages.items(),
                           key=lambda x: x[1]['count'], reverse=True)

        for msg_id, info in sorted_msgs[:20]:  # Top 20
            percentage = (info['count'] / self.total_messages) * 100
            stats += f"0x{msg_id:03X}: {info['count']:6d} ({percentage:5.1f}%)\n"

        if len(sorted_msgs) > 20:
            stats += f"... and {len(sorted_msgs) - 20} more\n"

        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(1.0, stats)

    def add_filter(self, event=None):
        filter_text = self.filter_var.get().strip()
        if not filter_text:
            return

        try:
            # Parse CAN ID (hex or decimal)
            if filter_text.startswith('0x') or filter_text.startswith('0X'):
                can_id = int(filter_text, 16)
            else:
                can_id = int(filter_text)

            self.message_filters.add(can_id)
            self.filter_var.set("")
            messagebox.showinfo("Filter Added", f"Added filter for CAN ID: 0x{can_id:X}")

        except ValueError:
            messagebox.showerror("Invalid Filter", "Please enter a valid CAN ID (hex or decimal)")

    def clear_messages(self):
        self.grouped_messages.clear()
        self.trace_messages.clear()

        # Clear tree views
        for item in self.grouped_tree.get_children():
            self.grouped_tree.delete(item)
        for item in self.trace_tree.get_children():
            self.trace_tree.delete(item)

    def reset_statistics(self):
        self.total_messages = 0
        self.error_count = 0
        self.start_time = time.time()
        self.grouped_messages.clear()
        self.trace_messages.clear()
        self.clear_messages()

def main():
    root = tk.Tk()
    app = CANBusObserver(root)

    # Handle window closing
    def on_closing():
        if app.is_connected:
            app.disconnect_from_can()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
