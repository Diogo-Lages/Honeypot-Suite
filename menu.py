import os
import importlib
import tkinter as tk
from tkinter import scrolledtext, messagebox
import sys

# Directory containing the honeypot scripts
HONEYPOT_DIR = os.path.dirname(os.path.abspath(__file__))
HONEYPOTS = ["https", "dns", "ssh", "ftp", "postgresql"]

class HoneypotMenu:
    def __init__(self, root):
        self.root = root
        self.root.title("Honeypot Management System")
        self.root.geometry("800x600")

        # Title Label
        tk.Label(root, text="Honeypot Management System", font=("Helvetica", 16)).pack(pady=10)

        # Protocol Selection Frame
        self.protocol_frame = tk.LabelFrame(root, text="Select Honeypot", padx=10, pady=10)
        self.protocol_frame.pack(fill="both", expand=False, padx=10, pady=5)

        self.protocol_var = tk.StringVar(value="https")
        for protocol in HONEYPOTS:
            tk.Radiobutton(
                self.protocol_frame,
                text=f"{protocol.upper()} Honeypot",
                variable=self.protocol_var,
                value=protocol,
                command=self.update_config_fields,
            ).pack(anchor="w")

        # Configuration Frame
        self.config_frame = tk.LabelFrame(root, text="Configuration", padx=10, pady=10)
        self.config_frame.pack(fill="both", expand=False, padx=10, pady=5)

        # Host Input
        tk.Label(self.config_frame, text="Host:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.host_entry = tk.Entry(self.config_frame, width=30)
        self.host_entry.grid(row=0, column=1, padx=5, pady=5)
        self.host_entry.insert(0, "0.0.0.0")

        # Port Input
        tk.Label(self.config_frame, text="Port:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.port_entry = tk.Entry(self.config_frame, width=30)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)
        self.port_entry.insert(0, "default")

        # Additional Configurations
        self.additional_configs = {}
        self.additional_config_widgets = {}

        # Buttons Frame
        self.buttons_frame = tk.Frame(root)
        self.buttons_frame.pack(fill="x", padx=10, pady=10)

        self.start_button = tk.Button(self.buttons_frame, text="Start Honeypot", command=self.start_honeypot)
        self.start_button.pack(side="left", padx=5)

        self.stop_button = tk.Button(self.buttons_frame, text="Stop Honeypot", command=self.stop_honeypot, state="disabled")
        self.stop_button.pack(side="left", padx=5)

        # Logs Display
        self.logs_frame = tk.LabelFrame(root, text="Logs", padx=10, pady=10)
        self.logs_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.logs_text = scrolledtext.ScrolledText(self.logs_frame, height=15, state="disabled")
        self.logs_text.pack(fill="both", expand=True)

        # State Tracking
        self.current_honeypot = None
        self.honeypot_module = None

        # Initialize Default Configs
        self.update_config_fields()

    def update_config_fields(self):
        # Clear previous additional configs
        for widget in self.additional_config_widgets.values():
            widget.grid_forget()
        self.additional_config_widgets.clear()

        # Load selected protocol's default config
        protocol = self.protocol_var.get()
        try:
            module_name = f"{protocol}_honeypot"
            self.honeypot_module = importlib.import_module(module_name)

            # Update host and port fields
            self.host_entry.delete(0, tk.END)
            self.port_entry.delete(0, tk.END)
            self.host_entry.insert(0, getattr(self.honeypot_module, "DEFAULT_HOST", "0.0.0.0"))
            self.port_entry.insert(0, str(getattr(self.honeypot_module, "DEFAULT_PORT", "default")))

            # Add additional configuration fields if needed
            row_index = 2
            if hasattr(self.honeypot_module, "ADDITIONAL_CONFIGS"):
                for config_name, config_info in self.honeypot_module.ADDITIONAL_CONFIGS.items():
                    label = tk.Label(self.config_frame, text=f"{config_name}:")
                    label.grid(row=row_index, column=0, sticky="w", padx=5, pady=5)
                    entry = tk.Entry(self.config_frame, width=30)
                    entry.grid(row=row_index, column=1, padx=5, pady=5)
                    entry.insert(0, config_info.get("default", ""))
                    self.additional_config_widgets[config_name] = entry
                    row_index += 1

        except ImportError as e:
            messagebox.showerror("Error", f"Failed to load {protocol} honeypot module: {e}")
            self.honeypot_module = None

    def start_honeypot(self):
        if not self.honeypot_module:
            messagebox.showerror("Error", "Please select a valid honeypot protocol.")
            return

        try:
            # Collect configuration
            protocol = self.protocol_var.get()
            host = self.host_entry.get()
            port = self.port_entry.get()
            additional_config = {
                key: widget.get() for key, widget in self.additional_config_widgets.items()
            }

            # Validate inputs
            if not all([host, port]):
                messagebox.showerror("Error", "Host and Port are required!")
                return

            port = int(port)

            # Start the honeypot
            self.honeypot_module.start_honeypot(host, port, additional_config)
            self.update_logs(f"{protocol.upper()} honeypot started on {host}:{port}")
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start {protocol.upper()} honeypot: {e}")

    def stop_honeypot(self):
        if not self.honeypot_module or not hasattr(self.honeypot_module, "stop_honeypot"):
            messagebox.showerror("Error", "No honeypot is currently running.")
            return

        try:
            self.honeypot_module.stop_honeypot()
            self.update_logs(f"{self.protocol_var.get().upper()} honeypot stopped successfully.")
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop honeypot: {e}")

    def update_logs(self, message):
        self.logs_text.config(state="normal")
        self.logs_text.insert(tk.END, f"{message}\n")
        self.logs_text.see(tk.END)
        self.logs_text.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = HoneypotMenu(root)
    root.mainloop()