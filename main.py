import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import networkx as nx
from tkinter import Tk, Label, Button, ttk, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ===================== Simulation Functions =====================
# Simulate Tor network traffic
def simulate_tor_traffic(num_entries=1000):
    np.random.seed(42)
    data = {
        "packet_id": range(num_entries),
        "timestamp": pd.date_range(start="2024-01-01", periods=num_entries, freq="s"),
        "packet_size": np.random.normal(500, 50, num_entries),
        "destination": np.random.choice(["mail.server1.com", "mail.server2.com", "malicious.server.com"], num_entries),
    }
    anomaly_indices = np.random.choice(num_entries, size=50, replace=False)
    data["packet_size"][anomaly_indices] = np.random.uniform(1000, 3000, size=50)
    data["destination"][anomaly_indices] = "malicious.server.com"
    return pd.DataFrame(data)

# Simulate email metadata
def generate_email_metadata(num_entries=300):
    np.random.seed(42)
    data = {
        "email_id": range(num_entries),
        "sender": np.random.choice(["user1@mail.com", "user2@mail.com", "malicious@mail.com"], num_entries),
        "recipient": np.random.choice(["admin@mail.com", "employee@mail.com", "client@mail.com"], num_entries),
        "attachments": np.random.randint(0, 5, num_entries),
    }
    anomaly_indices = np.random.choice(num_entries, size=20, replace=False)
    for i in anomaly_indices:
        data["sender"][i] = "malicious@mail.com"
        data["attachments"][i] = np.random.randint(5, 10)
    return pd.DataFrame(data)

# Anomaly Detection using Isolation Forest
def detect_anomalies(data):
    features = data[["packet_size"]]
    model = IsolationForest(contamination=0.05, random_state=42)
    data["anomaly"] = model.fit_predict(features)
    return data

# ===================== GUI Class =====================
class AnomalyDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Tor Anomaly Detection System")
        self.data_traffic = None
        self.data_email = None

        # Title Label
        Label(root, text="Tor Anomaly Detection System", font=("Arial", 18)).pack(pady=10)

        # Buttons
        Button(root, text="Simulate Traffic Data", command=self.load_traffic_data, width=25).pack(pady=5)
        Button(root, text="Detect Traffic Anomalies", command=self.detect_traffic_anomalies, width=25).pack(pady=5)
        Button(root, text="Visualize Traffic Anomalies", command=self.visualize_traffic, width=25).pack(pady=5)
        Button(root, text="Simulate Email Metadata", command=self.load_email_data, width=25).pack(pady=5)
        Button(root, text="View Email Communication Graph", command=self.view_email_graph, width=25).pack(pady=5)
        Button(root, text="Quit", command=root.quit, width=25).pack(pady=10)

        # Data Table
        self.tree = ttk.Treeview(root, columns=("Packet ID", "Timestamp", "Packet Size", "Destination", "Anomaly"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
        self.tree.pack(pady=10, fill="both", expand=True)

    # Simulate and load traffic data
    def load_traffic_data(self):
        self.data_traffic = simulate_tor_traffic()
        self.update_table(self.data_traffic)
        messagebox.showinfo("Success", "Traffic data simulated successfully!")

    # Detect anomalies in traffic data
    def detect_traffic_anomalies(self):
        if self.data_traffic is not None:
            self.data_traffic = detect_anomalies(self.data_traffic)
            self.update_table(self.data_traffic)
            messagebox.showinfo("Success", "Anomaly detection completed!")
        else:
            messagebox.showwarning("Warning", "Please simulate traffic data first!")

    # Visualize traffic anomalies
    def visualize_traffic(self):
        if self.data_traffic is not None:
            anomalies = self.data_traffic[self.data_traffic["anomaly"] == -1]
            fig, ax = plt.subplots(figsize=(8, 5))
            ax.scatter(self.data_traffic["timestamp"], self.data_traffic["packet_size"], c=self.data_traffic["anomaly"], cmap="coolwarm")
            ax.set_title("Traffic Anomalies")
            ax.set_xlabel("Timestamp")
            ax.set_ylabel("Packet Size")
            plt.tight_layout()

            # Embed plot in Tkinter window
            canvas = FigureCanvasTkAgg(fig, master=self.root)
            canvas.draw()
            canvas.get_tk_widget().pack(pady=10)
        else:
            messagebox.showwarning("Warning", "Please simulate traffic data first!")

    # Simulate and load email metadata
    def load_email_data(self):
        self.data_email = generate_email_metadata()
        self.update_table(self.data_email)
        messagebox.showinfo("Success", "Email metadata simulated successfully!")

    # View email communication graph
    def view_email_graph(self):
        if self.data_email is not None:
            G = nx.Graph()
            for _, row in self.data_email.iterrows():
                G.add_edge(row["sender"], row["recipient"], weight=row["attachments"])

            # Visualization
            fig, ax = plt.subplots(figsize=(8, 6))
            pos = nx.spring_layout(G)
            nx.draw(G, pos, with_labels=True, node_color="skyblue", node_size=2000, font_size=10, ax=ax)
            plt.title("Email Communication Graph")
            plt.tight_layout()

            # Embed plot in Tkinter window
            canvas = FigureCanvasTkAgg(fig, master=self.root)
            canvas.draw()
            canvas.get_tk_widget().pack(pady=10)
        else:
            messagebox.showwarning("Warning", "Please simulate email metadata first!")

    # Update table with data
    def update_table(self, data):
        # Clear existing rows
        for row in self.tree.get_children():
            self.tree.delete(row)
        # Insert new rows
        for _, row in data.iterrows():
            anomaly_label = "Yes" if row.get("anomaly", 1) == -1 else "No"
            self.tree.insert("", "end", values=(
                row.get("packet_id", row.get("email_id")),
                row.get("timestamp", ""),
                row.get("packet_size", row.get("attachments", "")),
                row.get("destination", row.get("recipient", "")),
                anomaly_label
            ))

# ===================== Main =====================
root = Tk()
root.geometry("900x700")
app = AnomalyDetectionApp(root)
root.mainloop()
