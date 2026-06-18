import os
import re
import pickle
import sqlite3
from datetime import datetime
import pandas as pd
import pefile
from tkinter import filedialog, messagebox
import tkinter as tk
from tkinterdnd2 import DND_FILES, TkinterDnD

# ===============================
# Global variables and paths
# ===============================
selected_file_path = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "rf_model.pkl")
DB_PATH = os.path.join(BASE_DIR, "scan_history.db")

# ===============================
# Database functions
# ===============================
def init_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT,
            file_path TEXT,
            file_type TEXT,
            result TEXT,
            confidence REAL,
            scan_time TEXT
        )
    """)
    conn.commit()
    conn.close()

def ensure_confidence_column():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(scan_history)")
    columns = [row[1] for row in cursor.fetchall()]
    if "confidence" not in columns:
        cursor.execute("ALTER TABLE scan_history ADD COLUMN confidence REAL")
        conn.commit()
    conn.close()

def save_scan_history(file_name, file_path, file_type, result, confidence):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_history (file_name, file_path, file_type, result, confidence, scan_time)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        file_name,
        file_path,
        file_type,
        result,
        confidence,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()

def get_scan_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT file_name, file_type, result, confidence, scan_time
        FROM scan_history
        ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows

def clear_scan_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()

def export_scan_history():
    rows = get_scan_history()
    if not rows:
        messagebox.showinfo("Export History", "No scan history available to export.")
        return

    save_path = filedialog.asksaveasfilename(
        title="Export Scan History",
        defaultextension=".csv",
        filetypes=[
            ("CSV Files", "*.csv"),
            ("Text Files", "*.txt")
        ]
    )

    if not save_path:
        return

    if save_path.lower().endswith(".csv"):
        df = pd.DataFrame(
            rows,
            columns=["File Name", "File Type", "Result", "Confidence", "Scan Time"]
        )
        df.to_csv(save_path, index=False)
        messagebox.showinfo("Export Successful", f"Scan history exported to:\n{save_path}")

    elif save_path.lower().endswith(".txt"):
        with open(save_path, "w", encoding="utf-8") as f:
            for row in rows:
                file_name, file_type, result, confidence, scan_time = row
                confidence_text = f"{confidence}%" if confidence is not None else "N/A"
                f.write(
                    f"Time: {scan_time}\n"
                    f"File: {file_name}\n"
                    f"Type: {file_type}\n"
                    f"Result: {result}\n"
                    f"Confidence: {confidence_text}\n"
                    + "-" * 78 + "\n"
                )
        messagebox.showinfo("Export Successful", f"Scan history exported to:\n{save_path}")

    else:
        messagebox.showerror("Export Failed", "Unsupported export format selected.")

def get_history_summary():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE result = 'Safe / Benign'")
    benign_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE result = 'Suspicious / Ransomware-like'")
    suspicious_count = cursor.fetchone()[0]

    conn.close()
    return total_scans, benign_count, suspicious_count

# ===============================
# Load model
# ===============================
if os.path.exists(MODEL_PATH):
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
else:
    model = None

# ===============================
# Helper functions
# ===============================
def is_csv_file(file_path):
    return file_path.lower().endswith(".csv")

def is_executable_file(file_path):
    allowed_ext = (".exe", ".dll", ".xll", ".sys", ".ocx", ".cpl", ".scr", ".com")
    return file_path.lower().endswith(allowed_ext)

def clean_dropped_path(raw_path):
    raw_path = raw_path.strip()
    if raw_path.startswith("{") and raw_path.endswith("}"):
        raw_path = raw_path[1:-1]
    return raw_path

def get_file_type(file_path):
    if is_csv_file(file_path):
        return "CSV Sample"
    if is_executable_file(file_path):
        return "Executable File"
    return "Unknown"

def extract_features_from_pe(file_path):
    pe = pefile.PE(file_path)

    features = {feature: 0 for feature in model.feature_names_in_}

    def set_if_exists(name, value):
        if name in features:
            features[name] = value

    set_if_exists("Machine", pe.FILE_HEADER.Machine)
    set_if_exists("MajorLinkerVersion", pe.OPTIONAL_HEADER.MajorLinkerVersion)
    set_if_exists("MinorLinkerVersion", pe.OPTIONAL_HEADER.MinorLinkerVersion)
    set_if_exists("MajorOSVersion", pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    set_if_exists("MajorImageVersion", pe.OPTIONAL_HEADER.MajorImageVersion)
    set_if_exists("NumberOfSections", pe.FILE_HEADER.NumberOfSections)
    set_if_exists("SizeOfStackReserve", pe.OPTIONAL_HEADER.SizeOfStackReserve)
    set_if_exists("DllCharacteristics", pe.OPTIONAL_HEADER.DllCharacteristics)

    try:
        debug_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6]
        set_if_exists("DebugRVA", debug_dir.VirtualAddress)
        set_if_exists("DebugSize", debug_dir.Size)
    except Exception:
        pass

    try:
        export_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
        set_if_exists("ExportRVA", export_dir.VirtualAddress)
        set_if_exists("ExportSize", export_dir.Size)
    except Exception:
        pass

    try:
        iat_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[12]
        set_if_exists("IatRVA", iat_dir.VirtualAddress)
        set_if_exists("IatVRA", iat_dir.VirtualAddress)
    except Exception:
        pass

    try:
        resource_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2]
        set_if_exists("ResourceSize", resource_dir.Size)
    except Exception:
        pass

    try:
        with open(file_path, "rb") as f:
            raw_data = f.read().decode(errors="ignore")
        btc_pattern = r"\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{11,71})\b"
        btc_found = 1 if re.search(btc_pattern, raw_data) else 0
        set_if_exists("BitcoinAddresses", btc_found)
    except Exception:
        pass

    return pd.DataFrame([features])

def get_result_explanation(result_text):
    if result_text == "Safe / Benign":
        return (
            "Explanation: The extracted file features were more consistent with benign "
            "patterns learned by the machine learning model."
        )
    elif result_text == "Suspicious / Ransomware-like":
        return (
            "Explanation: The extracted file features showed similarity to ransomware-"
            "related patterns in the trained dataset. This is a predictive warning and "
            "should not be treated as final confirmation."
        )
    else:
        return "Explanation: No explanation available."

def validate_csv_input(sample_df):
    if sample_df.empty:
        return False, "The CSV file is empty."

    if not hasattr(model, "feature_names_in_"):
        return False, "Model feature information is unavailable."

    expected_cols = list(model.feature_names_in_)
    actual_cols = list(sample_df.columns)

    missing_cols = [col for col in expected_cols if col not in actual_cols]
    if missing_cols:
        return False, f"Missing required columns: {', '.join(missing_cols[:5])}"

    sample_df = sample_df[expected_cols]

    try:
        sample_df = sample_df.apply(pd.to_numeric)
    except Exception:
        return False, "CSV contains non-numeric values in required feature columns."

    return True, sample_df

# ===============================
# File handlers
# ===============================
def set_selected_file(file_path):
    global selected_file_path
    selected_file_path = file_path
    selected_file_label.config(text=f"Selected File: {file_path}")
    drop_area.config(text="File loaded successfully")
    status_label.config(text="Status: File selected")

def select_file():
    file_path = filedialog.askopenfilename(
        title="Select CSV sample or executable file",
        filetypes=[
            ("Supported Files", "*.csv *.exe *.dll *.xll *.sys *.ocx *.cpl *.scr *.com"),
            ("CSV Files", "*.csv"),
            ("Executable Files", "*.exe *.dll *.xll *.sys *.ocx *.cpl *.scr *.com"),
            ("All Files", "*.*")
        ]
    )
    if file_path:
        set_selected_file(file_path)

def on_drop(event):
    file_path = clean_dropped_path(event.data)
    if os.path.isfile(file_path):
        set_selected_file(file_path)
    else:
        result_label.config(text="Result: Invalid dropped file")
        confidence_label.config(text="Confidence: -")
        explanation_label.config(text="Explanation: Please drop one valid file.")
        status_label.config(text="Status: Please drop one valid file")

# ===============================
# Scan logic
# ===============================
def scan_file():
    if selected_file_path is None:
        result_label.config(text="Result: No file selected")
        confidence_label.config(text="Confidence: -")
        explanation_label.config(text="Explanation: Please select or drop a file first.")
        status_label.config(text="Status: Please select or drop a file first")
        return

    if model is None:
        result_label.config(text="Result: Model not found")
        confidence_label.config(text="Confidence: -")
        explanation_label.config(text="Explanation: The trained model file could not be loaded.")
        status_label.config(text="Status: rf_model.pkl is missing")
        return

    try:
        if is_csv_file(selected_file_path):
            raw_df = pd.read_csv(selected_file_path)
            is_valid, validated_result = validate_csv_input(raw_df)

            if not is_valid:
                result_label.config(text="Result: Invalid CSV format")
                confidence_label.config(text="Confidence: -")
                explanation_label.config(text=f"Explanation: {validated_result}")
                status_label.config(text="Status: CSV validation failed")
                return

            sample_df = validated_result

        elif is_executable_file(selected_file_path):
            sample_df = extract_features_from_pe(selected_file_path)

            if hasattr(model, "feature_names_in_"):
                expected_cols = list(model.feature_names_in_)
                sample_df = sample_df.reindex(columns=expected_cols, fill_value=0)

        else:
            result_label.config(text="Result: Unsupported file type")
            confidence_label.config(text="Confidence: -")
            explanation_label.config(text="Explanation: Only CSV and supported executable-type files can be scanned.")
            status_label.config(text="Status: Use CSV or executable-type files only")
            return

        prediction = model.predict(sample_df)[0]

        confidence_value = None
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(sample_df)[0]
            confidence_value = round(float(max(probabilities)) * 100, 2)

        if prediction == 0:
            result_text = "Suspicious / Ransomware-like"
            messagebox.showwarning(
                "Security Alert",
                "Warning: The selected file is predicted as suspicious or ransomware-like.\n"
                "Please avoid opening or executing this file until further verification."
            )
        else:
            result_text = "Safe / Benign"

        result_label.config(text=f"Result: {result_text}")
        if confidence_value is not None:
            confidence_label.config(text=f"Confidence: {confidence_value}%")
        else:
            confidence_label.config(text="Confidence: Not available")

        explanation_label.config(text=get_result_explanation(result_text))

        status_label.config(
            text=f"Status: Scan completed for {os.path.basename(selected_file_path)}"
        )

        save_scan_history(
            file_name=os.path.basename(selected_file_path),
            file_path=selected_file_path,
            file_type=get_file_type(selected_file_path),
            result=result_text,
            confidence=confidence_value
        )

    except Exception as e:
        result_label.config(text="Result: Scan failed")
        confidence_label.config(text="Confidence: -")
        explanation_label.config(text="Explanation: The system could not process the selected file.")
        status_label.config(text=f"Status: {str(e)}")

# ===============================
# History window
# ===============================
def view_history():
    history_window = tk.Toplevel(root)
    history_window.title("Scan History")
    history_window.geometry("820x520")
    history_window.resizable(False, False)

    title = tk.Label(history_window, text="Scan History", font=("Arial", 14, "bold"))
    title.pack(pady=10)

    summary_label = tk.Label(history_window, text="", font=("Arial", 10, "bold"), justify="left")
    summary_label.pack(pady=5)

    text_area = tk.Text(history_window, wrap="word", width=98, height=20)
    text_area.pack(padx=10, pady=10)

    def load_history():
        total_scans, benign_count, suspicious_count = get_history_summary()
        summary_label.config(
            text=f"Total Scans: {total_scans}    Safe/Benign: {benign_count}    Suspicious: {suspicious_count}"
        )

        text_area.config(state="normal")
        text_area.delete("1.0", "end")

        rows = get_scan_history()

        if not rows:
            text_area.insert("end", "No scan history available.")
        else:
            for row in rows:
                file_name, file_type, result, confidence, scan_time = row
                confidence_text = f"{confidence}%" if confidence is not None else "N/A"
                text_area.insert(
                    "end",
                    f"Time: {scan_time}\n"
                    f"File: {file_name}\n"
                    f"Type: {file_type}\n"
                    f"Result: {result}\n"
                    f"Confidence: {confidence_text}\n"
                    + "-" * 78 + "\n"
                )

        text_area.config(state="disabled")

    def confirm_clear_history():
        confirm = messagebox.askyesno(
            "Clear History",
            "Are you sure you want to delete all scan history?"
        )
        if confirm:
            clear_scan_history()
            load_history()
            messagebox.showinfo("History Cleared", "All scan history has been deleted.")

    button_frame = tk.Frame(history_window)
    button_frame.pack(pady=5)

    refresh_button = tk.Button(button_frame, text="Refresh", command=load_history, width=15)
    refresh_button.grid(row=0, column=0, padx=5)

    export_button = tk.Button(button_frame, text="Export History", command=export_scan_history, width=15)
    export_button.grid(row=0, column=1, padx=5)

    clear_history_button = tk.Button(button_frame, text="Clear History", command=confirm_clear_history, width=15)
    clear_history_button.grid(row=0, column=2, padx=5)

    close_button = tk.Button(button_frame, text="Close", command=history_window.destroy, width=15)
    close_button.grid(row=0, column=3, padx=5)

    load_history()

# ===============================
# About / Help
# ===============================
def show_about():
    messagebox.showinfo(
        "About / Help",
        "Ransomware Detection System\n\n"
        "Purpose:\n"
        "This system predicts whether a selected input is safe/benign or suspicious/ransomware-like using a trained machine learning model.\n\n"
        "Supported input types:\n"
        "- CSV feature samples\n"
        "- Executable-type files (.exe, .dll, .xll, .sys, .ocx, .cpl, .scr, .com)\n\n"
        "Main features:\n"
        "- Select or drag-and-drop file\n"
        "- Scan and display result\n"
        "- Confidence score\n"
        "- Explanation section\n"
        "- Security alert for suspicious result\n"
        "- Scan history, export, and clear history\n\n"
        "Important note:\n"
        "The system provides a predictive classification based on the trained dataset. "
        "A suspicious result should be treated as a warning, not as final confirmation."
    )

# ===============================
# Clear selection
# ===============================
def clear_selection():
    global selected_file_path
    selected_file_path = None
    selected_file_label.config(text="Selected File: None")
    drop_area.config(text="Drag and drop a CSV or executable file here")
    result_label.config(text="Result: Waiting for scan")
    confidence_label.config(text="Confidence: -")
    explanation_label.config(text="Explanation: Scan a file to view the prediction basis.")
    status_label.config(text="Status: Ready")

# ===============================
# GUI window
# ===============================
init_database()
ensure_confidence_column()

root = TkinterDnD.Tk()
root.title("Ransomware Detection System")
root.geometry("900x610")
root.resizable(False, False)

title_label = tk.Label(
    root,
    text="Ransomware Detection System",
    font=("Arial", 18, "bold")
)
title_label.pack(pady=15)

instruction_label = tk.Label(
    root,
    text="Select or drag-and-drop a CSV sample or executable-type file to scan."
)
instruction_label.pack(pady=5)

top_button_frame = tk.Frame(root)
top_button_frame.pack(pady=10)

select_button = tk.Button(
    top_button_frame,
    text="Select File",
    command=select_file,
    width=18
)
select_button.grid(row=0, column=0, padx=6)

clear_button = tk.Button(
    top_button_frame,
    text="Clear Selection",
    command=clear_selection,
    width=18
)
clear_button.grid(row=0, column=1, padx=6)

history_button = tk.Button(
    top_button_frame,
    text="View History",
    command=view_history,
    width=18
)
history_button.grid(row=0, column=2, padx=6)

about_button = tk.Button(
    top_button_frame,
    text="About / Help",
    command=show_about,
    width=18
)
about_button.grid(row=0, column=3, padx=6)

drop_area = tk.Label(
    root,
    text="Drag and drop a CSV or executable file here",
    width=68,
    height=6,
    bg="#e6e6e6",
    relief="ridge",
    bd=2,
    font=("Arial", 11)
)
drop_area.pack(pady=10)

drop_area.drop_target_register(DND_FILES)
drop_area.dnd_bind("<<Drop>>", on_drop)

selected_file_label = tk.Label(
    root,
    text="Selected File: None",
    wraplength=860,
    justify="left"
)
selected_file_label.pack(pady=6)

scan_button = tk.Button(
    root,
    text="Scan File",
    command=scan_file,
    width=22,
    height=2,
    font=("Arial", 11, "bold")
)
scan_button.pack(pady=12)

result_label = tk.Label(
    root,
    text="Result: Waiting for scan",
    font=("Arial", 12, "bold")
)
result_label.pack(pady=8)

confidence_label = tk.Label(
    root,
    text="Confidence: -",
    font=("Arial", 11)
)
confidence_label.pack(pady=3)

explanation_label = tk.Label(
    root,
    text="Explanation: Scan a file to view the prediction basis.",
    font=("Arial", 10),
    wraplength=860,
    justify="left"
)
explanation_label.pack(pady=8)

status_label = tk.Label(
    root,
    text="Status: Ready",
    font=("Arial", 10)
)
status_label.pack(pady=5)

root.mainloop()