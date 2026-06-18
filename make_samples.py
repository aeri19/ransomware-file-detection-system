import pandas as pd
import os

# Path to your original dataset
DATA_PATH = r"C:\flutter\src\namer_app\data\data_file.csv"

# Folder where the sample CSV files will be saved
OUTPUT_DIR = r"C:\flutter\src\namer_app\gui_ransomware"

# Load dataset
df = pd.read_csv(DATA_PATH)

# Columns not needed for model input
drop_cols = ["FileName", "md5Hash", "Benign"]
drop_cols = [col for col in drop_cols if col in df.columns]

# Create benign sample
benign_sample = df[df["Benign"] == 1].drop(columns=drop_cols).head(1)

# Create ransomware sample
ransomware_sample = df[df["Benign"] == 0].drop(columns=drop_cols).head(1)

# Save files
benign_path = os.path.join(OUTPUT_DIR, "benign_sample.csv")
ransomware_path = os.path.join(OUTPUT_DIR, "ransomware_sample.csv")

benign_sample.to_csv(benign_path, index=False)
ransomware_sample.to_csv(ransomware_path, index=False)

print("Benign sample saved at:", benign_path)
print("Ransomware sample saved at:", ransomware_path)