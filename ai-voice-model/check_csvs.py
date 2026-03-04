from tqdm import tqdm
import pandas as pd
import os

csv_files = []

for root, _, files in os.walk("csv_features"):
    for file in files:
        if file.endswith(".csv"):
            csv_files.append(os.path.join(root, file))

print(f"Found {len(csv_files)} CSV files.")

for csv_file in tqdm(csv_files):
    try:
        pd.read_csv(csv_file)
    except Exception as e:
        print(f"Failed to load {csv_file}: {e}")
