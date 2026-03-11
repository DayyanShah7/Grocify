import os
import librosa
import pandas as pd
from tqdm import tqdm

# CONFIG
AUDIO_FOLDER = "voice_data"
CSV_OUTPUT = "csv_features"
SAMPLE_RATE = 16000
N_MFCC = 13
AUDIO_EXTENSIONS = ('.wav', '.mp3', '.m4a', '.flac')

os.makedirs(CSV_OUTPUT, exist_ok=True)
success_count = 0

print("Processing audio files...")

for root, _, files in os.walk(AUDIO_FOLDER):
    for file in tqdm(files):
        if file.lower().endswith(AUDIO_EXTENSIONS):
            try:
                path = os.path.join(root, file)

                # Load audio
                y, sr = librosa.load(path, sr=SAMPLE_RATE)
                mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=N_MFCC)

                # MFCC → DataFrame
                df = pd.DataFrame(
                    mfcc.T,
                    columns=[f"MFCC_{i+1}" for i in range(N_MFCC)]
                )

                # Preserve folder structure
                rel_path = os.path.relpath(root, AUDIO_FOLDER)
                save_dir = os.path.join(CSV_OUTPUT, rel_path)
                os.makedirs(save_dir, exist_ok=True)

                csv_path = os.path.join(
                    save_dir,
                    f"{os.path.splitext(file)[0]}.csv"
                )
                df.to_csv(csv_path, index=False)
                success_count += 1

            except Exception as e:
                print(f"Failed {file}: {e}")

print(f"\nSuccessfully converted {success_count} files to CSV")
if success_count == 0:
    raise RuntimeError("No audio files processed!")
