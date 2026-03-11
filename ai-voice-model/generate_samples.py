from gtts import gTTS
import os

phrases = [
    "add milk",
    "add rice",
    "add green apple",
    "add chicken breast",
    "remove milk",
    "remove rice",
    "remove green apple",
    "remove chicken breast"
]

base_folder = "voice_data"

for phrase in phrases:
    intent = phrase.split()[0]
    folder = os.path.join(base_folder, intent)
    os.makedirs(folder, exist_ok=True)

    # Count existing files to avoid overwrite
    existing_files = len(os.listdir(folder)) + 1

    filename = f"{intent}_ai_{existing_files}.mp3"
    path = os.path.join(folder, filename)

    tts = gTTS(text=phrase, lang="en")
    tts.save(path)

print("AI voice samples generated safely.")
