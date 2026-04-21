import pefile
import joblib
import numpy as np
import os
import math
import re
import pandas as pd
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='pefile')
import hashlib
import json
import requests
import sys

# To ensure a clean console output when running the script, we can suppress TensorFlow and Scikit-Learn warnings/logs.
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' # Silences library logs
import warnings
warnings.filterwarnings("ignore") # Silences Scikit-Learn version warnings

# 1. SETUP: Load the V3 Files
MODEL_PATH = "E:/Sem-03/Database Labs/Project/ai_model/malware_model_v3.pkl"
SCALER_PATH = 'E:/Sem-03/Database Labs/Project/ai_model/scaler_v3.pkl'
FILE_TO_TEST = 'E:/Sem-03/Database Labs/Project/ai_model/microsoft-office-2021-16-0-19725-20152.exe'

try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    #print("V3 Model and Scaler loaded successfully.")
except Exception as e:
    print(f"Error loading files: {e}")

# 2. FEATURE EXTRACTION: The 33-Feature Engine
def calculate_entropy(data):
    if not data: return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0: entropy += - p_x * math.log(p_x, 2)
    return float(entropy)

def extract_33_features(path):
    try:
        pe = pefile.PE(path)
        with open(path, 'rb') as f:
            data = f.read()

        f = [0.0] * 33

        # 0-2: Strings
        strings = re.findall(b"[\x20-\x7e]{4,}", data)
        f[0] = float(len(strings))
        f[1] = float(sum(len(s) for s in strings) / f[0]) if f[0] > 0 else 0.0
        f[2] = float(len([c for c in data if 32 <= c <= 126]))

        # 3-6: Entropy, URLs, Size
        f[3] = calculate_entropy(data)
        f[4] = float(len(re.findall(b'https?://', data)))
        f[5] = float(os.path.getsize(path))
        f[6] = float(pe.OPTIONAL_HEADER.SizeOfImage)

        # 7-13: Directory Flags
        # 7-13: Directory Flags
        f[7] = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0.0

        # FIX FOR EXPORTS:
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            try:
                f[8] = float(len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
            except (AttributeError, TypeError):
                f[8] = 0.0
        else:
            f[8] = 0.0

        # FIX FOR IMPORTS:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            try:
                f[9] = float(len(pe.DIRECTORY_ENTRY_IMPORT))
            except (AttributeError, TypeError):
                f[9] = 0.0
        else:
            f[9] = 0.0
        f[10] = 1.0 if pe.FILE_HEADER.Characteristics & 0x0001 else 0.0
        f[11] = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0.0
        f[12] = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') else 0.0
        f[13] = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_TLS') else 0.0

        # 14-16: COFF Headers
        f[14] = float(pe.FILE_HEADER.TimeDateStamp)
        m_type = pe.FILE_HEADER.Machine
        f[15] = 1.0 if m_type == 332 else (2.0 if m_type == 34404 else 0.0)
        f[16] = float(pe.FILE_HEADER.Characteristics)

        # 17-19: Subsystem & Magic
        sub = pe.OPTIONAL_HEADER.Subsystem
        f[17] = 1.0 if sub == 2 else (2.0 if sub == 3 else 0.0)
        f[18] = float(pe.OPTIONAL_HEADER.DllCharacteristics)
        mag = pe.OPTIONAL_HEADER.Magic
        f[19] = 1.0 if mag == 267 else (2.0 if mag == 523 else 0.0)

        # 20-30: Optional Header Technicals
        f[20] = float(pe.OPTIONAL_HEADER.MajorImageVersion)
        f[21] = float(pe.OPTIONAL_HEADER.MinorImageVersion)
        f[22] = float(pe.OPTIONAL_HEADER.MajorLinkerVersion)
        f[23] = float(pe.OPTIONAL_HEADER.MinorLinkerVersion)
        f[24] = float(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
        f[25] = float(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
        f[26] = float(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
        f[27] = float(pe.OPTIONAL_HEADER.MinorSubsystemVersion)
        f[28] = float(pe.OPTIONAL_HEADER.SizeOfCode)
        f[29] = float(pe.OPTIONAL_HEADER.SizeOfHeaders)
        f[30] = float(pe.OPTIONAL_HEADER.SizeOfHeapCommit)

        # 31-32: Entry & Section Count
        f[31] = float(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        f[32] = float(len(pe.sections)) if hasattr(pe, 'sections') else 0.0

        # --- THE "SUPER-FEATURE" INJECTION ---
        # We replace two less-important features with high-signal interactions

        # Interaction A: Entropy per Unit of Code
        # If there's very little code but massive entropy, it's a "Dropper"
        size_of_code = f[28] if f[28] > 0 else 1.0
        f[20] = f[3] / math.log(size_of_code + 1) # Replacing MajorImageVersion

        # Interaction B: String Density
        # Malware hides strings; Clean files are full of them.
        file_size = f[5] if f[5] > 0 else 1.0
        f[21] = f[0] / (file_size / 1024)

        # --- SECTION ENTROPY OVERRIDE ---
        if hasattr(pe, 'sections'):
            max_s_ent = max([s.get_entropy() for s in pe.sections]) if pe.sections else 0
            if max_s_ent > 7.2:
                f[3] = max_s_ent

        return np.array(f).reshape(1, -1)
    except Exception as e:
        print(f"Extraction Error: {e}")
        return None

# 3. PREDICTION: Run the Data through V3
feature_names = [
    'numstrings', 'avlength', 'printables', 'entropy', 'urls', 'size', 'vsize',
    'has_debug', 'exports_counts', 'imports_counts', 'has_relocations',
    'has_resources', 'has_signature', 'has_tls', 'coff.timestamp', 'coff.machine',
    'coff.characteristics', 'optional.subsystem', 'optional.dll_characteristics',
    'optional.magic', 'optional.major_image_version', 'optional.minor_image_version',
    'optional.major_linker_version', 'optional.minor_linker_version',
    'optional.major_operating_system_version', 'optional.minor_operating_system_version',
    'optional.major_subsystem_version', 'optional.minor_subsystem_version',
    'optional.sizeof_code', 'optional.sizeof_headers', 'optional.sizeof_heap_commit',
    'entry', 'sections'
]

raw_vector = extract_33_features(FILE_TO_TEST)


def analyze_and_push(file_path):
    print(f"Starting Intelligence Triage for: {os.path.basename(file_path)}")
    
    # 1. Generate Fingerprint
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    # 2. Extract & Scale
    raw_vector = extract_33_features(file_path)
    if raw_vector is None: return
    
    df_input = pd.DataFrame(raw_vector, columns=feature_names)
    scaled_df = pd.DataFrame(scaler.transform(df_input), columns=feature_names)
    
    # 3. Model Inference
    prob = float(model.predict_proba(scaled_df)[0, 1])
    
    # 4. Construct Forensic Payload
    payload = {
        "file_name": os.path.basename(file_path),
        "hash": file_hash,
        "entropy": float(raw_vector[0][3]),
        "probability": prob,
        "features": {
            "num_strings": int(raw_vector[0][0]),
            "imports": int(raw_vector[0][9]),
            "sections": int(raw_vector[0][32]),
            "debug": int(raw_vector[0][7]),
            "code_size": int(raw_vector[0][28]),
            "full_set": scaled_df.iloc[0].to_dict() # Saving scaled features to JSON
        }
    }

    # 5. Push to XAMPP Bridge
    url = "http://localhost/smart_inventory/api/upload_scan.php"
    try:
        with open(file_path, 'rb') as f:
            files = {'image': (os.path.basename(file_path), f, 'application/octet-stream')}
            data = {'json_data': json.dumps(payload)}
            response = requests.post(url, files=files, data=data)
            print(f"Server Response: {response.text}")
    except Exception as e:
        print(f"Upload Failed: {e}")
          
def main():
    if len(sys.argv) < 2:
        return

    target_file = sys.argv[1]
    
    # 1. Extraction
    raw_vector = extract_33_features(target_file)
    if raw_vector is None:
        # Send a clean error back to PHP instead of crashing
        print(json.dumps({"success": False, "error": "PE file structure is invalid or corrupt."}))
        return

    # Now the scaler will have data to transform
    df_input = pd.DataFrame(raw_vector, columns=feature_names)
    
    # 2. Prediction
    df_input = pd.DataFrame(raw_vector, columns=feature_names)
    scaled_df = pd.DataFrame(scaler.transform(df_input), columns=feature_names)
    prob = float(model.predict_proba(scaled_df)[0, 1])

    # Clean the features for JSON output (handle NaN and Inf)
    # 1. Capture the features into a dictionary
    raw_features = scaled_df.iloc[0].to_dict()

    # 2. THE SANITIZATION FIX: 
    # Iterate through the features to replace JSON-breaking values
    clean_features = {}
    for k, v in raw_features.items():
        # Replace NaN or Infinity with 0.0 to prevent PHP json_decode failure
        if pd.isna(v) or np.isinf(v):
            clean_features[k] = 0.0
        else:
            clean_features[k] = float(v)

    # 3. CONSTRUCT THE FINAL RESPONSE
    response = {
        "success": True,
        "probability": float(prob),
        "file": os.path.basename(target_file),
        "features": clean_features  # Use the cleaned dictionary
    }

    # 4. SILENT OUTPUT (Only print the JSON)
    print(json.dumps(response))

if __name__ == "__main__":
    main()