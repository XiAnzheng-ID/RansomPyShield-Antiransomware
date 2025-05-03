import pickle
import pandas as pd
from notifypy import Notify
import numpy as np
import os
import time
import psutil
import threading
from machinelearning.extract import extract_pe_features, load_yara_rules, extract_blint_findings, extract_sigcheck_info

MODEL_FEATURES = [
    'number_of_sections','entry_point','dll_characteristics','contain_crypto_address','is_packed',
    'ransomware_command_indicator','suspicious_technique_indicator','contain_tor_link','using_encryption_library','ransomware_string_indicator',
    'suspicious_entropy_and_indicator','Check_for_Debugger','yara_match_count','is_signed','is_cert_valid',
    'unique_section_names','max_entropy','min_entropy','mean_entropy','SectionsMinRawsize',
    'SectionMaxRawsize','SectionsMeanRawsize','SectionsMinVirtualsize','SectionMaxVirtualsize','SectionsMeanVirtualsize',
    'imported_dll_count','imported_function_count','exported_function_count',
    'blint_guard_cf','blint_high_entropy_va','blint_no_bind','blint_no_seh','blint_nx_compat'
]

ALLOWED_EXTENSIONS = ('.exe', '.EXE', 'dll', '.DLL', '.ransom', '.malware', '.mal', '.virus')

monitoring_thread = None
monitoring_active = False

def parse_blint_flags(blint_output):
    flags = set(f.strip() for f in blint_output.split(",") if f.strip())
    return flags

def interpret_probability(probability, ransomware_threshold=0.60, gray_threshold=0.50):
    prob_ransomware = probability[1]
    if prob_ransomware >= ransomware_threshold:
        return "Ransomware/Malware"
    elif prob_ransomware >= gray_threshold:
        return "Unknown/Suspicious"
    else:
        return "Benign"
    
def kill_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        print(f"[INFO] Process with PID {pid} terminated.")
    except psutil.NoSuchProcess:
        print(f"[ERROR] Process with PID {pid} no longer exists.")
    except psutil.AccessDenied:
        print(f"[ERROR] Access denied to terminate process with PID {pid}.")
    except Exception as e:
        print(f"[ERROR] Failed to terminate process with PID {pid}: {e}")

def scan_file(file_path, model, yara_rules, use_blint=False, blint_path="blint.exe", use_sigcheck=False, sigcheck_path="sigcheck.exe", ransomware_threshold=0.70, pid=None):
    features = extract_pe_features(file_path, yara_rules, label="unknown")
    if not features:
        print(f"[ERROR] Failed to extract {file_path}")
        return

    if use_blint:
        blint_raw = extract_blint_findings(file_path, blint_path)
        blint_flags = parse_blint_flags(blint_raw)

        blint_possible_flags = ["GUARD_CF", "HIGH_ENTROPY_VA", "NO_BIND", "NO_SEH", "NX_COMPAT"]
        for flag in blint_possible_flags:
            features[f'blint_{flag.lower()}'] = 1 if flag in blint_flags else 0

    if use_sigcheck:
        sigcheck_result = extract_sigcheck_info(file_path, sigcheck_path)
        features['is_signed'] = sigcheck_result.get('is_signed', 0)
        features['is_cert_valid'] = sigcheck_result.get('is_cert_valid', 0)

    df = pd.DataFrame([features])
    for feat in MODEL_FEATURES:
        if feat not in df.columns:
            df[feat] = 0
    df = df[MODEL_FEATURES]

    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0]

    print(f"\n[RESULT] File: {file_path}")
    print(f"Benign             : {probability[0]*100:.2f}%")
    print(f"Ransomware/Malware : {probability[1]*100:.2f}%")
    verdict = interpret_probability(probability)
    print(f"Verdict            : {verdict}")

    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        top_n = 50
        sorted_idx = np.argsort(importances)[::-1][:top_n]
        print("[INFO] Top features:")
        for idx in sorted_idx:
            fname = MODEL_FEATURES[idx]
            print(f"  - {fname}: {df.iloc[0][fname]} (importance: {importances[idx]:.4f})")

    # Processing the process if it exceeds the threshold
    if probability[1] >= ransomware_threshold:
        print("[WARNING] Ransomware/Malware detected!")
        notification = Notify()
        notification.title = f"RansomPyShield - Machine learning: {probability[1]*100:.2f}%"
        notification.message = f"{verdict} File detected: {file_path}, has been killed"
        notification.send()
        if pid is not None:
            kill_process(pid)

    return prediction, probability, verdict
def monitor_new_processes(model, yara_rules, use_blint, blint_path, use_sigcheck, sigcheck_path):
    global monitoring_active
    known_pids = set(p.pid for p in psutil.process_iter())
    print("[INFO] Process monitoring started...")

    while monitoring_active:
        try:
            time.sleep(0.1)
            current_pids = set(p.pid for p in psutil.process_iter())
            new_pids = current_pids - known_pids

            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    exe_path = proc.exe()
                    if exe_path.lower().endswith(ALLOWED_EXTENSIONS):
                        print(f"\n[INFO] New process detected: {exe_path}")
                        scan_file(exe_path, model, yara_rules, use_blint, blint_path, use_sigcheck, sigcheck_path, pid=pid)
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    print(f"[ERROR] Unexpected error: {e}")

            known_pids = current_pids
        except Exception as e:
            print(f"[ERROR] Monitoring loop error: {e}")
            break

    print("[INFO] Monitoring stopped.")

def start_ml_monitoring():
    global monitoring_thread, monitoring_active
    if monitoring_active:
        print("[INFO] Monitoring is already running.")
        return

    localappdata = os.getenv('LOCALAPPDATA')
    model_path = os.path.join(localappdata, "RansomPyShield", "ransompyshield.pkl")
    yara_rules_dir = os.path.join(localappdata, "RansomPyShield", "ML_Rules")

    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    yara_rules, _ = load_yara_rules(yara_rules_dir)

    use_blint = True
    use_sigcheck = True
    blint_path = "blint.exe"
    sigcheck_path = "sigcheck.exe"

    monitoring_active = True
    monitoring_thread = threading.Thread(
        target=monitor_new_processes,
        args=(model, yara_rules, use_blint, blint_path, use_sigcheck, sigcheck_path),
        daemon=True
    )
    monitoring_thread.start()

def stop_ml_monitoring():
    global monitoring_active
    monitoring_active = False
