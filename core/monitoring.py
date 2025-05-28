import argparse
import importlib
import json
import os
import sys
import time
from pathlib import Path

import joblib
import pandas as pd
from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver as Observer

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
parser = argparse.ArgumentParser()
parser.add_argument(
    "--model",
    required=True,
    help="Название модели из `/models`, например `xgb`",
)
parser.add_argument(
    "--dataset",
    required=True,
    help="Название датасета из `/data`, например `zap_emulated`",
)
parser.add_argument("--suricata_log_path", required=True)
parser.add_argument("--out_path", required=False, default="./monitoring.json")
args, unknown = parser.parse_known_args()

MODEL_PATH = f"./models/{args.model}"
DATASET_MODULE = f"data.{args.dataset}.extract_features"
LOG_PATH = args.suricata_log_path
OUT_PATH = args.out_path

extract_features = importlib.import_module(DATASET_MODULE).extract_features

model_artifacts = joblib.load(MODEL_PATH + "/model_artifacts.pkl")
model = model_artifacts["model"]
label_encoders = model_artifacts["label_encoders"]
le_target = model_artifacts["le_target"]


def merge_alerts_only(d1, d2):
    merged = d1.copy()
    if "alert" in d2:
        if "alert" in merged:
            v1 = merged["alert"]
            v2 = d2["alert"]
            # Если уже список — расширяем
            if isinstance(v1, list):
                merged["alert"] = v1 + [v2]
            else:
                merged["alert"] = [v1, v2]
        else:
            merged["alert"] = d2["alert"]
    for k, v in d2.items():
        if k == "alert":
            continue
        merged[k] = v
    return merged


class MonitoringHandler(FileSystemEventHandler):
    def __init__(self, filepath, outpath):
        self.filepath = os.path.realpath(filepath)
        self.outpath = os.path.realpath(outpath)
        self._inode = None
        self._file = None
        self._open()
        self._flow_cache = dict()
        self._cache_size = 256
        self._flow_timeout = 0.1

    def _open(self, read_hist=True):
        self._file = open(self.filepath, "r")
        self._inode = os.fstat(self._file.fileno()).st_ino
        self._file.seek(0 if read_hist else os.SEEK_END)

    def on_modified(self, event):
        if (
            not event.is_directory
            and os.path.realpath(event.src_path) == self.filepath
        ):
            if os.stat(self.filepath).st_ino != self._inode:
                self._file.close()
                self._open()
            self._process_new_lines()

    def on_created(self, event):
        if (
            not event.is_directory
            and os.path.realpath(event.src_path) == self.filepath
        ):
            self._file.close()
            self._open()
            self._process_new_lines()

    def on_moved(self, event):
        if (
            not event.is_directory
            and os.path.realpath(event.dest_path) == self.filepath
        ):
            self._file.close()
            self._open()
            self._process_new_lines()

    def _process_new_lines(self):
        now = time.time()
        for line in self._file:
            try:
                event = json.loads(line)
            except Exception:
                continue
            features_dict = extract_features(event, label_encoders)
            if not features_dict:
                continue
            features_df = pd.DataFrame([features_dict])
            prediction = model.predict(features_df)[0]
            pred_label = le_target.inverse_transform([prediction])[0]
            event["ml_pred"] = pred_label
            flow_id = event.get("flow_id")

            if flow_id is not None:
                prev, last_time = self._flow_cache.pop(flow_id, ({}, now))
                merged = merge_alerts_only(prev, event)
                self._flow_cache[flow_id] = (merged, now)
            else:
                with open(self.outpath, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")

        self._flush_old_flows()

    def _flush_old_flows(self):
        now = time.time()
        remove = []
        for flow_id, (merged, last_time) in self._flow_cache.items():
            if now - last_time > self._flow_timeout:
                with open(self.outpath, "a", encoding="utf-8") as f:
                    f.write(json.dumps(merged, ensure_ascii=False) + "\n")
                remove.append(flow_id)
        for flow_id in remove:
            del self._flow_cache[flow_id]


def watch_http_json(in_path, out_path):
    abs_in = os.path.realpath(in_path)
    abs_out = os.path.realpath(out_path)
    if not os.path.exists(abs_in):
        print(abs_in)
        raise FileNotFoundError(f"Файл не найден: {abs_in}")

    observer = Observer(timeout=0.01)
    handler = MonitoringHandler(abs_in, abs_out)
    observer.schedule(handler, os.path.dirname(abs_in), recursive=False)
    observer.start()
    print(f"[INFO] Monitoring started: {abs_in}")
    try:
        while True:
            time.sleep(0.01)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    watch_http_json(LOG_PATH, OUT_PATH)
