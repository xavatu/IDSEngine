import json
import queue
import threading
import time

import pandas as pd


class Event:
    def __init__(self, raw_json: str):
        self.raw_json = raw_json
        self.data = self.parse(raw_json)

    @staticmethod
    def parse(raw_json: str):
        try:
            return json.loads(raw_json)
        except Exception:
            return {}

    @property
    def flow_id(self):
        return self.data.get("flow_id")

    def __getitem__(self, item):
        return self.data.get(item)

    def __setitem__(self, key, value):
        self.data[key] = value

    def to_json(self):
        return json.dumps(self.data, ensure_ascii=False)


class FlowCache:
    def __init__(self, timeout=0.05):
        self.cache = {}
        self.timeout = timeout
        self.lock = threading.Lock()

    def update(self, flow_id, event, merge_func):
        with self.lock:
            now = time.time()
            prev, last_time = self.cache.pop(flow_id, (None, now))
            merged_event = (
                merge_func(prev, event) if prev is not None else event
            )
            self.cache[flow_id] = (merged_event, now)

    def flush_expired(self):
        to_flush = []
        with self.lock:
            now = time.time()
            expired_keys = [
                fid
                for fid, (_, t) in self.cache.items()
                if now - t > self.timeout
            ]
            for fid in expired_keys:
                event, _ = self.cache.pop(fid)
                to_flush.append(event)
        return to_flush

    def force_flush_all(self):
        with self.lock:
            result = [event for event, _ in self.cache.values()]
            self.cache.clear()
        return result


def merge_alerts_only(e1: Event, e2: Event) -> Event:
    merged = Event(json.dumps(e1.data.copy() if e1 else {}))
    if "alert" in e2.data:
        if "alert" in merged.data:
            v1 = merged.data["alert"]
            v2 = e2.data["alert"]
            merged.data["alert"] = (
                v1 + [v2] if isinstance(v1, list) else [v1, v2]
            )
        else:
            merged.data["alert"] = e2.data["alert"]
    for k, v in e2.data.items():
        if k != "alert":
            merged.data[k] = v
    return merged


class Status:
    def __init__(self):
        self.read = 0
        self.processed = 0
        self.lock = threading.Lock()
        self.update_event = threading.Event()

    def update_read(self, val):
        with self.lock:
            self.read += val
        self.update_event.set()

    def update_processed(self, val):
        with self.lock:
            self.processed += val
        self.update_event.set()

    def report(self):
        last_print = ""
        while True:
            self.update_event.wait()
            with self.lock:
                line = f"\rread={self.read} processed={self.processed}"
            if line != last_print:
                print(line, end="", flush=True)
                last_print = line
            self.update_event.clear()


def event_worker(
    q,
    model,
    label_encoders,
    le_target,
    extract_features,
    out_queue,
    flow_cache,
    merge_func,
    status,
):
    while True:
        try:
            raw_json = q.get(timeout=1)
        except queue.Empty:
            continue
        try:
            event = Event(raw_json)
            features_dict = extract_features(event.data, label_encoders)
            if not features_dict:
                return
            features_df = pd.DataFrame([features_dict])
            prediction = model.predict(features_df)[0]
            pred_label = le_target.inverse_transform([prediction])[0]
            event["ml_pred"] = pred_label

            flow_id = event.flow_id
            flow_cache.update(flow_id, event, merge_func)
            expired = flow_cache.flush_expired()
            for expired_event in expired:
                out_queue.put(expired_event)
            status.update_processed(1)
        except Exception as e:
            print(f"[ERROR] Processing event: {e!r}")


def writer_thread(out_queue, out_path):
    while True:
        try:
            event = out_queue.get(timeout=1)
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(event.to_json() + "\n")
        except queue.Empty:
            continue
