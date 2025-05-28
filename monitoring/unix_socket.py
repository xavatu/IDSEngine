import argparse
import importlib
import json
import os
import socket
import time
from abc import ABC, abstractmethod
from typing import Callable

import joblib
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
    def __init__(self, timeout: float = 0.1):
        self.cache = {}
        self.timeout = timeout

    def update(self, flow_id, event: Event, merge_func: Callable):
        now = time.time()
        prev, last_time = self.cache.pop(flow_id, (None, now))
        if prev is not None:
            merged_event = merge_func(prev, event)
        else:
            merged_event = event
        self.cache[flow_id] = (merged_event, now)

    def flush(self, out_path: str, write_func: Callable):
        now = time.time()
        to_remove = []
        for flow_id, (event, last_time) in self.cache.items():
            if now - last_time > self.timeout:
                write_func(out_path, event)
                to_remove.append(flow_id)
        for fid in to_remove:
            del self.cache[fid]

    @staticmethod
    def write_event(out_path: str, event: Event):
        with open(out_path, "a", encoding="utf-8") as f:
            f.write(event.to_json() + "\n")


class EventHandler(ABC):
    @abstractmethod
    def handle(self, event: Event):
        pass


class AlertEventHandler(EventHandler):
    def __init__(
        self,
        model,
        label_encoders,
        le_target,
        extract_features,
        out_path: str,
        flow_cache: FlowCache,
        merge_func: Callable,
    ):
        self.model = model
        self.label_encoders = label_encoders
        self.le_target = le_target
        self.extract_features = extract_features
        self.out_path = out_path
        self.flow_cache = flow_cache
        self.merge_func = merge_func
        self.events_processed = 0

    def handle(self, event: Event):
        features_dict = self.extract_features(event.data, self.label_encoders)
        if not features_dict:
            return
        features_df = pd.DataFrame([features_dict])
        prediction = self.model.predict(features_df)[0]
        pred_label = self.le_target.inverse_transform([prediction])[0]
        event["ml_pred"] = pred_label

        flow_id = event.flow_id
        self.events_processed += 1
        print(f"\rProcessed packets: {self.events_processed}", end="")
        self.flow_cache.update(flow_id, event, self.merge_func)
        self.flow_cache.flush(self.out_path, FlowCache.write_event)


def merge_alerts_only(e1: Event, e2: Event) -> Event:
    merged = Event(json.dumps(e1.data.copy()))
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


class SuricataUnixSocketServer:
    def __init__(self, socket_path: str, event_handler: EventHandler):
        self.socket_path = socket_path
        self.server = None
        self.conn = None
        self.event_handler = event_handler

    def start(self):
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.socket_path)
        self.server.listen(1)
        print(
            f"[INFO] Listening on {self.socket_path} ... Waiting for Suricata."
        )
        self.conn, _ = self.server.accept()
        print(f"[INFO] Suricata connected!")

        try:
            self._main_loop()
        finally:
            self.shutdown()

    def listen_forever(self):
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.socket_path)
        while True:
            self.server.listen(1)
            print(
                f"[INFO] Listening on {self.socket_path} ... Waiting for Suricata."
            )
            self.conn, _ = self.server.accept()
            print(f"[INFO] Suricata connected!")
            try:
                self._main_loop()
            except Exception as e:
                print(f"[WARNING] Connection lost via {e}")

    def _main_loop(self):
        buf = b""
        while True:
            data = self.conn.recv(4096)
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    event = Event(line.decode("utf-8"))
                    self.event_handler.handle(event)

    def shutdown(self):
        if self.conn:
            self.conn.close()
        if self.server:
            self.server.close()
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--unix_socket", required=True)
    parser.add_argument(
        "--out_path", required=False, default="./logs/unix_socket.jsonl"
    )
    args, unknown = parser.parse_known_args()

    MODEL_PATH = f"./models/{args.model}"
    DATASET_MODULE = f"data.{args.dataset}.extract_features"
    SOCKET_PATH = args.unix_socket
    OUT_PATH = args.out_path

    extract_features = importlib.import_module(DATASET_MODULE).extract_features
    model_artifacts = joblib.load(MODEL_PATH + "/model_artifacts.pkl")
    model = model_artifacts["model"]
    label_encoders = model_artifacts["label_encoders"]
    le_target = model_artifacts["le_target"]

    flow_cache = FlowCache(timeout=0.1)
    handler = AlertEventHandler(
        model,
        label_encoders,
        le_target,
        extract_features,
        OUT_PATH,
        flow_cache,
        merge_alerts_only,
    )

    server = SuricataUnixSocketServer(SOCKET_PATH, handler)
    server.listen_forever()


if __name__ == "__main__":
    main()
