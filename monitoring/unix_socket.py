import argparse
import importlib
import multiprocessing
import os
import queue
import socket
import threading

import joblib

from monitoring.monitoring_threads import (
    FlowCache,
    Status,
    event_worker,
    merge_alerts_only,
    writer_thread,
)

WORKER_THREADS = max(4, multiprocessing.cpu_count() * 2)

# import sys
# print(getattr(sys, "_is_gil_enabled", lambda: "Unknown")())
# False


def unix_socket_reader(socket_path, q, status):
    if os.path.exists(socket_path):
        os.remove(socket_path)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(1)
    print(f"[INFO] Listening on {socket_path} ... Waiting for Suricata.")
    conn, _ = server.accept()
    print(f"[INFO] Suricata connected!")
    buf = b""
    while True:
        data = conn.recv(65536)
        if not data:
            break
        buf += data
        *lines, buf = buf.split(b"\n")
        for line in lines:
            line = line.strip()
            if line:
                decoded = line.decode("utf-8")
                q.put(decoded)
                status.update_read(1)
    if buf.strip():
        decoded = buf.decode("utf-8")
        q.put(decoded)
        status.update_read(1)


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

    flow_cache = FlowCache(timeout=0.05)
    q = queue.Queue(maxsize=10000)
    out_queue = queue.Queue(maxsize=10000)
    status = Status()
    threads = []

    t_reader = threading.Thread(
        target=unix_socket_reader, args=(SOCKET_PATH, q, status), daemon=True
    )
    threads.append(t_reader)

    for _ in range(WORKER_THREADS):
        t = threading.Thread(
            target=event_worker,
            args=(
                q,
                model,
                label_encoders,
                le_target,
                extract_features,
                out_queue,
                flow_cache,
                merge_alerts_only,
                status,
            ),
            daemon=True,
        )
        threads.append(t)

    t_writer = threading.Thread(
        target=writer_thread, args=(out_queue, OUT_PATH), daemon=True
    )
    threads.append(t_writer)

    t_report = threading.Thread(target=status.report, daemon=True)
    threads.append(t_report)

    for t in threads:
        t.start()
    for t in threads[:-1]:
        t.join()


if __name__ == "__main__":
    main()
