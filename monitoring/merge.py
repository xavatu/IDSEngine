import argparse
import json
import multiprocessing
import os
import queue
import socket
import threading
import time


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

    def to_json(self):
        return json.dumps(self.data, ensure_ascii=False)


class FlowCache:
    def __init__(self, timeout=0.2):
        self.cache = {}
        self.timeout = timeout
        self.lock = threading.Lock()

    def update(self, flow_id, event, merge_func):
        with self.lock:
            now = time.time()
            prev, last_time = self.cache.pop(flow_id, (None, now))
            merged = merge_func(prev, event) if prev else event
            self.cache[flow_id] = (merged, now)

    def flush_expired(self):
        with self.lock:
            now = time.time()
            expired = [
                fid
                for fid, (_, t) in self.cache.items()
                if now - t > self.timeout
            ]
            result = [self.cache.pop(fid)[0] for fid in expired]
        return result


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


def merge_full(e1: Event, e2: Event) -> Event:
    if e1 is None:
        return e2
    merged = e1.data.copy()
    for key, value in e2.data.items():
        if key not in merged:
            merged[key] = value
        elif isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key].update(value)
        elif isinstance(merged[key], list) and isinstance(value, list):
            merged[key].extend(value)
        elif merged[key] == value:
            continue
        else:
            v1 = merged[key]
            v2 = value
            v1_list = v1 if isinstance(v1, list) else [v1]
            v2_list = v2 if isinstance(v2, list) else [v2]
            merged[key] = list(
                {json.dumps(i, sort_keys=True) for i in v1_list + v2_list}
            )
            merged[key] = [json.loads(i) for i in merged[key]]
    return Event(json.dumps(merged))


def event_worker(q, out_queue, flow_cache, merge_func, status):
    while True:
        try:
            raw_json = q.get(timeout=1)
        except queue.Empty:
            continue
        try:
            event = Event(raw_json)
            flow_id = event.flow_id
            if flow_id is None:
                continue
            flow_cache.update(flow_id, event, merge_func)
            for ev in flow_cache.flush_expired():
                out_queue.put(ev)
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
    parser.add_argument("--unix_socket", required=True)
    parser.add_argument(
        "--out_path", required=False, default="./data/new/merged.jsonl"
    )
    args = parser.parse_args()

    SOCKET_PATH = args.unix_socket
    OUT_PATH = args.out_path

    WORKER_THREADS = max(4, multiprocessing.cpu_count() * 2)
    q = queue.Queue(maxsize=10000)
    out_queue = queue.Queue(maxsize=10000)
    status = Status()
    flow_cache = FlowCache(timeout=0.2)
    threads = []

    t_reader = threading.Thread(
        target=unix_socket_reader, args=(SOCKET_PATH, q, status), daemon=True
    )
    threads.append(t_reader)

    for _ in range(WORKER_THREADS):
        t = threading.Thread(
            target=event_worker,
            args=(q, out_queue, flow_cache, merge_full, status),
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
