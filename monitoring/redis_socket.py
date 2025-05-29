import argparse
import importlib
import multiprocessing
import queue
import threading
import redis

import joblib

from monitoring.monitoring_threads import (
    FlowCache,
    Status,
    event_worker,
    merge_alerts_only,
    writer_thread,
)

WORKER_THREADS = max(4, multiprocessing.cpu_count() * 2)


def redis_socket_reader(redis_client, redis_key, q, status):
    print(
        f"[INFO] Listening Redis key '{redis_key}' ... Waiting for Suricata events."
    )
    while True:
        item = redis_client.blpop(redis_key, timeout=0)
        if not item:
            continue
        decoded = item[1].decode("utf-8")
        q.put(decoded)
        status.update_read(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--redis_host", required=False, default="127.0.0.1")
    parser.add_argument("--redis_port", required=False, type=int, default=6379)
    parser.add_argument(
        "--redis_key", required=False, default="suricata-eve-log"
    )
    parser.add_argument(
        "--out_path", required=False, default="./logs/redis_socket.jsonl"
    )
    args, unknown = parser.parse_known_args()

    MODEL_PATH = f"./models/{args.model}"
    DATASET_MODULE = f"data.{args.dataset}.extract_features"

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

    redis_client = redis.StrictRedis(
        host=args.redis_host, port=int(args.redis_port), db=0
    )

    t_reader = threading.Thread(
        target=redis_socket_reader,
        args=(redis_client, args.redis_key, q, status),
        daemon=True,
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
        target=writer_thread, args=(out_queue, args.out_path), daemon=True
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
