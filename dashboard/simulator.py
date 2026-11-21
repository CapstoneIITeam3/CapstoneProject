"""Replay mode (SRS §3.2.1): feeds records into the pipeline at a fixed interval.

If data/replay.csv exists it is replayed row by row. It can be the raw NSL-KDD
KDDTrain+.txt / KDDTest+.txt (no header, 41 features + label [+ difficulty]) or
any CSV with a header containing the NSL-KDD column names (+ optional 'label').
Otherwise synthetic NSL-KDD-shaped traffic is generated so the dashboard can be
demoed before the data pipeline is ready.

NSL-KDD has no IP addresses, so src/dst IPs are synthesised for display only.
"""
import csv
import logging
import os
import random
import threading
import time

from detector import NSL_KDD_FEATURES, CATEGORICAL

log = logging.getLogger(__name__)
_BASE = os.path.dirname(os.path.abspath(__file__))
# first file found is replayed; the parent folder is checked too so the dashboard can live inside the team repo
REPLAY_CANDIDATES = [os.path.join(d, "data", f)
                     for d in (_BASE, os.path.dirname(_BASE))
                     for f in ("replay.csv", "KDDTest+.txt", "KDDTrain+.txt")]

INTERNAL = [f"10.0.{a}.{b}" for a in range(1, 4) for b in range(10, 60, 7)]
EXTERNAL = [f"{a}.{b}.{c}.{d}" for a, b, c, d in
            [(45, 33, 12, 9), (185, 220, 101, 4), (103, 21, 244, 7), (91, 240, 118, 22),
             (198, 51, 100, 23), (203, 0, 113, 77), (172, 67, 10, 5), (8, 8, 4, 4), (142, 250, 70, 14)]]
ATTACKERS = ["185.220.101.4", "45.33.12.9", "103.21.244.7", "91.240.118.22"]


def _base():
    f = {k: 0.0 for k in NSL_KDD_FEATURES if k not in CATEGORICAL}
    f.update(protocol_type="tcp", service="http", flag="SF", logged_in=1.0,
             count=random.randint(1, 20), srv_count=random.randint(1, 20),
             same_srv_rate=round(random.uniform(0.85, 1), 2),
             dst_host_count=random.randint(20, 255), dst_host_srv_count=random.randint(20, 255),
             dst_host_same_srv_rate=round(random.uniform(0.7, 1), 2))
    return f


def synth_record():
    r = random.random()
    f = _base()
    if r < 0.78:
        label = "normal"
        f.update(protocol_type=random.choice(["tcp"] * 6 + ["udp"] * 3 + ["icmp"]),
                 service=random.choice(["http", "http", "smtp", "domain_u", "ftp_data", "private", "ecr_i"]),
                 duration=random.choice([0] * 8 + [random.randint(1, 300)]),
                 src_bytes=random.randint(100, 2000), dst_bytes=random.randint(0, 9000))
        if f["protocol_type"] == "icmp":
            f["src_bytes"] = random.randint(8, 520)
    elif r < 0.88:
        label = random.choice(["neptune", "smurf", "back"])
        if label == "neptune":
            f.update(flag="S0", service="private", src_bytes=0, dst_bytes=0, logged_in=0,
                     count=random.randint(150, 510), serror_rate=1.0, srv_serror_rate=1.0,
                     same_srv_rate=round(random.uniform(0, 0.1), 2), dst_host_serror_rate=1.0)
        elif label == "smurf":
            f.update(protocol_type="icmp", service="ecr_i", src_bytes=random.choice([1032, 520, 1480]),
                     count=511, srv_count=511, logged_in=0)
        else:
            f.update(src_bytes=54540, dst_bytes=8314, hot=random.randint(2, 4))
    elif r < 0.95:
        label = random.choice(["portsweep", "satan", "ipsweep", "nmap"])
        f.update(flag=random.choice(["REJ", "RSTO", "SF", "S0"]), service=random.choice(["private", "other", "eco_i"]),
                 src_bytes=random.randint(0, 20), logged_in=0, rerror_rate=round(random.uniform(0.3, 1), 2),
                 diff_srv_rate=round(random.uniform(0.4, 1), 2), dst_host_diff_srv_rate=round(random.uniform(0.3, 1), 2),
                 same_srv_rate=round(random.uniform(0, 0.3), 2))
        if label == "ipsweep":
            f["protocol_type"] = "icmp"
    elif r < 0.985:
        label = random.choice(["guess_passwd", "warezclient", "ftp_write"])
        f.update(service=random.choice(["telnet", "ftp", "ftp_data", "pop_3"]),
                 duration=random.randint(0, 60), src_bytes=random.randint(100, 400),
                 num_failed_logins=random.randint(0, 2) if label == "guess_passwd" else 0,
                 hot=random.randint(0, 5), is_guest_login=1.0 if label == "warezclient" else 0.0,
                 logged_in=0 if label == "guess_passwd" else 1)
        if label == "guess_passwd" and f["num_failed_logins"] == 0:
            f["num_failed_logins"] = 1
    else:
        label = random.choice(["buffer_overflow", "rootkit", "perl"])
        f.update(service="telnet", duration=random.randint(20, 200), src_bytes=random.randint(1000, 6000),
                 dst_bytes=random.randint(1000, 9000), hot=random.randint(1, 6),
                 root_shell=1.0, num_file_creations=random.randint(0, 3), num_shells=random.randint(0, 1))
    attack = label != "normal"
    src = random.choice(ATTACKERS) if attack and random.random() < 0.7 else random.choice(EXTERNAL + INTERNAL)
    dst = random.choice(INTERNAL)
    return f, label, src, dst


class CsvReplayer:
    def __init__(self, path):
        self.path = path
        self._rows = self._read()
        random.shuffle(self._rows)  # mix normal and attack rows so the live feed looks like real traffic
        self._i = 0
        log.info("Replaying %d records from %s", len(self._rows), path)

    def _read(self):
        with open(self.path, newline="") as fh:
            first = fh.readline()
            fh.seek(0)
            has_header = "protocol_type" in first
            reader = csv.reader(fh)
            if has_header:
                header = [h.strip() for h in next(reader)]
            else:
                header = NSL_KDD_FEATURES + ["label", "difficulty"]
            rows = []
            for row in reader:
                if not row:
                    continue
                d = dict(zip(header, row))
                feats = {}
                for k in NSL_KDD_FEATURES:
                    v = d.get(k, 0)
                    feats[k] = v if k in CATEGORICAL else float(v or 0)
                rows.append((feats, (d.get("label") or d.get("class") or "").strip().rstrip(".") or None))
            return rows

    def next(self):
        f, label = self._rows[self._i % len(self._rows)]
        self._i += 1
        attack = label not in (None, "normal")
        src = random.choice(ATTACKERS) if attack and random.random() < 0.7 else random.choice(EXTERNAL + INTERNAL)
        return dict(f), label, src, random.choice(INTERNAL)


def find_dataset():
    """DATASET env var picks a file explicitly (name inside data/, or a full path),
    e.g. DATASET=KDDTrain+.txt. Otherwise: replay.csv, then KDDTest+.txt, then KDDTrain+.txt."""
    want = os.environ.get("DATASET", "").strip()
    if want:
        options = [want] + [os.path.join(d, "data", want) for d in (_BASE, os.path.dirname(_BASE))]
        found = next((p for p in options if os.path.isfile(p)), None)
        if not found:
            log.error("DATASET=%s not found in data/; falling back to the default order", want)
        else:
            return os.path.abspath(found)
    return next((p for p in REPLAY_CANDIDATES if os.path.exists(p)), None)


def make_source():
    path = find_dataset()
    if path:
        try:
            r = CsvReplayer(path)
            if r._rows:
                return r.next, "csv", path
        except Exception as e:
            log.error("Could not read %s (%s), using synthetic traffic", path, e)
    return synth_record, "synthetic", None


def start(app, ingest_fn, get_interval, is_enabled):
    """Background thread: every `interval` seconds push one record through ingest_fn."""
    next_record, kind, path = make_source()
    app.config["REPLAY_SOURCE"] = kind
    app.config["REPLAY_FILE"] = path

    def loop():
        while True:
            try:
                with app.app_context():
                    interval = get_interval()
                    if is_enabled():
                        burst = random.choice([1, 1, 1, 2, 3])
                        for _ in range(burst):
                            f, label, src, dst = next_record()
                            ingest_fn(f, true_label=label, src_ip=src, dst_ip=dst, source="replay")
            except Exception as e:
                log.error("Replay tick failed: %s", e)
                interval = 5
            time.sleep(max(0.5, interval))

    t = threading.Thread(target=loop, name="replay", daemon=True)
    t.start()
    return t
