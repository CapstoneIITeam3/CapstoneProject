
import random
import requests
import time

API_URL = "http://127.0.0.1:5000/api/predict"

PROTOCOLS = ["tcp", "udp", "icmp"]
SERVICES = ["http", "private", "domain_u", "smtp", "ftp", "eco_i"]
FLAGS = ["SF", "S0", "REJ", "RSTR"]


def generate_traffic():
    """Generate one sample with all 41 NSL-KDD input features."""

    traffic = {
        "duration": random.randint(0, 1000),
        "protocol_type": random.choice(PROTOCOLS),
        "service": random.choice(SERVICES),
        "flag": random.choice(FLAGS),
        "src_bytes": random.randint(0, 100000),
        "dst_bytes": random.randint(0, 100000),
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": random.choice([0, 1]),
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": random.randint(1, 500),
        "srv_count": random.randint(1, 500),
        "serror_rate": round(random.random(), 2),
        "srv_serror_rate": round(random.random(), 2),
        "rerror_rate": round(random.random(), 2),
        "srv_rerror_rate": round(random.random(), 2),
        "same_srv_rate": round(random.random(), 2),
        "diff_srv_rate": round(random.random(), 2),
        "srv_diff_host_rate": round(random.random(), 2),
        "dst_host_count": random.randint(1, 255),
        "dst_host_srv_count": random.randint(1, 255),
        "dst_host_same_srv_rate": round(random.random(), 2),
        "dst_host_diff_srv_rate": round(random.random(), 2),
        "dst_host_same_src_port_rate": round(random.random(), 2),
        "dst_host_srv_diff_host_rate": round(random.random(), 2),
        "dst_host_serror_rate": round(random.random(), 2),
        "dst_host_srv_serror_rate": round(random.random(), 2),
        "dst_host_rerror_rate": round(random.random(), 2),
        "dst_host_srv_rerror_rate": round(random.random(), 2)
    }

    return traffic


def simulate_traffic(total=10, interval=2):
    for number in range(1, total + 1):
        traffic = generate_traffic()

        try:
            response = requests.post(
                API_URL,
                json=traffic,
                timeout=15
            )

            print(f"\nTraffic #{number}")
            print("HTTP Status:", response.status_code)
            print("Response:", response.json())

        except requests.RequestException as error:
            print("Connection error:", error)

        time.sleep(interval)


if __name__ == "__main__":
    simulate_traffic(total=10, interval=2)
