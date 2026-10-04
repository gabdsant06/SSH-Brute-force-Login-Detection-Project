"""
SSH Brute-Force Login Attempt Detector
------------------------
Parses an OpenSSH server log (auth.log format) and flags source IPs that show
brute-force behaviour:

  1. Burst of failed logins  - many failures from one IP inside a short window
  2. Username enumeration    - one IP trying many different usernames
  3. Possible compromise     - an IP that failed repeatedly, then logged in

Data: Loghub OpenSSH sample (https://github.com/logpai/loghub/tree/master/OpenSSH)

Usage:
    python ssh_bruteforce_detector.py OpenSSH_2k.log
"""

import re
import sys

import pandas as pd

# ---- Tunable thresholds -----------------------------------------------------
WINDOW = "10min"          # sliding time window for counting failures (used 10 min industry standard)
FAIL_THRESHOLD = 5        # an IP is flagged for a burst only if it fails 5 or more times within 10 minutes - human users rarely fail more than 2-5 times in a row
USERNAME_THRESHOLD = 4    # number of distinct usernames tried by one IP set to 4+ to be considered enumeration, human users rarely try more than 2-3 usernames in a row
LOG_YEAR = 2025           # syslog lines have no year, so we assume one

# ---- Regex patterns for the events we care about ----------------------------
# Example lines:
#   Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2
#   Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2
#   Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186
# Used regex patterns to identify the timestamp, IP address, and username from each line. 
TIMESTAMP = r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s[\d:]{8})"
IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
PATTERNS = {
    "failed":   re.compile(TIMESTAMP + r".*Failed password for (?:invalid user )?(?P<user>\S+) from " + IP),
    "accepted": re.compile(TIMESTAMP + r".*Accepted password for (?P<user>\S+) from " + IP),
    "invalid":  re.compile(TIMESTAMP + r".*Invalid user (?P<user>\S*) from " + IP),
}

def parse_log(path):
    """Turn raw log lines into a DataFrame of (timestamp, event, user, ip) for structured analysis"""
    rows = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            for event, pattern in PATTERNS.items():
                m = pattern.search(line)
                if m:
                    rows.append({"ts": m["ts"], "event": event,
                                 "user": m["user"], "ip": m["ip"]})
                    break
    df = pd.DataFrame(rows)
    df["ts"] = pd.to_datetime(f"{LOG_YEAR} " + df["ts"], format="%Y %b %d %H:%M:%S")
    return df.sort_values("ts").reset_index(drop=True)


def max_failures_in_window(df):
    """For each IP, record the highest number of failed logins inside any 10 min WINDOW."""
    fails = df[df["event"] == "failed"].set_index("ts")
    return (fails.groupby("ip")["event"]
                 .rolling(WINDOW).count()
                 .groupby(level="ip").max()
                 .astype(int)
                 .rename("max_fails_in_window"))


def detect(df):
    fails = df[df["event"] == "failed"]
    accepts = df[df["event"] == "accepted"]

    summary = pd.DataFrame({
        "total_failures": fails.groupby("ip").size(),
        "distinct_usernames": df[df["event"] != "accepted"].groupby("ip")["user"].nunique(),
        "first_seen": df.groupby("ip")["ts"].min(),
        "last_seen": df.groupby("ip")["ts"].max(),
    })
    summary = summary.join(max_failures_in_window(df))
    summary["successful_logins"] = accepts.groupby("ip").size()
    summary = summary.fillna(0)
    int_cols = ["total_failures", "distinct_usernames", "max_fails_in_window", "successful_logins"]
    summary[int_cols] = summary[int_cols].astype(int)

    # Flag each detection rule
    summary["burst"] = summary["max_fails_in_window"] >= FAIL_THRESHOLD
    summary["enumeration"] = summary["distinct_usernames"] >= USERNAME_THRESHOLD
    summary["possible_compromise"] = (summary["total_failures"] >= FAIL_THRESHOLD) & (summary["successful_logins"] > 0)

    flagged = summary[summary[["burst", "enumeration", "possible_compromise"]].any(axis=1)]
    return summary, flagged.sort_values("total_failures", ascending=False)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "OpenSSH_2k.log"
    df = parse_log(path)
    summary, flagged = detect(df)

    print(f"Parsed {len(df)} auth events from {df['ip'].nunique()} source IPs "
          f"({df['ts'].min():%b %d %H:%M} to {df['ts'].max():%b %d %H:%M})")
    print(f"Failed logins: {(df['event'] == 'failed').sum()} | "
          f"Successful logins: {(df['event'] == 'accepted').sum()}\n")

    print(f"Flagged {len(flagged)} suspicious IPs "
          f"(burst = {FAIL_THRESHOLD}+ failures in {WINDOW}, "
          f"enumeration = {USERNAME_THRESHOLD}+ usernames):\n")
    cols = ["total_failures", "max_fails_in_window", "distinct_usernames",
            "successful_logins", "burst", "enumeration", "possible_compromise"]
    print(flagged[cols].to_string())

    share = flagged["total_failures"].sum() / summary["total_failures"].sum()
    print(f"\nThe Flagged IPs account for {share:.0%} of all failed logins.")

    flagged.to_csv("flagged_ips.csv")
    print("Saved results to flagged_ips.csv")


if __name__ == "__main__":
    main()
