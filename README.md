# SSH-Brute-force-Login-Detection-Project

A Python project that parses OpenSSH server logs from a dataset by the Chinese University of Hong Kong downloaded from Loghub. The pipeline flags IP addresses showing brute-force and enumeration behaviour.

## Motivation 
While on Mastercard's Digital Enablement Service team this summer, I learned how card testing and BIN attacks are detected: fraudsters fix the initial BIN 6 or BIN 8 and then repeatedly generate the remaining 10 digits until a PAN is tested and approved, often in remote commerce websites. In our analysis, this testing shows up through abnormally high tokenization request failure rates. SSH brute-forcing follows the same pattern, with bots cycling through usernames and passwords until one logs in. I built this to explore how those detection ideas carry over to server security. 

## Detection rules
| Rule | What it catches | Threshold |
|---|---|---|
| Failure burst | Many failed logins from one IP in a short window | 5+ failures in a 10-minute sliding window is the threshold set because human users rarely fail more than 2-5 times in a row|
| Username enumeration | One IP trying many different usernames | 5+ distinct usernames because human users rarely try more than 2-3 user names in a row|
| Possible compromise | Repeated failures followed by a successful unauthorized login | 5+ failures and 1+ success |

### Why 5 failures in 10 minutes?
- **Matches Fail2ban's defaults** (`maxretry = 5`, `findtime = 10m`), a widely used tool for blocking SSH brute-force attacks on Linux servers.
- **Separates people from bots:** a legitimate user who mistypes a password fails a few times and stops; automated tools fail dozens or hundreds of times.
- **Tested for sensitivity:** windows from 5 to 60 minutes flagged the same attackers; only a 1-minute window missed a slower one.

## Results
On a 2,000-line sample of real logs from an internet-facing lab server:
- Parsed 632 authentication events from 25 source IPs
- Flagged 6 IPs, responsible for 91% (472) of all failed logins (519 total)
- The most active IP (183.61.140.253) made 279 failed attempts within 10 minutes (max_fails_in_window), cycling through 10 usernames (distinct_usernames)

## Data
[Loghub](https://github.com/logpai/loghub) OpenSSH sample (`OpenSSH_2k.log`), a public collection of real system logs for research.

## Usage
pip install pandas
python ssh_bruteforce_detector.py OpenSSH_2k.log

Outputs a table of flagged IPs and saves them to `flagged_ips.csv`. Thresholds can be adjusted at the top of the script.

## Limitations and next steps
- Small sample (about 4 hours of logs); a longer dataset would better test the thresholds
- Static thresholds: a per-IP baseline could adapt to normal traffic levels

## Tech
Python, pandas, regex