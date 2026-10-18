# Linux-LOG-ANALYZER
# Log Analyzer — XE105

Authentication log analyzer for Linux (`/var/log/auth.log`).
It extracts command usage and monitors authentication-related
changes, for a SOC / blue-team point of view.

- **Student:** Ariel Serfaty (s15)
- **Class / Unit:** TMagen773639
- **Program code:** XE105
- **Lecturer:** Tzach Azoalis

---

## Files

| File | Description |
|------|-------------|
| `TMagen773639.s15.xe105.py` | The main analyzer script. |
| `generate_auth_events.sh` | Helper that creates one example of each event in `auth.log` (for testing / screenshots). |
| `TMagen773639.s15.xe105.pdf` | Project report with screenshots and explanations. |
| `lightlogs.txt` | Report produced by the script (created next to it at run time). |

---

## Requirements

- Linux (the script also accepts `/var/log/secure` on Red Hat / Fedora).
- Python 3 (standard library only — no `pip install` needed).
- Read access to `/var/log/auth.log` (run as `root`, or as a member of
  the `adm` group).

---

## Usage

```bash
# Analyse the live system log
sudo python3 TMagen773639.s15.xe105.py

# Analyse a copied log file instead
python3 TMagen773639.s15.xe105.py /path/to/auth.log
```

The results are **printed on screen** and saved in **`lightlogs.txt`**,
in the same folder as the script.

---

## What it reports

**Part 1 — Command usage**
For each command run through `sudo`: the timestamp, the user who ran it
(the real executor, not the `USER=` target identity), and the command.

**Part 2 — Authentication changes**

| Section | Detects | Log marker used |
|---------|---------|-----------------|
| 2.1 | New users | `new user:` |
| 2.2 | Deleted users | `delete user` |
| 2.3 | Password changes | `password changed for` |
| 2.4 | `su` usage (success / failure) | `su[` + `(to ` / `FAILED SU` |
| 2.5 | `sudo` usage grouped by user | `COMMAND=` |
| 2.6 | Failed `sudo` attempts (**ALERT!**) | `incorrect password attempt`, `NOT in sudoers` |

Each event type is matched on its **system trace** (e.g. `new user:`),
not on the command typed (`adduser`): the trace proves the action really
happened, while a command can fail and leave no effect.

---

## Testing

Because `logrotate` periodically empties `auth.log`, use the helper
script to regenerate a full set of events before running the analyzer:

```bash
chmod +x generate_auth_events.sh
./generate_auth_events.sh
sudo python3 TMagen773639.s15.xe105.py
```

It creates a disposable `testuser` account, triggers one of each event,
then deletes the account.

---

## Notes and limits

- Output is duplicated to screen and file via `tee` (standard Linux tool).
- The report path is built from `__file__`, so `lightlogs.txt` is always
  created next to the script, whatever folder it is launched from.
- Only the current `auth.log` is analysed; events already moved to
  `auth.log.1` by log rotation are not included.
