"""Signup rules ported from Factory v2 (``src/modules/auth``, ``src/modules/referrals``).

Each module is a port of one v2 file and keeps its semantics, windows and
thresholds; ``parity/vectors.json`` pins them:

- :mod:`namekey` — ``same-person.ts`` nameToken / registrationNameKey
- :mod:`network` — ``device-repeat.ts`` isGlobalIp, ``same-person.ts`` networkKey
- :mod:`device` — ``device-repeat.ts`` registrationFingerprint, deviceRepeatReason
- :mod:`same_person` — ``same-person.ts`` findSamePersonReason
- :mod:`referral` — ``referrals/signup.ts`` same-IP and referrer-velocity flags
- :mod:`policy` — reason tiers -> decision and actions

The rules see only keyed hashes (:class:`SignalKeys`) and ask the ledger
through small query protocols, so they never touch an email or an IP.
"""

RULESET = "2026.11-1"
