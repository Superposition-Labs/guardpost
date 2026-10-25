# Rules: reasons, tiers, decisions

What `POST /api/v2/check` evaluates, in which order, and what each reason means. The rules are
ports of Factory v2's signup code (`src/modules/auth/register.ts`, `oauth.ts`, `device-repeat.ts`,
`same-person.ts`, `email-validation.ts`, `referrals/signup.ts`) with the same windows, thresholds and
short-circuits. [`parity/vectors.json`](../parity/vectors.json) pins them: function vectors computed
by running v2's TypeScript, and end-to-end scenarios that both Guardpost
(`tests/test_parity_vectors.py`) and Factory v2 run. The current rule set is `2026.11-1`
(`ruleset` in every response; `guardpost/rules/__init__.py`).

## How a decision is made

Every reason has a **tier**:

| Tier | Effect | In the response |
| ---- | ------ | --------------- |
| `hard` | block the signup | `hard_reasons`, `block_code` |
| `soft` | degrade: create the account without perks (Factory's "suspicious") | `soft_reasons` |
| `weak` | raise `risk_score` only | `weak_reasons` |

The decision is the highest tier present: `block` > `degrade` > `allow`. A tenant can re-tier any
reason kind (`guardpost tenant config-set <tenant> email.reason_tiers.typo_domain=soft`).

The order, as in Factory v2 (the first hard reason stops the check):

1. **Email gates** (`signup.method = email` only; OAuth skips them): `invalid_format`, then
   `typo_domain`, then `undeliverable_domain`.
2. **Email flags**: the domain and address heuristics (disposable, keywords, MX infrastructure,
   role accounts, dot noise, `ua_domain` ...). Not run when the request has only `email_sha256`.
3. **Ledger gates**: `banned_email`; then the alias collision (`alias_collision`). Email path:
   flags, then the collision. OAuth: the collision, then flags.
4. **IP**: `blacklisted_ip` (hard). Otherwise, only while the signup is still clean:
   `graylisted_ip`, else `subnet_burst` (the address is clean but its /24 is not). `subnet_burst`
   degrades and never blocks, and is counted once in the score.
5. **Device repeat**: only on a still-clean signup; OAuth skips returning users.
6. **Same person** (`same_device`, then `same_name`): always on the email path (even when already
   flagged, so the code is retracted); OAuth skips returning users.
7. **Referral verdict**, for a signup that carries a referral.

`risk_score` (0 to 100) is a weighted sum of the reasons and the IP and /24 status (a banned
address is 100); it is informational and never changes the decision.

## Reason catalogue

Reasons keep Factory's `kind:detail` form (`code`). `kind` is the part before the first colon;
compare kinds when comparing with Factory, since some details differ (see the last column).
`evidence` never carries an email or an IP: only the tenant's own account ids and counts.

### Gates (hard by default)

| Kind | `code` | `block_code` | Evidence | Factory v2 |
| ---- | ------ | ------------ | -------- | ---------- |
| `invalid_format` | `invalid_format` | `EMAIL_INVALID_FORMAT` | | 400 "Invalid email format" |
| `typo_domain` | `typo_domain:<source>`: `map` (the typo map), `tld` (a mistyped TLD such as `.con`), `numeric` (a digit prefix such as `1gmail.com`) | `EMAIL_TYPO_SUSPECTED` (+ `suggestion`) | `suggested_domain` | `EMAIL_TYPO_SUSPECTED` (map only, see divergences) |
| `undeliverable_domain` | `undeliverable_domain` | `EMAIL_DOMAIN_UNDELIVERABLE` | | `EMAIL_DOMAIN_UNDELIVERABLE` (no MX; reserved test domains pass) |
| `banned_email` | `banned_email` | `EMAIL_BANNED` | | 400, permanent `banned_emails` |
| `alias_collision` | `alias_collision:<account_id>` | `EMAIL_ALIAS_EXISTS` | `account_id` | 400 "An account with this email already exists" (same normalized address) |
| `blacklisted_ip` | `blacklisted_ip:<status reason>`, e.g. `blacklisted_ip:8 suspicious registrations`, `blacklisted_ip:tenant override (ip)` | `IP_BLACKLISTED` | | 400 on a blacklisted `ip_reputation` row |

Any other reason promoted to `hard` by a tenant blocks with `POLICY_BLOCK`.

### Email flags

| Kind | Default tier | When | Factory v2 |
| ---- | ------------ | ---- | ---------- |
| `disposable_domain` | soft | the domain is on the disposable list (about 9,980 domains: the community list plus Guardpost's own) | same, smaller list (Guardpost's is a superset) |
| `suspicious_domain_keyword` | soft | the domain contains a throwaway keyword (`tempmail`, `throwaway`, ...) | same |
| `numeric_domain` | soft | 4 or more digits in the domain's first label | same |
| `very_short_domain` | soft | a first label of 2 characters or fewer | same |
| `no_mx_records` | soft | no MX (a flag here; the gate above refuses the email path first) | same |
| `disposable_mx_infrastructure` | soft | the MX points at a known disposable mail backend | same |
| `multiple_aliases` | soft | more than one `+` in the local part | same |
| `role_account` | soft | one of Factory's 43 role prefixes (`admin@`, `info@`, ...) | same |
| `dot_noise_local` | soft | a Gmail-family local part padded with dots (the dotted-Gmail farms) | same |
| `ua_domain` | soft | any `*.ua` address, trusted domains included; on for region `ru` (`region_rules.ua_domain`) | same (RU only) |
| `role_account_extended` | weak | one of 157 further role prefixes (`dev@`, `hello@`, ...) | none |
| `homograph_domain` | weak | the domain renders like a trusted one (Cyrillic or other confusables) | none |
| `gibberish_domain` | weak | a random-looking domain | none |
| `relay_domain` | weak | a forwarding or relay service domain | none |
| `null_mx` | weak | an RFC 7505 null MX (`.`) | none (v2 accepts a null MX) |

Trusted domains (Gmail, Yandex, Mail.ru, ...) skip the domain heuristics and DNS; the address
heuristics (`role_account`, `dot_noise_local`, `multiple_aliases`, `ua_domain`) still run.

### Network, device and person (soft)

| Kind | `code` | Evidence | When | Factory v2 |
| ---- | ------ | -------- | ---- | ---------- |
| `graylisted_ip` | `graylisted_ip:<status reason>`, e.g. `graylisted_ip:5 suspicious registrations` | | the address is graylisted in the shared reputation | same |
| `subnet_burst` | `subnet_burst:<a.b.c.0/24>` | | the address is clean but its /24 is graylisted or blacklisted | same |
| `device_repeat` | `device_repeat:<n>` | `prior_accounts` | at least 2 earlier accounts in 7 days with the same fingerprint on the same /24 (the exact address for IPv6); a non-global address never matches | same |
| `same_device` | `same_device:<account_id>` | `account_id` | an account in the last 7 days with the exact IP and fingerprint (global addresses only) | `same_device:<email>` |
| `same_name` | `same_name:<account_id>` | `account_id`, `matched_on` (`fingerprint`, `network`) | the same full name (any script or order: Алина Синичкина = Alina Sinichkina = Sinichkina Alina) in the last 30 days, plus the same /24 or the same fingerprint. A name alone never matches | `same_name:<email>` |

The shared IP thresholds (per address / per /24): graylist at 5 / 8 suspicious registrations or
15 / 25 in 7 days; blacklist at 8 / 15 suspicious or 30 / 50 in 30 days. Blacklisted is terminal
until an admin whitelists it (`guardpost ip whitelist --global`) or a tenant overrides it.

### Referral verdict

Only for a request with `referral`. `referral.reason`:

| Reason | Verdict | When |
| ------ | ------- | ---- |
| `returning_user` | not attributed | `signup.returning_user` |
| `signup_degrade`, `signup_block` | not attributed | the signup itself is not clean |
| `self_referral` | not attributed | referrer = the new account |
| `referrer_code_retracted` | not attributed | the referrer's code was retracted (`referral_code_retracted` event) |
| `same_ip_<n>_in_24h` | attributed, suspicious | this IP already produced 3 referrals in 24 h (any referrer) |
| `referrer_velocity_24h (<n> referrals in 24h)` | attributed, suspicious | the referrer already has 3 unflagged referrals in 24 h |
| `referrer_velocity_7d (<n> referrals in 7d)` | attributed, suspicious | ... or 10 in 7 days |
| null | attributed | clean |

## Actions

What the app withholds from the new account (`actions`, in this order):

| Action | When | Factory v2 |
| ------ | ---- | ---------- |
| `no_welcome_credits` | `degrade`, or a returning user | no signup bonus |
| `no_referral_attribution` | `degrade`, or a returning user | no referral row |
| `no_referral_payouts` | `degrade` | `custom_referral_bonus = 0`, `can_choose_referral_payout = false` |
| `retract_referral_code` | a `same_device` or `same_name` match | the new account's code retracted with the admin retraction fields |

A `block` has no actions (there is no account).

## Per-tenant settings

`guardpost tenant config-set <tenant> key.path=value` (validated; unknown keys are rejected).
Defaults are Factory v2's:

| Setting | Default | Rule |
| ------- | ------- | ---- |
| `region` | none | `ru` turns on `ua_domain` |
| `region_rules.ua_domain` | follows `region` | force `ua_domain` on or off |
| `email.reason_tiers.<kind>` | the tables above | re-tier a reason kind (`hard`, `soft`, `weak`) |
| `email.trusted_extra_domains` | `GUARDPOST_TRUSTED_EXTRA_DOMAINS` | app-internal domains treated as trusted (Factory: `factory.bot`, `deleted.local`) |
| `device_repeat.window_days`, `.prior_threshold` | 7, 2 | `device_repeat` |
| `same_person.device_window_days`, `.name_window_days` | 7, 30 | `same_device`, `same_name` |
| `referral.same_ip_limit`, `.velocity_24h`, `.velocity_7d` | 3, 3, 10 | referral flags |
| `retention.signals_days`, `.events_days` | 35, 400 | [PRIVACY.md](PRIVACY.md#retention) |
| `rate_limit_per_minute` | `GUARDPOST_RATE_LIMIT` | requests per minute for all the tenant's keys |

## Known divergences

Where Guardpost and Factory v2 legitimately differ (`known_divergences` in `parity/vectors.json`).
A shadow comparison should classify these as `known_divergence`, not as a mismatch:

| Id | Difference |
| -- | ---------- |
| `ipv6-canonical-text` | Guardpost canonicalizes an address (RFC 5952 IPv6, IPv4-mapped forms) before keying it; v2 compares raw strings. Latent: Factory's proxy sends canonical addresses. |
| `typo-extra-sources` | Guardpost's typo gate also matches mistyped TLDs (`typo_domain:tld`, e.g. `hotmail.con`) and extra map entries; v2 sends such an address to the MX gate, where it usually fails as `EMAIL_DOMAIN_UNDELIVERABLE`. Same decision, different `block_code`. |
| `guardpost-weak-signals` | `homograph_domain`, `null_mx`, `role_account_extended`, `gibberish_domain`, `relay_domain` exist only in Guardpost. Weak: they never change the decision but do appear in `reasons`. |
| `list-superset` | Guardpost's disposable domains, MX hosts, keywords and typo map are a superset of Factory's (`tests/test_factory_superset.py`), so it can flag an address v2 passes (Guardpost stricter). |
| `returning-user-from-client` | Guardpost cannot recognise a returning user (a deleted account's email key is erased); it trusts `signup.returning_user`. |
| `referrer-resolution` | v2 resolves the referral code itself (unknown, promo and retracted codes); Guardpost receives `referrer_account_id` and learns of a retraction only through `referral_code_retracted` events. |
| `blocked-signup-committed` | In commit (shadow) mode Guardpost records an account it would have blocked, because the app created it, and counts it as suspicious on the shared IP counters; v2 writes nothing for a refused signup. Only reachable when the decisions already differ. |
| `replay-time-bounds` | Guardpost bounds every lookup by `occurred_at`, so a replay sees the ledger as it was; v2 reads the live tables at wall-clock time. Identical for real-time signups. |
| `dns-cache` | v2 caches MX answers for 6 hours; Guardpost's v2 check asks its resolver every time. |

Also by design: `same_device` and `same_name` name the earlier account by its account id, where
Factory names it by email. The 4 domains the community list dropped upstream in October 2026
(`atomicmail.io`, `ip6.li`, `iwi.net`, `mailhub.pro`) stay flagged: Guardpost pins them in its custom
list because Factory's vendored copy still has them. That differs from upstream, not from Factory.

## Changing a rule

A rule change changes `RULESET` (`guardpost/rules/__init__.py`), the parity vectors and, for the
API, `openapi/guardpost.json` and the TypeScript types (`clients/ts`, CI checks both). Factory v2
pins `vectors.json` by sha256 and ruleset, so a change that is not mirrored there fails its parity
test on purpose. Replays must respect the date each rule took effect (for example, device
fingerprints exist only from October 2026).
