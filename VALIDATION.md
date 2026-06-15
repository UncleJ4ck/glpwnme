# Validation and CI notes

Every CVE/GHSA module in this repo is meant to have a clean behavioral
differential: `check()` fires on a live vulnerable GLPI and stays silent on the
patched one. A few modules have preconditions a CI runner must satisfy or they
will report a (correct) negative for the wrong reason.

## PHP-7.4-only modules

These exploit a PHP loose-comparison gate (`"1`...` == 1`) that only holds on
PHP 7.x. On PHP 8 the payload never reaches the sink, so the bug is genuinely
not exploitable there. The modules declare `min_php_version` / `max_php_version`
and self-gate: on a PHP-8 target they report not-applicable rather than a false
negative.

| Module | Sink / entry point | Patched | CI instance needed |
|---|---|---|---|
| `CVE_2024_27096` | `/ajax/search.php` `sort[]` -> `Search::manageParams` | 10.0.13 | PHP 7.4, GLPI 10.0.x **< 10.0.13** |
| `CVE_2024_31456` | `/ajax/map.php` `params[sort][]` -> `prepareDatasForSearch` | 10.0.15 | PHP 7.4, GLPI 10.0.x **< 10.0.15** |
| `CVE_2023_43813` | `/front/computer.php` `sort[]` (list render) | 10.0.10 | PHP 7.4, GLPI 10.0.x **< 10.0.10** |

A standard PHP-8.2 GLPI 10.0.x image **cannot** demonstrate these three. Use a
PHP-7.4 build. Validated pairs (same PHP 7.4 on both sides, so the silence is the
patch and not the PHP version):

- `CVE_2024_27096`: vuln 10.0.11 / 10.0.12 (PHP 7.4) fire; patched 10.0.15 (PHP 7.4) silent.
- `CVE_2024_31456`: vuln 10.0.1 (PHP 7.4) fires; patched 10.0.15 (PHP 7.4) silent.
- `CVE_2023_43813`: vuln 10.0.1 (PHP 7.4) fires; patched 10.0.11 (PHP 7.4) silent.

## Other module preconditions

| Module | Precondition |
|---|---|
| `GHSA_7GH3_9VHW_RJ4F` | an LDAP auth source configured |
| `CVE_2023_51446` | an LDAP auth source on BOTH a vuln (<10.0.12) and patched (>=10.0.12) instance, plus an LDAP-backed credential (e.g. sectest1). Vuln 10.0.11, patched 10.0.12. |
| `CVE_2025_21626` | at least one LDAP / mail / IMAP / CAS server configured |
| `CVE_2023_33971` | the `formcreator` plugin installed AND activated (state 1) |
| `CVE_2025_32786` | the `glpiinventory` plugin installed AND activated (state 1) |
| `CVE_2023_36808`, `CVE_2023_46727`, `CVE_2025_59935`, inventory CVEs | native inventory enabled (`enabled_inventory=1`); 46727 also needs >= 1 existing asset |
| `CVE_2024_45608` | timezones enabled (`bin/console database:enable_timezones`) |
| `CVE_2026_25937` | a 2FA-enrolled account (login lands on `/MFA/Prompt`) |
| `CVE_2022_35947` | REST API enabled + an apiclient allowing the source IP + a user with an `api_token` |
| `CVE_2023_22500` | public FAQ enabled (`use_public_faq=1`), then clear the GLPI cache |

## Destructive checks (opsec-unsafe)

`_is_check_opsec_safe = False` modules create artifacts (and purge them) or
write state. They require `--no-opsec`. Notable: `CVE_2023_42802` performs a real
file-read traversal, `CVE_2026_42321` / `CVE_2025_59935` push inventory + create
assets, `CVE_2024_37149` toggles a config right and creates a probe plugin row.
All purge their probes in a `finally` block.

## Deploying a PHP-7.4 lab instance

The validation lab uses Docker images keyed by PHP version:

- `glpwnme-php74test` (PHP 7.4) for 9.5.x and the PHP-7-only modules above
- `glpwnme-php82test` (PHP 8.2) for 10.0.6+
- the default PHP-8.4 image for 11.x

Example (CVE-2024-27096 needs PHP 7.4, GLPI < 10.0.13):

```
deploy-glpi.sh 10.0.12 <port> glpwnme-php74test
```

Then point the scanner at it:

```
python3 -m glpwnme -t http://127.0.0.1:<port> -u glpi -p glpi -e CVE_2024_27096 --check --no-opsec
```
