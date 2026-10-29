# Technical execution notes

## Scope

These notes document the supplied exact-build research scripts. They do not assert that every version with the same vulnerable code path is exploitable using these constants.

## Mechanism separation

The package keeps three operations distinct:

1. **Trigger-only OOM request** — `poc_cve_2026_109618_trigger.py` constructs one amplified multipart request. It intentionally omits A1/B1, leak parsing, runtime addresses, ROP, and commands.
2. **A1/B1 session-memory disclosure** — `php8511_cookie_leak.py` uses cross-request stale session state and a forged `zend_string` to URL-encode adjacent process memory into `Set-Cookie: PHPSESSID`. This is the script’s mechanism-based CVE-2026-109619 attribution, not a reassignment of any public PoC by a CVE authority.
3. **Incomplete-HashTable cleanup sink** — the integrated RCE runner uses the CVE-2026-109618 OOM/cleanup mechanism after a fresh validated disclosure.

Worker discovery, pool scrubbing, holder rebinds, and same-worker queueing are delivery and affinity techniques, not separate vulnerabilities.

## Execution flow

```text
01  Start and configure evidence collection
02  Discover the Apache worker pool
03  Scrub, hold, and repin workers
04  Queue A1 followed by B1 for one selected mod_php child
05  A1 reaches calibrated OOM and leaves stale session state
06  B1 reclaims storage and installs a forged zend_string
07  PHP returns adjacent memory in an overlong PHPSESSID cookie
08  Decode the cookie and scan little-endian 64-bit pointers
09  Validate repeated dtor evidence, module alignment, and heap evidence
10  Derive fresh libphp/heap addresses internally
11  Build the forged object, pivot, and libphp-only ROP chain
12  Send one amplified RCE request
13  Cleanup reaches the forged handlers and zif_system(command)
14  Fetch /proof.txt independently for the default command
15  Report VERIFIED, FAILED, or DELIVERED_UNVERIFIED accurately
```

See `execution-diagram.png` for the visual version and failure branches.

## Address model

```text
libphp_base = leaked_zval_ptr_dtor - dtor_offset
heap_base   = libphp_base + heap_delta
rce_block   = heap_base + rce_block_offset
zif_system  = libphp_base + zif_system_offset
```

The leak supplies runtime pointer evidence. It does not supply portable image-relative offsets. Those offsets come from the exact `libphp.so` binary, while heap/request geometry also depends on runtime configuration and request history.

## Validation gates

The integrated runner requires:

- a dominant-pointer count of at least 100;
- a derived libphp base aligned to 2 MiB;
- at least one disclosed pointer in the derived heap bucket.

The offline validator has independent defaults and supports stricter heap evidence, structural positions, additional module anchors, and ambiguity rejection. Its `VALIDATED` result is strong consistency evidence, not mathematical proof and not an RCE-compatibility guarantee.

## Failure interpretation

| Observation | Interpretation |
|---|---|
| `0 accepted holders` | Failure during connectivity/worker discovery, before A1/B1; check the target and request path |
| No `PHPSESSID` value | Disclosure did not complete |
| Ordinary short session ID | Normal cookie, not a memory disclosure; often a profile or heap-geometry mismatch |
| Overlong cookie but no pointers | Reject the disclosure |
| Bad module alignment | Wrong pointer candidate or wrong binary offset |
| Missing/weak heap confirmation | Do not treat derived heap addresses as trustworthy |
| Empty RCE POST response | Inconclusive; use independent proof |
| No `uid=` in `/proof.txt` | Default command execution is not verified |
| `DELIVERED_UNVERIFIED` | The request was delivered, but command execution was not independently confirmed |

The proof file created by the default command resides on the target. Reading the local testing machine’s `/var/www/html/proof.txt` is not a valid verification step.

## Why a version-matched profile can still fail

Two installations can both report PHP 8.5.11 while having different:

- `libphp.so` bytes and Build IDs;
- compiler and linker options;
- NTS/ZTS or architecture properties;
- loaded modules and startup allocations;
- memory limits and Apache worker behavior;
- heap state and request history.

Changing only the version string or one offset does not port the chain. A different target requires exact-binary analysis and controlled runtime recalibration.

## Evidence hygiene

Raw responses and decoded cookies may contain arbitrary process memory. Keep them outside version control, restrict access, and delete them when no longer needed. The repository `.gitignore` excludes common evidence outputs, but operators remain responsible for reviewing every file before committing.
