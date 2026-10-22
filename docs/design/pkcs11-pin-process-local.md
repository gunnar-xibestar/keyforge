# Process-local PKCS#11 user PIN

Design only. This note does not change code. Forge Lead should review it, and Gunnar must approve it before implementation.

`read_user_pin` in `keyforge/kms.py` asks for the token user PIN and, on a non-blank answer, copies it into `os.environ["KEYFORGE_PKCS11_PIN"]` before returning it. The docstring says the value stays in this process and is not written to `keyforge.env`. The environment assignment is wider than that: the value is visible in `/proc/<pid>/environ` and is inherited by any child. The one in-process caller that depends on the side effect, rather than the return value, is `status`: it discards the return and then calls `pkcs11_from_env`, which reads the variable back.

## 1. Pass the PIN without setting `KEYFORGE_PKCS11_PIN`

Most callers already take the PIN as an argument. Keep that, and add a process-local cache for the one path that currently uses the environment as a side channel.

`Pkcs11Token`, `_open_token`, `confirm_user_pin`, `list_aes_labels`, and `destroy_aes_labels` already receive the PIN as a parameter. `softhsm.init_token` passes it on the `softhsm2-util --pin` argv. Setup uses `_read_pin`, which returns the string and does not touch the environment; the caller then hands that string to those functions. None of those need `read_user_pin` to publish the PIN.

Add a private module cache in `keyforge/kms.py`, the same shape as `_memory_key`. `read_user_pin` stores a non-blank PIN there and returns it. It does not assign `os.environ`. A blank entry still prints `input blank` and asks again, and it does not cache anything.

Resolve the PIN in `pkcs11_from_env` and `status` in this order:

1. An explicit argument, if one is added.
2. The process cache, after a prompt in this process (a missing PIN, or a wrong-PIN retry).
3. `os.environ["KEYFORGE_PKCS11_PIN"]` when the shell, `keyforge.env` via `load_env_file`, setup, or a test already set it.
4. Otherwise, if module, token label, and key label are all present and stdin is a TTY, call `read_user_pin`. A non-TTY stdin keeps today's `no terminal` error. If any of those three is missing, keep today's missing-settings error and do not prompt.

`status` must use the returned PIN. `pin_set` means a PIN is available from the environment or the cache. It still must not print the PIN. `format_status` can keep printing `pin_set:` and can keep naming `KEYFORGE_PKCS11_PIN` in the missing list.

`_open_token` already logs in with the returned PIN. Also store that corrected PIN in the cache so the next `provider_for()` in the same process does not ask again. `service.create` and `service.reveal` each call `provider_for` once, and each call builds a new `Pkcs11Token`, so the cache is what preserves "prompt once per process". Also set `Pkcs11Token._pin` when a retry succeeds. Today the object keeps the constructor PIN, so a later `_session()` on that same object starts over with the rejected PIN and asks again. The environment write never fixed that; it only helped a later `pkcs11_from_env`.

Cache rule: the environment is the initial value. A prompt writes the cache, and the cache wins for the rest of this process. That matches today's overwrite of `os.environ` on retry, except the corrected PIN is not published and children still see the previous environment value. Do not let a stale cache ignore an environment PIN when this process has not prompted.

Leave setup's prompt path alone. It does not call `read_user_pin`.

## 2. Everything that still reads `KEYFORGE_PKCS11_PIN`

### Reads the value

| Site | What it does |
|---|---|
| `keyforge/kms.py` `pkcs11_from_env` | `os.environ.get("KEYFORGE_PKCS11_PIN", "")`, then prompts when that is empty and module, token, and label are set. |
| `keyforge/kms.py` `status` | Same read, used only for `pin_set`. On a TTY it calls `read_user_pin` and ignores the return, then calls `pkcs11_from_env`. |
| `keyforge/setup.py` `load_env_file` | Copies every `KEY=VALUE` from `keyforge.env` into `os.environ`. `cli.main` calls this before any command. It is not a named read, and it is how a saved PIN becomes a process variable. |

`provider_for` does not read the variable itself. When `KEYFORGE_KMS_PROVIDER=pkcs11` it calls `pkcs11_from_env`. `service.create` and `service.reveal` are the only production callers of `provider_for`.

### Writes the value

| Site | What it does |
|---|---|
| `keyforge/kms.py` `read_user_pin` | The assignment this design removes. |
| `keyforge/setup.py` `run` | Puts the PIN in `saved["KEYFORGE_PKCS11_PIN"]`, then assigns every saved key into `os.environ` (existing Auth0, skipped Auth0, and new Auth0) and writes `export KEYFORGE_PKCS11_PIN=...` through `_write_env`. |
| `keyforge/setup.py` `_kms_status_lines` | Temporarily `os.environ.update(saved)` so `status` can see the PIN, then restores the previous values. |

### Names the variable and does not read it

- `Pkcs11Token` docstring ("Read from the environment only") and the empty-PIN `KeyForgeError`, which tells the operator the name.
- The missing-settings lists in `pkcs11_from_env` and `status`, and the `pin_set` line from `format_status`.
- `keyforge/setup.py` provider text: `User PIN: KEYFORGE_PKCS11_PIN`.
- Prompt labels `KEYFORGE_PKCS11_PIN: ` in `read_user_pin` and in setup's `_read_pin` / `_create_token`. Those are prompt strings, not reads.
- `keyforge/softhsm.py` `setup_instructions`: "Enter that as KEYFORGE_PKCS11_PIN."

### Subprocesses

`softhsm.init_token` copies `os.environ` into the environment of `softhsm2-util`. The tool does not look up `KEYFORGE_PKCS11_PIN`. The user PIN is `--pin` and the SO PIN is `--so-pin`. Setup calls `init_token` before it assigns the saved PIN into `os.environ`, so that child does not receive the PIN from `read_user_pin` or from setup's later assignment. It does inherit the variable when the parent shell or `load_env_file` had already set it.

No other production code spawns a process. `tests/test_pkcs11.py` and `tests/test_softhsm_tokens.py` run `softhsm2-util` without an explicit `env`, so they inherit the test process. `SoftHsmTests` sets `KEYFORGE_PKCS11_PIN` after that `init-token` call. `test_softhsm_tokens.py` never sets the variable. Neither test reads it back from the child.

### Tests

Assertions that the prompt writes the environment, which phase 1 must change:

- `tests/test_kms_roundtrip.py`: `test_read_user_pin_does_not_log_the_pin` asserts `os.environ.get("KEYFORGE_PKCS11_PIN") == PIN` after `read_user_pin`.
- `tests/test_kms_roundtrip.py`: `test_pkcs11_from_env_prompt_does_not_log_pin` asserts the same after `pkcs11_from_env` prompts.
- `tests/test_kms_status.py`: `test_status_prompts_for_a_missing_pin_on_a_tty` asserts `os.environ["KEYFORGE_PKCS11_PIN"] == "s3cret"` after `status()`.

Inputs and names that should keep working because they are not the prompt side effect:

- `tests/test_kms_roundtrip.py`, `tests/test_kms_status.py`, `tests/test_pkcs11.py`, and `tests/test_setup.py` save and restore the variable around each case. `test_kms_roundtrip.py` also lists it in `_ENV_KEYS`.
- `tests/test_kms_roundtrip.py` sets the variable before `status()` in `test_status_hides_pin_on_failure_and_success`.
- `tests/test_pkcs11.py` `SoftHsmTests` sets it so `provider_for` can open SoftHSM. `Pkcs11ConfigTests.test_missing_env_is_explicit` pops it and expects the name in the error.
- `tests/test_kms_status.py` expects the name in `kms status` text when PKCS#11 settings are absent (`test_pkcs11_reports_missing_without_export_confusion`).
- `tests/test_setup.py` expects setup itself to put the PIN in `os.environ` before Auth0 login, expects the prompt label `KEYFORGE_PKCS11_PIN: `, and expects `KEYFORGE_PKCS11_PIN=pin-secret` in the env file. Those go through `_read_pin` and `_write_env`, not `read_user_pin`.

### Docs and CI

- `docs/configuration.md` environment table lists `KEYFORGE_PKCS11_MODULE` / `_TOKEN` / `_PIN` / `_KEY_LABEL` as the PKCS#11 session.
- `docs/setup.md` says first-use AES key generation uses the same `KEYFORGE_PKCS11_PIN` already used to open the session, and that a later TTY prompt stays in the process and is not written back to `keyforge.env`. The file also says the PIN is stored in `keyforge.env` at mode 0600.
- `README.md`, `EXTENSIBILITY.md`, `docs/operations.md`, `docs/audit-integrity.md`, and `docs/demo-server.md` do not mention the variable.
- `.github/workflows/ci.yml` does not set or read it. The workflow installs SoftHSM and runs pytest. `SoftHsmTests` sets the variable in the test process.

## 3. What would break, and how to migrate

Removing only the assignment in `read_user_pin`, with no cache and no change to `status`, changes behavior:

- `status()` on a TTY with module, token, and label set and the variable unset prompts, forces `pin_set` true, then `pkcs11_from_env` prompts again. A `getpass` mock with a finite iterator raises `StopIteration`. The operator is asked twice.
- Another `provider_for()` in the same process prompts again. One CLI command is one process and reloads `keyforge.env`, so a later `create` or `reveal` in a new process is unchanged when the env file holds the PIN. The same-process cases are `status` itself, library callers, and a wrong-PIN retry followed by another `provider_for()`.
- A wrong-PIN retry currently overwrites the variable, so the next `pkcs11_from_env` uses the corrected PIN. Without a cache, that next call uses the old environment value and prompts again.
- The three assertions in section 2 fail.
- A prompted PIN no longer appears in `/proc/<pid>/environ` or in a child's environment. No production child reads that variable. That is the intended change.
- `Pkcs11Token._pin` is already unchanged by the retry. The same object still starts the next session from the constructor PIN. Removing the assignment does not change that.

Stopping the reads in the same change would break existing installs. Do not do that here.

- Non-interactive `create`, `rotate`, and `reveal` whose only PIN is `KEYFORGE_PKCS11_PIN` (shell or `keyforge.env`) would raise `no terminal` or report the variable missing.
- Setup's `_kms_status_lines` injects the just-entered PIN through `os.environ` and then calls `status`. If `status` no longer reads the variable, setup reports the PIN missing after the operator typed it.
- `SoftHsmTests` and any operator or CI job that exports the variable would stop opening the token.
- `docs/configuration.md` and `docs/setup.md` would be wrong until rewritten.

### Recommendation

Phase 1, after approval: add the cache, stop the write in `read_user_pin`, and make `status` use the return value. Keep every read of `KEYFORGE_PKCS11_PIN`. Keep setup writing the PIN into `os.environ` and into `keyforge.env`. Update the three prompt assertions so they check the return value or the cache and assert that the variable is unchanged. Tests that share a process need to clear the cache the way they already restore the environment. Update the `Pkcs11Token` docstring that says the PIN is read from the environment only, and the `docs/setup.md` sentence that says first-use key generation uses the environment variable. Generation uses the PIN already held on the `Pkcs11Token`, which came from the environment, the cache, or the prompt return. Leave the prompt text `KEYFORGE_PKCS11_PIN: ` so the operator-facing name stays stable.

No operator migration in phase 1. Existing `keyforge.env` files keep working. The environment value is still honored. A prompt in the same process shadows it for later calls in that process, which is what overwriting `os.environ` does today, except children keep the previous value.

Phase 2 is a separate design. It would stop setup from storing the PIN in `keyforge.env` and from copying it into `os.environ`, and would need a replacement for persisted unlock (another mode-0600 file, or a prompt on each process). Until then, a configured PIN remains in the env file, in the process environment after `load_env_file`, and in any child that inherits `os.environ`, including `softhsm2-util`. A small follow-up can drop `KEYFORGE_PKCS11_PIN` from the environment dict passed to that tool, because the tool takes `--pin` and does not read the variable. That scrub is not required for phase 1. The `--pin` argv is already visible to process listings; that is pre-existing and out of scope.
