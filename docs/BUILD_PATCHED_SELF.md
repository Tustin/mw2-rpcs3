# Building a patched MW2 SELF

This runbook creates a patched ELF and retail SELF from the verified clean TU0
ELF. Always run the commands from the repository root.

## Required files

- `files/default_mp_tu0_clean.elf` — immutable patch input;
- `files/default_mp_tu0_clean.self` — retail SELF metadata template;
- `files/self/tool/scetool.exe` — SELF packaging tool;
- `files/self/data/keys` — scetool key data;
- `cmd/mw2-qos-patcher` — ELF patcher and SELF packaging driver.

The expected SHA-256 of the clean ELF is:

```text
5ecae7aebdffa8b5aa62f087a81f1b9c20f9c4b3dbdc4d41c2c00e65f1072041
```

## Safety rules

1. Never use `files/default_mp_tu0_clean.elf` as `-output`.
2. Never copy, move, or redirect generated data over the clean ELF.
3. Use distinct `.elf` and `.self` output paths for every build variant.
4. The patcher refuses identical input/output paths and refuses existing SELF
   outputs. Do not bypass these protections with `-force`.
5. `-force` only permits a non-reference input hash; it does not make overwriting
   the clean ELF acceptable.

Optionally make the clean inputs read-only:

```bash
chmod a-w files/default_mp_tu0_clean.elf files/default_mp_tu0_clean.self
```

## Build and sign

Choose unique output names, then run the patcher. This command patches a copy of
the clean ELF, invokes `files/self/tool/scetool.exe`, decrypts the generated SELF
again, and verifies that the decrypted result exactly matches the patched ELF.

```bash
go run ./cmd/mw2-qos-patcher \
  -input files/default_mp_tu0_clean.elf \
  -output files/default_mp_tu0_qos_selector.elf \
  -self-output files/default_mp_tu0_qos_selector.self \
  -self-template files/default_mp_tu0_clean.self \
  -scetool-dir files/self
```

On Linux, SELF packaging requires WSL integration with `powershell.exe` and
`wslpath`. On Windows, the patcher runs `scetool.exe` directly. The scetool
working directory must remain `files/self` so its `data` directory is found.

The equivalent signing operation performed by the patcher is:

```text
scetool.exe -v -t <clean-template.self> -0 SELF -1 TRUE -s FALSE -e <patched.elf> <output.self>
```

Do not run that command manually for routine builds. The patcher additionally
performs this required verification step:

```text
scetool.exe -v -d <output.self> <roundtrip.elf>
```

It compares `<roundtrip.elf>` byte-for-byte with `<patched.elf>` and only
publishes the final SELF when they match.

## Verify the outputs

A successful run prints the clean input hash, patched ELF hash, SELF hash, and
both output paths. Confirm all three files and hashes explicitly:

```bash
sha256sum \
  files/default_mp_tu0_clean.elf \
  files/default_mp_tu0_qos_selector.elf \
  files/default_mp_tu0_qos_selector.self
```

The clean ELF hash must still be:

```text
5ecae7aebdffa8b5aa62f087a81f1b9c20f9c4b3dbdc4d41c2c00e65f1072041
```

Run the patcher tests after patcher changes:

```bash
go test ./cmd/mw2-qos-patcher
go vet ./cmd/mw2-qos-patcher
```

## Rebuilding

The SELF output path must not already exist. To preserve previous artifacts,
prefer a new descriptive output name. If intentionally replacing a disposable
build, delete only its generated ELF and SELF first:

```bash
rm files/default_mp_tu0_qos_selector.elf files/default_mp_tu0_qos_selector.self
```

Never include `files/default_mp_tu0_clean.elf` or
`files/default_mp_tu0_clean.self` in a cleanup command.

## Installing in RPCS3

Install or copy the generated `.self` under the game filename expected by the
test setup. Keep the descriptive generated artifact in `files/`; do not rename
or replace the clean ELF to perform installation.
