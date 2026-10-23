# /// script
# dependencies = ["jsonschema==4.26.0"]
# ///
"""Validate the data/ json files changed since a commit against the CVE schema version each file names.

    pipx run .github/scripts/validate.py <base commit>
"""
import json
import subprocess
import sys
import urllib.request

import jsonschema

REPO = "https://raw.githubusercontent.com/CVEProject/cve-schema"
SCHEMA_URLS = {
    "5.0": f"{REPO}/ce5f5c865f14dc40a6548d36b74751abca1c588a/schema/archive/v5.0/docs/CVE_JSON_5.0_bundled.json",
    "5.1": f"{REPO}/cc1c0214befc0e2ccfb98c8f4306ec116f65fd34/schema/docs/CVE_Record_Format_bundled.json",  # v5.1.1
    "5.2": f"{REPO}/5533f6038cc0434e544e69240c704906d591de46/schema/docs/CVE_Record_Format_bundled.json",  # v5.2.0
}


def load_validator(url: str) -> jsonschema.protocols.Validator:
    with urllib.request.urlopen(url) as response:
        schema = json.load(response)
    cls = jsonschema.validators.validator_for(schema)
    return cls(schema, format_checker=cls.FORMAT_CHECKER)


def problem(path: str, validators: dict) -> str | None:
    try:
        with open(path) as f:
            record = json.load(f)
    except json.JSONDecodeError as e:
        return f"not valid JSON: {e}"
    version = record.get("dataVersion")
    if version not in SCHEMA_URLS:
        return f"no schema known for dataVersion {version}"
    if version not in validators:
        validators[version] = load_validator(SCHEMA_URLS[version])
    error = jsonschema.exceptions.best_match(validators[version].iter_errors(record))
    # a record is "published or rejected", so the top error just says "matched neither"; dig to the real one
    while error and error.context:
        error = jsonschema.exceptions.best_match(error.context)
    return error and f"dataVersion {version}: {error.json_path}: {error.message}"


def main(base: str) -> int:
    diff = ["git", "diff", "--name-only", "--diff-filter=AM", base, "HEAD", "--", "data/*.json"]
    changed = subprocess.check_output(diff, text=True).split()
    validators = {}
    failed = 0
    for path in changed:
        if message := problem(path, validators):
            print(f"{path}: {message}")
            failed += 1
    print(f"{len(changed)} records checked, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
