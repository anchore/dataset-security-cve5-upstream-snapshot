# /// script
# dependencies = ["jsonschema-rs==0.61.2"]
# ///
"""Validate the data/ json files changed since a commit against the CVE schema version each file names.

    pipx run .github/scripts/validate.py --base-commit <base commit>
"""
import argparse
import json
import logging
import shlex
import subprocess
import sys
import urllib.request

from typing import Any

import jsonschema_rs

logger = logging.getLogger("schema-validator")

# records here are full CVE records, so the schema is used as published
FRAGMENTS = False

REPO = "https://raw.githubusercontent.com/CVEProject/cve-schema"
SCHEMA_URLS = {
    "5.0": f"{REPO}/ce5f5c865f14dc40a6548d36b74751abca1c588a/schema/archive/v5.0/docs/CVE_JSON_5.0_bundled.json",
    "5.1": f"{REPO}/cc1c0214befc0e2ccfb98c8f4306ec116f65fd34/schema/docs/CVE_Record_Format_bundled.json",  # v5.1.1
    "5.2": f"{REPO}/5533f6038cc0434e544e69240c704906d591de46/schema/docs/CVE_Record_Format_bundled.json",  # v5.2.0
}


def relax(node) -> None:
    # fragments have no providerMetadata, wherever a schema version requires it
    if isinstance(node, dict):
        if "providerMetadata" in node.get("required", []):
            node["required"] = [key for key in node["required"] if key != "providerMetadata"]
        for value in node.values():
            relax(value)
    elif isinstance(node, list):
        for value in node:
            relax(value)


def load_validator(url: str) -> jsonschema_rs.Validator:
    logger.debug(f"loading: {url}")
    with urllib.request.urlopen(url) as response:
        schema = json.load(response)

    # The uri format type is too strict here as there are urls in the dataset that 
    # are invalid per the spec but correct ie git://
    schema.get("definitions", {}).get("uriType", {}).pop("format", None)

    if FRAGMENTS:
        relax(schema)
        # and their tags can be empty
        schema.get("definitions", {}).get("cnaTags", {}).pop("minItems", None)
    return jsonschema_rs.validator_for(schema)
    #return cls(schema, format_checker=cls.FORMAT_CHECKER)


def validate_json_file(path: str, validators: dict) -> list[Any] | None:
    try:
        with open(path) as f:
            record = json.load(f)
    except json.JSONDecodeError as e:
        return f"not valid JSON: {e}"
    # rejected fragments intentionally keep "affected": [], even though the upstream schema forbids it.  This
    # is because we MAY choose to unreject something on our side and want all of the components to compare to
    if FRAGMENTS and "rejectedReasons" in record.get("containers", {}).get("cna", {}):
        return None
    version = record.get("dataVersion")
    if version not in SCHEMA_URLS:
        return f"no schema known for dataVersion {version}"
    if version not in validators:
        validators[version] = load_validator(SCHEMA_URLS[version])

    result = validators[version].evaluate(record)
    return result.errors()


def main(base_commit: str | None) -> int:
    file_paths_command = "git ls-files --directory data"
    if base_commit:
        file_paths_command = f"git diff --name-only --diff-filter=AM {base_commit} HEAD -- data/"
    
    changed = subprocess.check_output(shlex.split(file_paths_command), text=True).split()
    validators = {}
    failed = 0
    for path in changed:
        logger.debug(f"validating: {path}")        
        if errors := validate_json_file(path, validators):
            for error in errors:
                logger.error(f"{path}: {json.dumps(error)}")
                failed += 1
    logger.info(f"{len(changed)} records checked, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='Schema Validator',
        description='Validates records in the repository against the relevant CVE Schema',
    )    
    parser.add_argument("--base-commit", required=False)
    parser.add_argument("-v", "--verbose", required=False, action='store_true')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    sys.exit(main(args.base_commit))
