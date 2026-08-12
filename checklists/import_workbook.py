#!/usr/bin/env python3

"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Checklist Workbook Importer (skeleton)

Purpose
-------
Converts the manager's assessment checklist / attack-path workbook (.xlsx or
.csv) into the checklists/*.yaml schema the Checklist Validation Engine
consumes. COLUMN_MAP below is a placeholder aligned to checklists/README.md -
update it once the real workbook's actual column headers are known.

Usage
-----
python3 checklists/import_workbook.py --input <workbook.xlsx> --output checklists/checklist.yaml
===============================================================================
"""

import argparse
import csv
from pathlib import Path

import yaml


# TODO: update these keys to match the real workbook's column headers once
# it is shared. Left-hand side = workbook column header, right-hand side =
# checklist.yaml field name (see checklists/README.md).
COLUMN_MAP = {

    "Checklist ID": "id",
    "Control": "title",
    "Tool": "tool",
    "Query Reference": "query_ref",
    "Expected Evidence": "expected_evidence",
    "Manual Validation Required": "manual_validation_required",
    "MITRE Mapping": "mitre_mapping",
    "Threat Scenario": "threat_scenario",
    "Related Attack Paths": "related_attack_paths",

}

TRUE_VALUES = {"yes", "y", "true", "1"}


def parse_bool(value):

    return str(value).strip().lower() in TRUE_VALUES


def parse_mitre_mapping(value):

    # Placeholder representation until the workbook's actual format is
    # known: "Tactic:TechniqueID:Technique Name; ..." pairs, one per
    # mapping entry. Update once the real column format is confirmed.

    if not value:

        return []

    mappings = []

    for entry in str(value).split(";"):

        entry = entry.strip()

        if not entry:

            continue

        parts = [p.strip() for p in entry.split(":")]

        if len(parts) == 3:

            mappings.append({

                "tactic": parts[0],
                "technique_id": parts[1],
                "technique": parts[2],

            })

    return mappings


def read_csv(path):

    with open(path, newline="", encoding="utf-8") as f:

        return list(csv.DictReader(f))


def read_xlsx(path):

    import openpyxl

    workbook = openpyxl.load_workbook(path, data_only=True)

    sheet = workbook.active

    rows = list(sheet.iter_rows(values_only=True))

    if not rows:

        return []

    headers = [str(h).strip() if h is not None else "" for h in rows[0]]

    records = []

    for row in rows[1:]:

        record = dict(zip(headers, row))

        records.append(record)

    return records


def convert(records):

    checklist = []

    for record in records:

        item = {}

        for workbook_column, field in COLUMN_MAP.items():

            item[field] = record.get(workbook_column)

        item["manual_validation_required"] = parse_bool(
            item.get("manual_validation_required")
        )

        item["mitre_mapping"] = parse_mitre_mapping(
            item.get("mitre_mapping")
        )

        for text_field in (
            "id",
            "title",
            "tool",
            "query_ref",
            "expected_evidence",
            "threat_scenario",
            "related_attack_paths",
        ):

            if item.get(text_field) is None:

                item[text_field] = ""

            else:

                item[text_field] = str(item[text_field]).strip()

        if item.get("tool"):

            item["tool"] = item["tool"].lower()

        checklist.append(item)

    return checklist


def main():

    parser = argparse.ArgumentParser(
        description="Convert an assessment checklist workbook into checklists/*.yaml"
    )

    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="checklists/checklist.yaml")

    args = parser.parse_args()

    input_path = Path(args.input)

    if input_path.suffix.lower() == ".csv":

        records = read_csv(input_path)

    elif input_path.suffix.lower() in (".xlsx", ".xlsm"):

        records = read_xlsx(input_path)

    else:

        raise ValueError(
            f"Unsupported workbook format: {input_path.suffix}"
        )

    checklist = convert(records)

    output_path = Path(args.output)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:

        yaml.safe_dump(
            {"checklist": checklist},
            f,
            sort_keys=False,
        )

    print(
        f"Imported {len(checklist)} checklist items -> {output_path}"
    )


if __name__ == "__main__":

    main()
