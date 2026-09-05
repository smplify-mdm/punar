#!/usr/bin/env python3
"""Focused regression checks for the platform-specific install-plan layouts."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


REPO = Path(__file__).resolve().parents[2]
SCHEMAS = REPO / "schemas"
PLAN_SCHEMA = SCHEMAS / "install/plan.json"
UEFI_EXAMPLE = SCHEMAS / "install/examples/install-plan.json"
PI_EXAMPLE = SCHEMAS / "install/examples/install-plan-raspberry-pi.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def registry() -> Registry:
    result = Registry()
    for path in sorted(SCHEMAS.rglob("*.json")):
        if "examples" in path.relative_to(SCHEMAS).parts:
            continue
        schema = load(path)
        if schema_id := schema.get("$id"):
            result = result.with_resource(schema_id, Resource.from_contents(schema))
    return result


def retoken(document: dict) -> None:
    canonical = json.dumps(
        document["plan"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    document["plan_token"] = hashlib.sha256(canonical).hexdigest()


def assert_valid(validator: Draft202012Validator, name: str, document: dict) -> None:
    errors = list(validator.iter_errors(document))
    assert not errors, f"{name} should validate: {errors[0].message if errors else ''}"
    expected = document["plan_token"]
    retoken(document)
    assert document["plan_token"] == expected, f"{name} has a stale plan_token"


def assert_invalid(validator: Draft202012Validator, name: str, document: dict) -> None:
    retoken(document)
    errors = list(validator.iter_errors(document))
    assert errors, f"{name} should fail structural validation"


def assert_non_overlapping(name: str, document: dict) -> None:
    partitions = document["plan"]["partitions"]
    previous_end = 0
    for partition in partitions:
        assert partition["offset_bytes"] >= previous_end, (
            f"{name} partition {partition['number']} overlaps its predecessor"
        )
        previous_end = partition["offset_bytes"] + partition["size_bytes"]
    assert previous_end <= document["plan"]["disk"]["size_bytes"], (
        f"{name} layout exceeds its bound disk"
    )


def different_fixed_value(field: str, current: object) -> object:
    if field == "number":
        return int(current) + 1
    if field in {"offset_bytes", "size_bytes"}:
        return int(current) + 4096
    if field == "name":
        return "PUNAR-ESP" if current != "PUNAR-ESP" else "PUNAR-DATA"
    if field in {"type_guid", "partuuid"}:
        return "ffffffff-ffff-ffff-ffff-ffffffffffff"
    if field == "filesystem":
        return "ext4" if current != "ext4" else "vfat"
    if field == "encrypted":
        return not bool(current)
    raise AssertionError(f"no mutation for fixed field {field}")


def assert_every_fixed_partition_field_is_bound(
    validator: Draft202012Validator, name: str, document: dict
) -> None:
    for index, partition in enumerate(document["plan"]["partitions"]):
        fixed_fields = [
            "number",
            "name",
            "type_guid",
            "partuuid",
            "offset_bytes",
            "filesystem",
            "encrypted",
        ]
        if partition["name"] != "PUNAR-DATA":
            fixed_fields.append("size_bytes")
        for field in fixed_fields:
            mutated = copy.deepcopy(document)
            target = mutated["plan"]["partitions"][index]
            if field == "filesystem" and field not in partition:
                target[field] = "ext4"
            else:
                target[field] = different_fixed_value(field, partition[field])
            assert_invalid(
                validator,
                f"{name} partition {index + 1} mutated fixed {field}",
                mutated,
            )


def main() -> None:
    validator = Draft202012Validator(load(PLAN_SCHEMA), registry=registry())
    uefi = load(UEFI_EXAMPLE)
    raspberry_pi = load(PI_EXAMPLE)

    assert_valid(validator, "UEFI example", uefi)
    assert_valid(validator, "Raspberry Pi example", raspberry_pi)
    assert_non_overlapping("UEFI example", uefi)
    assert_non_overlapping("Raspberry Pi example", raspberry_pi)
    assert len(raspberry_pi["plan"]["partitions"]) == 6

    assert_every_fixed_partition_field_is_bound(validator, "UEFI", uefi)
    assert_every_fixed_partition_field_is_bound(
        validator, "Raspberry Pi", raspberry_pi
    )

    uefi_arm = copy.deepcopy(uefi)
    uefi_arm["plan"]["architecture"] = "aarch64"
    for index in (1, 2):
        uefi_arm["plan"]["partitions"][index]["type_guid"] = (
            "b921b045-1df0-41c3-af44-4c6f280d3fae"
        )
    retoken(uefi_arm)
    assert_valid(validator, "aarch64 UEFI layout", uefi_arm)

    mixed_root_guid = copy.deepcopy(uefi_arm)
    mixed_root_guid["plan"]["partitions"][2]["type_guid"] = (
        "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
    )
    assert_invalid(validator, "mixed-architecture UEFI root GUIDs", mixed_root_guid)

    obsolete_pi = copy.deepcopy(raspberry_pi)
    obsolete_pi["plan"]["partitions"] = obsolete_pi["plan"]["partitions"][1:]
    for number, partition in enumerate(obsolete_pi["plan"]["partitions"], start=1):
        partition["number"] = number
    assert_invalid(validator, "obsolete five-partition Raspberry Pi layout", obsolete_pi)

    for name, document in [("UEFI", uefi), ("Raspberry Pi", raspberry_pi)]:
        reordered = copy.deepcopy(document)
        reordered["plan"]["partitions"][0:2] = reversed(
            reordered["plan"]["partitions"][0:2]
        )
        assert_invalid(validator, f"reordered {name} layout", reordered)

        too_small_data = copy.deepcopy(document)
        too_small_data["plan"]["partitions"][-1]["size_bytes"] = 17179869183
        assert_invalid(validator, f"undersized {name} data partition", too_small_data)

        exact_data_floor = copy.deepcopy(document)
        exact_data_floor["plan"]["partitions"][-1]["size_bytes"] = 17179869184
        retoken(exact_data_floor)
        assert_valid(validator, f"{name} exact 16-GiB data floor", exact_data_floor)

        unencrypted = copy.deepcopy(document)
        unencrypted["plan"]["encryption"] = "none"
        unencrypted["plan"]["partitions"][-1]["encrypted"] = False
        retoken(unencrypted)
        assert_valid(validator, f"unencrypted {name} layout", unencrypted)

        inconsistent_encryption = copy.deepcopy(unencrypted)
        inconsistent_encryption["plan"]["partitions"][-1]["encrypted"] = True
        assert_invalid(
            validator,
            f"{name} data encryption inconsistent with plan",
            inconsistent_encryption,
        )

        overlapping_data = copy.deepcopy(document)
        prior = overlapping_data["plan"]["partitions"][-2]
        overlapping_data["plan"]["partitions"][-1]["offset_bytes"] = (
            prior["offset_bytes"] + prior["size_bytes"] - 4096
        )
        assert_invalid(validator, f"overlapping {name} data partition", overlapping_data)

    pi_wrong_architecture = copy.deepcopy(raspberry_pi)
    pi_wrong_architecture["plan"]["architecture"] = "x86_64"
    assert_invalid(validator, "x86_64 Raspberry Pi layout", pi_wrong_architecture)

    unsupported_sector = copy.deepcopy(uefi)
    unsupported_sector["plan"]["disk"]["logical_sector_bytes"] = 32768
    assert_invalid(validator, "sector size incompatible with fixed offsets", unsupported_sector)

    missing_recovery_pair = copy.deepcopy(uefi)
    del missing_recovery_pair["plan"]["recovery_payload"]
    assert_invalid(validator, "UEFI plan missing recovery payload", missing_recovery_pair)

    pi_with_uefi_recovery_pair = copy.deepcopy(raspberry_pi)
    pi_with_uefi_recovery_pair["plan"]["recovery_payload"] = copy.deepcopy(
        uefi["plan"]["recovery_payload"]
    )
    pi_with_uefi_recovery_pair["plan"]["recovery_boot_artifact"] = copy.deepcopy(
        uefi["plan"]["recovery_boot_artifact"]
    )
    assert_invalid(
        validator,
        "Raspberry Pi plan carrying UEFI recovery artifacts",
        pi_with_uefi_recovery_pair,
    )

    print(
        "install-plan-schema: PASS "
        "(exact UEFI/Pi fields, encryption, non-overlap and architecture)"
    )


if __name__ == "__main__":
    main()
