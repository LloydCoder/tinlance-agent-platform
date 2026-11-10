from __future__ import annotations

import json
import pathlib
import re
import typing


TEMPLATE_PATH = (
    pathlib.Path(__file__).parents[2]
    / "infra"
    / "aws"
    / "fcp03-durable-storage"
    / "template.json"
)


def load_template() -> dict[str, typing.Any]:
    return json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))


def test_identity_tables_are_on_demand_encrypted_ttl_enabled_and_recoverable() -> None:
    resources = load_template()["Resources"]
    for name, key_name in (
        ("TokenRevocationTable", "revocation_key"),
        ("DPoPReplayTable", "replay_key"),
    ):
        table = resources[name]
        properties = table["Properties"]
        assert table["DeletionPolicy"] == "Retain"
        assert table["UpdateReplacePolicy"] == "Retain"
        assert properties["BillingMode"] == "PAY_PER_REQUEST"
        assert properties["KeySchema"] == [{"AttributeName": key_name, "KeyType": "HASH"}]
        assert properties["TimeToLiveSpecification"] == {
            "AttributeName": "expires_at",
            "Enabled": True,
        }
        assert properties["PointInTimeRecoverySpecification"] == {
            "PointInTimeRecoveryEnabled": True
        }
        assert properties["SSESpecification"] == {
            "SSEEnabled": True,
            "SSEType": "KMS",
            "KMSMasterKeyId": {"Fn::GetAtt": ["DataKey", "Arn"]},
        }


def test_snapshot_bucket_enforces_immutable_retained_storage() -> None:
    resources = load_template()["Resources"]
    bucket = resources["SnapshotBucket"]
    properties = bucket["Properties"]

    assert bucket["DeletionPolicy"] == "Retain"
    assert bucket["UpdateReplacePolicy"] == "Retain"
    assert properties["ObjectLockEnabled"] is True
    assert properties["ObjectLockConfiguration"]["ObjectLockEnabled"] == "Enabled"
    retention = properties["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]
    assert retention == {
        "Mode": "COMPLIANCE",
        "Days": {"Ref": "SnapshotRetentionDays"},
    }
    assert properties["VersioningConfiguration"]["Status"] == "Enabled"
    encryption = properties["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]
    assert encryption["ServerSideEncryptionByDefault"] == {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": {"Fn::GetAtt": ["DataKey", "Arn"]},
    }
    assert properties["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    assert properties["OwnershipControls"]["Rules"] == [
        {"ObjectOwnership": "BucketOwnerEnforced"}
    ]


def test_kms_policy_separates_service_data_use_from_grant_creation() -> None:
    statements = load_template()["Resources"]["DataKey"]["Properties"]["KeyPolicy"][
        "Statement"
    ]
    by_sid = {statement["Sid"]: statement for statement in statements}

    assert by_sid["AccountKeyAdministration"]["Principal"]["AWS"]["Fn::Join"]
    ddb_data = by_sid["WorkloadDynamoDBDataEncryption"]
    assert "kms:CreateGrant" not in ddb_data["Action"]
    assert ddb_data["Condition"]["StringEquals"]["kms:ViaService"]["Fn::Join"]
    assert "kms:ViaService" in ddb_data["Condition"]["StringEquals"]

    ddb_grant = by_sid["WorkloadDynamoDBGrant"]
    assert ddb_grant["Action"] == "kms:CreateGrant"
    assert ddb_grant["Condition"]["Bool"]["kms:GrantIsForAWSResource"] == "true"

    s3_data = by_sid["WorkloadS3SnapshotDataEncryption"]
    assert "kms:CreateGrant" not in s3_data["Action"]
    assert "kms:ViaService" in s3_data["Condition"]["StringEquals"]
    s3_grant = by_sid["WorkloadS3SnapshotGrant"]
    assert s3_grant["Action"] == "kms:CreateGrant"
    assert s3_grant["Condition"]["Bool"]["kms:GrantIsForAWSResource"] == "true"


def test_workload_policy_is_scoped_to_the_identity_tables_snapshot_prefix_and_keys() -> None:
    resources = load_template()["Resources"]
    statements = resources["WorkloadAccessPolicy"]["Properties"]["PolicyDocument"]["Statement"]
    by_sid = {statement["Sid"]: statement for statement in statements}

    assert by_sid["TokenRevocationOperations"]["Resource"] == {
        "Fn::GetAtt": ["TokenRevocationTable", "Arn"]
    }
    assert by_sid["DPoPReplayOperations"]["Resource"] == {
        "Fn::GetAtt": ["DPoPReplayTable", "Arn"]
    }
    assert by_sid["SnapshotObjectOperations"]["Resource"]["Fn::Join"]
    assert "s3:DeleteObject" not in by_sid["SnapshotObjectOperations"]["Action"]
    assert by_sid["SnapshotHMACOperations"]["Resource"] == {
        "Fn::GetAtt": ["SigningKey", "Arn"]
    }


def test_snapshot_bucket_policy_denies_insecure_transport_wrong_encryption_and_version_delete() -> None:
    statements = load_template()["Resources"]["SnapshotBucketPolicy"]["Properties"][
        "PolicyDocument"
    ]["Statement"]
    by_sid = {statement["Sid"]: statement for statement in statements}

    assert by_sid["DenyInsecureTransport"]["Condition"]["Bool"] == {
        "aws:SecureTransport": "false"
    }
    assert by_sid["DenyUnencryptedSnapshotUploads"]["Condition"]["StringNotEquals"] == {
        "s3:x-amz-server-side-encryption": "aws:kms"
    }
    assert by_sid["DenyWrongSnapshotKMSKey"]["Condition"]["StringNotEquals"][
        "s3:x-amz-server-side-encryption-aws-kms-key-id"
    ] == {"Fn::GetAtt": ["DataKey", "Arn"]}
    assert by_sid["DenyVersionDeletion"]["Action"] == "s3:DeleteObjectVersion"
    assert by_sid["DenySnapshotObjectDeletion"]["Action"] == "s3:DeleteObject"


def test_data_key_policy_does_not_create_resource_dependency_cycles() -> None:
    policy = load_template()["Resources"]["DataKey"]["Properties"]["KeyPolicy"]
    encoded = json.dumps(policy)

    assert "TokenRevocationTable" not in encoded
    assert "DPoPReplayTable" not in encoded
    assert "SnapshotBucket" not in encoded


def test_workload_role_arn_rejects_wildcard_principals() -> None:
    pattern = load_template()["Parameters"]["WorkloadRoleArn"]["AllowedPattern"]

    assert re.fullmatch(
        pattern,
        "arn:aws:iam::123456789012:role/agent-platform-production",
    )
    assert not re.fullmatch(pattern, "arn:aws:iam::123456789012:role/*")
