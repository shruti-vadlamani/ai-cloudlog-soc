"""
event_templates.py
==================
Defines the exact CloudTrail JSON structure for every API call
simulated in this project. Templates are modeled directly from:
  - AWS CloudTrail Log Event Reference (official documentation)
  - Flaws.cloud published CloudTrail samples
  - Rhino Security Labs CloudGoat attack logs

Each template is a callable that accepts context parameters and
returns a complete CloudTrail event dict, ready to be serialized.

Structure mirrors real CloudTrail output exactly:
  - userIdentity (nested, type-aware)
  - requestParameters (per-API, documented fields only)
  - responseElements (None for read-ops where AWS omits it)
  - errorCode / errorMessage (only present on failures)
"""

import uuid
import random
from datetime import datetime


# ── Helpers ──────────────────────────────────────────────────────────────────

def _event_id() -> str:
    return str(uuid.uuid4())


def _request_id() -> str:
    return str(uuid.uuid4()).replace("-", "").upper()[:16]


def _arn(account_id: str, region: str, username: str) -> str:
    return f"arn:aws:iam::{account_id}:user/{username}"


def _assumed_role_arn(account_id: str, role: str, session: str) -> str:
    return f"arn:aws:sts::{account_id}:assumed-role/{role}/{session}"


def _user_identity_iam_user(username: str, account_id: str, region: str) -> dict:
    """Standard IAM user identity block."""
    return {
        "type": "IAMUser",
        "principalId": username.upper().replace("-", ""),
        "arn": _arn(account_id, region, username),
        "accountId": account_id,
        "accessKeyId": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
        "userName": username,
        "sessionContext": {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {
                "creationDate": "2024-01-15T06:00:00Z",
                "mfaAuthenticated": "false"
            }
        }
    }


def _user_identity_assumed_role(username: str, account_id: str, role_name: str) -> dict:
    """AssumedRole identity block — used by cicd-bot."""
    session_name = f"{username}-session"
    return {
        "type": "AssumedRole",
        "principalId": f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}:{session_name}",
        "arn": _assumed_role_arn(account_id, role_name, session_name),
        "accountId": account_id,
        "accessKeyId": f"ASIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
                "arn": f"arn:aws:iam::{account_id}:role/{role_name}",
                "accountId": account_id,
                "userName": role_name
            },
            "webIdFederationData": {},
            "attributes": {
                "creationDate": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "mfaAuthenticated": "false"
            }
        }
    }


def _base_event(
    event_time: datetime,
    event_name: str,
    event_source: str,
    username: str,
    account_id: str,
    region: str,
    source_ip: str,
    user_agent: str,
    is_cicd: bool = False
) -> dict:
    """Base CloudTrail record. All templates build on this."""
    if is_cicd:
        user_identity = _user_identity_assumed_role(username, account_id, "CICDDeployRole")
    else:
        user_identity = _user_identity_iam_user(username, account_id, region)

    return {
        "eventVersion": "1.09",
        "userIdentity": user_identity,
        "eventTime": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userAgent": user_agent,
        "requestID": _request_id(),
        "eventID": _event_id(),
        "readOnly": True,   # overridden per-template
        "eventType": "AwsApiCall",
        "managementEvent": False,
        "recipientAccountId": account_id,
        "requestParameters": None,
        "responseElements": None
    }


# ── User Agent Strings ────────────────────────────────────────────────────────

USER_AGENTS = {
    "aws-cli": [
        "aws-cli/2.15.10 Python/3.11.6 Linux/5.15.0 botocore/2.4.5",
        "aws-cli/2.13.5 Python/3.10.12 Linux/6.1.0 botocore/2.1.0",
    ],
    "boto3": [
        "Boto3/1.34.11 Python/3.11.6 Linux/5.15.0 Botocore/1.34.11",
        "Boto3/1.28.57 Python/3.10.8 Linux/5.4.0 Botocore/1.28.57",
    ],
    "console": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "signin.amazonaws.com"
    ]
}


def get_user_agent(style: str) -> str:
    return random.choice(USER_AGENTS.get(style, USER_AGENTS["boto3"]))


# ── S3 Templates ─────────────────────────────────────────────────────────────

def s3_get_object(ctx: dict, bucket: str, key: str, error: bool = False) -> dict:
    ev = _base_event(**ctx, event_name="GetObject", event_source="s3.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = False
    ev["requestParameters"] = {
        "bucketName": bucket,
        "key": key
    }
    if not error:
        ev["responseElements"] = None
        ev["additionalEventData"] = {
            "byteTransferredIn": 0,
            "byteTransferredOut": random.randint(1024, 52428800),  # 1KB-50MB
            "x-amz-id-2": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=52))
        }
    else:
        ev["errorCode"] = "AccessDenied"
        ev["errorMessage"] = "Access Denied"
    return ev


def s3_put_object(ctx: dict, bucket: str, key: str, error: bool = False) -> dict:
    ev = _base_event(**ctx, event_name="PutObject", event_source="s3.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = False
    ev["requestParameters"] = {
        "bucketName": bucket,
        "key": key,
        "ContentType": random.choice(["application/json", "text/csv", "application/octet-stream"]),
        "x-amz-server-side-encryption": "aws:kms"
    }
    if not error:
        ev["responseElements"] = {
            "x-amz-server-side-encryption": "aws:kms",
            "x-amz-version-id": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))
        }
    else:
        ev["errorCode"] = "AccessDenied"
        ev["errorMessage"] = "Access Denied"
    return ev


def s3_delete_object(ctx: dict, bucket: str, key: str) -> dict:
    ev = _base_event(**ctx, event_name="DeleteObject", event_source="s3.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = False
    ev["requestParameters"] = {
        "bucketName": bucket,
        "key": key
    }
    ev["responseElements"] = None
    return ev


def s3_delete_objects_batch(ctx: dict, bucket: str, keys: list) -> dict:
    """DeleteObjects (batch) — used in insider threat scenario."""
    ev = _base_event(**ctx, event_name="DeleteObjects", event_source="s3.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = False
    ev["requestParameters"] = {
        "bucketName": bucket,
        "delete": {
            "objects": [{"key": k} for k in keys],
            "quiet": False
        }
    }
    ev["responseElements"] = {
        "DeleteResult": {
            "Deleted": [{"Key": k} for k in keys]
        }
    }
    return ev


def s3_delete_bucket(ctx: dict, bucket: str) -> dict:
    ev = _base_event(**ctx, event_name="DeleteBucket", event_source="s3.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = True
    ev["requestParameters"] = {"bucketName": bucket}
    ev["responseElements"] = None
    return ev


def s3_list_objects_v2(ctx: dict, bucket: str, prefix: str = "") -> dict:
    ev = _base_event(**ctx, event_name="ListObjectsV2", event_source="s3.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = False
    ev["requestParameters"] = {
        "bucketName": bucket,
        "prefix": prefix,
        "delimiter": "/",
        "encodingType": "url",
        "max-keys": "1000"
    }
    ev["responseElements"] = None
    return ev


def s3_list_buckets(ctx: dict) -> dict:
    ev = _base_event(**ctx, event_name="ListBuckets", event_source="s3.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = None
    ev["responseElements"] = {
        "buckets": {"items": []},
        "owner": {"displayName": ctx["username"], "id": ''.join(random.choices('abcdef0123456789', k=64))}
    }
    return ev


def s3_head_object(ctx: dict, bucket: str, key: str) -> dict:
    ev = _base_event(**ctx, event_name="HeadObject", event_source="s3.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = False
    ev["requestParameters"] = {"bucketName": bucket, "key": key}
    ev["responseElements"] = None
    return ev


def s3_get_bucket_policy(ctx: dict, bucket: str) -> dict:
    ev = _base_event(**ctx, event_name="GetBucketPolicy", event_source="s3.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"bucketName": bucket, "policy": ""}
    ev["responseElements"] = None
    return ev


def s3_put_bucket_policy(ctx: dict, bucket: str) -> dict:
    ev = _base_event(**ctx, event_name="PutBucketPolicy", event_source="s3.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = True
    ev["requestParameters"] = {"bucketName": bucket, "policy": ""}
    ev["responseElements"] = None
    return ev


# ── IAM Templates ─────────────────────────────────────────────────────────────

def iam_list_users(ctx: dict, error: bool = False) -> dict:
    ev = _base_event(**ctx, event_name="ListUsers", event_source="iam.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"maxItems": 100}
    if not error:
        ev["responseElements"] = None
    else:
        ev["errorCode"] = "AccessDenied"
        ev["errorMessage"] = "User is not authorized to perform iam:ListUsers"
    return ev


def iam_list_roles(ctx: dict) -> dict:
    ev = _base_event(**ctx, event_name="ListRoles", event_source="iam.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"maxItems": 100}
    ev["responseElements"] = None
    return ev


def iam_list_policies(ctx: dict) -> dict:
    ev = _base_event(**ctx, event_name="ListPolicies", event_source="iam.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"scope": "Local", "onlyAttached": False, "maxItems": 100}
    ev["responseElements"] = None
    return ev


def iam_list_attached_user_policies(ctx: dict, target_username: str) -> dict:
    ev = _base_event(**ctx, event_name="ListAttachedUserPolicies", event_source="iam.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"userName": target_username}
    ev["responseElements"] = None
    return ev


def iam_list_groups_for_user(ctx: dict, target_username: str) -> dict:
    ev = _base_event(**ctx, event_name="ListGroupsForUser", event_source="iam.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"userName": target_username}
    ev["responseElements"] = None
    return ev


def iam_get_account_authorization_details(ctx: dict) -> dict:
    ev = _base_event(**ctx, event_name="GetAccountAuthorizationDetails", event_source="iam.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"filter": ["User", "Role", "Group", "LocalManagedPolicy"]}
    ev["responseElements"] = None
    return ev


def iam_get_user(ctx: dict, target_username: str = None) -> dict:
    ev = _base_event(**ctx, event_name="GetUser", event_source="iam.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"userName": target_username or ctx["username"]}
    ev["responseElements"] = None
    return ev


def iam_create_access_key(ctx: dict, target_username: str) -> dict:
    """Attack template: CreateAccessKey — privilege escalation + backdoor."""
    ev = _base_event(**ctx, event_name="CreateAccessKey", event_source="iam.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = True
    ev["requestParameters"] = {"userName": target_username}
    ev["responseElements"] = {
        "accessKey": {
            "accessKeyId": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
            "status": "Active",
            "userName": target_username,
            "createDate": "2026-02-17T20:30:00Z"
        }
    }
    return ev


def iam_attach_user_policy(ctx: dict, target_username: str, policy_arn: str) -> dict:
    """Attack template: AttachUserPolicy — privilege escalation."""
    ev = _base_event(**ctx, event_name="AttachUserPolicy", event_source="iam.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = True
    ev["requestParameters"] = {
        "userName": target_username,
        "policyArn": policy_arn
    }
    ev["responseElements"] = None
    return ev


def iam_create_user(ctx: dict, new_username: str) -> dict:
    """Attack template: CreateUser — privilege escalation."""
    ev = _base_event(**ctx, event_name="CreateUser", event_source="iam.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = True
    ev["requestParameters"] = {
        "userName": new_username,
        "tags": []
    }
    ev["responseElements"] = {
        "user": {
            "path": "/",
            "userName": new_username,
            "userId": f"AIDA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
            "arn": f"arn:aws:iam::{ctx['account_id']}:user/{new_username}",
            "createDate": "2026-02-17T20:32:00Z"
        }
    }
    return ev


def iam_create_login_profile(ctx: dict, target_username: str) -> dict:
    """Attack template: CreateLoginProfile — backdoor creation."""
    ev = _base_event(**ctx, event_name="CreateLoginProfile", event_source="iam.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = True
    ev["requestParameters"] = {
        "userName": target_username,
        "passwordResetRequired": False
    }
    ev["responseElements"] = {
        "loginProfile": {
            "userName": target_username,
            "createDate": "2026-02-25T21:45:00Z",
            "passwordResetRequired": False
        }
    }
    return ev


def iam_put_user_policy(ctx: dict, target_username: str, policy_name: str) -> dict:
    ev = _base_event(**ctx, event_name="PutUserPolicy", event_source="iam.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = True
    ev["requestParameters"] = {
        "userName": target_username,
        "policyName": policy_name,
        "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
    }
    ev["responseElements"] = None
    return ev


def iam_assume_role(ctx: dict, role_arn: str, session_name: str) -> dict:
    ev = _base_event(**ctx, event_name="AssumeRole", event_source="sts.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = True
    ev["requestParameters"] = {
        "roleArn": role_arn,
        "roleSessionName": session_name,
        "durationSeconds": 3600
    }
    ev["responseElements"] = {
        "credentials": {
            "accessKeyId": f"ASIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
            "sessionToken": ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=', k=100)),
            "expiration": "2026-02-17T22:00:00Z"
        },
        "assumedRoleUser": {
            "assumedRoleId": f"AROA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}:{session_name}",
            "arn": role_arn.replace(":role/", ":assumed-role/") + f"/{session_name}"
        }
    }
    return ev


def iam_get_role(ctx: dict, role_name: str) -> dict:
    ev = _base_event(**ctx, event_name="GetRole", event_source="iam.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"roleName": role_name}
    ev["responseElements"] = None
    return ev


def iam_list_access_keys(ctx: dict, target_username: str) -> dict:
    ev = _base_event(**ctx, event_name="ListAccessKeys", event_source="iam.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"userName": target_username}
    ev["responseElements"] = None
    return ev


# ── Lambda Templates ──────────────────────────────────────────────────────────

def lambda_list_functions(ctx: dict) -> dict:
    ev = _base_event(**ctx, event_name="ListFunctions20150331", event_source="lambda.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = None
    ev["responseElements"] = None
    return ev


def lambda_invoke(ctx: dict, function_name: str, error: bool = False) -> dict:
    ev = _base_event(**ctx, event_name="Invoke", event_source="lambda.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = False
    ev["requestParameters"] = {
        "functionName": function_name,
        "invocationType": "RequestResponse"
    }
    if not error:
        ev["responseElements"] = None
    else:
        ev["errorCode"] = "ResourceNotFoundException"
        ev["errorMessage"] = f"Function not found: {function_name}"
    return ev


def lambda_get_function(ctx: dict, function_name: str) -> dict:
    ev = _base_event(**ctx, event_name="GetFunction20150331", event_source="lambda.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"functionName": function_name}
    ev["responseElements"] = None
    return ev


def lambda_update_function_code(ctx: dict, function_name: str) -> dict:
    ev = _base_event(**ctx, event_name="UpdateFunctionCode20150331v2", event_source="lambda.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = True
    ev["requestParameters"] = {
        "functionName": function_name,
        "s3Bucket": "company-app-assets",
        "s3Key": f"lambda/{function_name}/deployment.zip"
    }
    ev["responseElements"] = {"functionName": function_name, "lastModified": "2026-02-17T10:00:00Z"}
    return ev


# ── EC2 Templates ─────────────────────────────────────────────────────────────

def ec2_describe_instances(ctx: dict) -> dict:
    ev = _base_event(**ctx, event_name="DescribeInstances", event_source="ec2.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = False
    ev["requestParameters"] = {
        "filterSet": {},
        "instancesSet": {}
    }
    ev["responseElements"] = None
    return ev


def ec2_describe_security_groups(ctx: dict) -> dict:
    ev = _base_event(**ctx, event_name="DescribeSecurityGroups", event_source="ec2.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = False
    ev["requestParameters"] = {"filterSet": {}, "securityGroupIdSet": {}}
    ev["responseElements"] = None
    return ev


def ec2_describe_vpcs(ctx: dict) -> dict:
    ev = _base_event(**ctx, event_name="DescribeVpcs", event_source="ec2.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = False
    ev["requestParameters"] = {"filterSet": {}, "vpcSet": {}}
    ev["responseElements"] = None
    return ev


# ── CloudWatch Templates ──────────────────────────────────────────────────────

def cloudwatch_put_metric_data(ctx: dict, namespace: str) -> dict:
    ev = _base_event(**ctx, event_name="PutMetricData", event_source="monitoring.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = False
    ev["requestParameters"] = {
        "namespace": namespace,
        "metricData": [{"metricName": "Requests", "value": random.randint(1, 1000), "unit": "Count"}]
    }
    ev["responseElements"] = None
    return ev


def cloudwatch_describe_alarms(ctx: dict) -> dict:
    ev = _base_event(**ctx, event_name="DescribeAlarms", event_source="monitoring.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"maxRecords": 100}
    ev["responseElements"] = None
    return ev


def cloudwatch_get_metric_statistics(ctx: dict, namespace: str, metric_name: str) -> dict:
    ev = _base_event(**ctx, event_name="GetMetricStatistics", event_source="monitoring.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = False
    ev["requestParameters"] = {
        "namespace": namespace,
        "metricName": metric_name,
        "period": 300,
        "statistics": ["Sum", "Average"]
    }
    ev["responseElements"] = None
    return ev


def cloudwatch_put_metric_alarm(ctx: dict, alarm_name: str) -> dict:
    ev = _base_event(**ctx, event_name="PutMetricAlarm", event_source="monitoring.amazonaws.com")
    ev["readOnly"] = False
    ev["managementEvent"] = True
    ev["requestParameters"] = {
        "alarmName": alarm_name,
        "comparisonOperator": "GreaterThanThreshold",
        "evaluationPeriods": 2,
        "threshold": 90.0
    }
    ev["responseElements"] = None
    return ev


# ── CloudTrail Templates ──────────────────────────────────────────────────────

def cloudtrail_lookup_events(ctx: dict) -> dict:
    ev = _base_event(**ctx, event_name="LookupEvents", event_source="cloudtrail.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"maxResults": 50}
    ev["responseElements"] = None
    return ev


def cloudtrail_describe_trails(ctx: dict) -> dict:
    ev = _base_event(**ctx, event_name="DescribeTrails", event_source="cloudtrail.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"includeShadowTrails": True}
    ev["responseElements"] = None
    return ev


def cloudtrail_get_trail_status(ctx: dict, trail_name: str) -> dict:
    ev = _base_event(**ctx, event_name="GetTrailStatus", event_source="cloudtrail.amazonaws.com")
    ev["readOnly"] = True
    ev["managementEvent"] = True
    ev["requestParameters"] = {"name": trail_name}
    ev["responseElements"] = None
    return ev


# ── Template Registry ─────────────────────────────────────────────────────────
# Maps (event_source_short, event_name) -> template function
# Used by normal_traffic_generator to pick realistic events per persona

TEMPLATE_REGISTRY = {
    "s3": {
        "GetObject": s3_get_object,
        "PutObject": s3_put_object,
        "ListObjectsV2": s3_list_objects_v2,
        "ListBuckets": s3_list_buckets,
        "HeadObject": s3_head_object,
        "GetBucketPolicy": s3_get_bucket_policy,
    },
    "iam": {
        "ListUsers": iam_list_users,
        "ListRoles": iam_list_roles,
        "ListPolicies": iam_list_policies,
        "GetUser": iam_get_user,
        "ListAttachedUserPolicies": iam_list_attached_user_policies,
        "ListGroupsForUser": iam_list_groups_for_user,
        "GetRole": iam_get_role,
        "ListAccessKeys": iam_list_access_keys,
        "AssumeRole": iam_assume_role,
    },
    "lambda": {
        "ListFunctions": lambda_list_functions,
        "Invoke": lambda_invoke,
        "GetFunction": lambda_get_function,
        "UpdateFunctionCode": lambda_update_function_code,
    },
    "ec2": {
        "DescribeInstances": ec2_describe_instances,
        "DescribeSecurityGroups": ec2_describe_security_groups,
        "DescribeVpcs": ec2_describe_vpcs,
    },
    "cloudwatch": {
        "PutMetricData": cloudwatch_put_metric_data,
        "DescribeAlarms": cloudwatch_describe_alarms,
        "GetMetricStatistics": cloudwatch_get_metric_statistics,
        "PutMetricAlarm": cloudwatch_put_metric_alarm,
    },
    "cloudtrail": {
        "LookupEvents": cloudtrail_lookup_events,
        "DescribeTrails": cloudtrail_describe_trails,
        "GetTrailStatus": cloudtrail_get_trail_status,
    }
}

# Per-persona probability distribution over event types within each service
# Weights are relative (normalized internally by normal_traffic_generator)
PERSONA_EVENT_WEIGHTS = {
    "alice-dev": {
        "s3": {"GetObject": 0.35, "PutObject": 0.30, "ListObjectsV2": 0.20, "HeadObject": 0.10, "ListBuckets": 0.05},
        "iam": {"GetUser": 0.50, "ListAttachedUserPolicies": 0.30, "ListGroupsForUser": 0.20},
        "lambda": {"Invoke": 0.50, "ListFunctions": 0.30, "GetFunction": 0.20},
        "ec2": {"DescribeInstances": 0.60, "DescribeSecurityGroups": 0.40},
        "cloudwatch": {"PutMetricData": 0.40, "GetMetricStatistics": 0.35, "DescribeAlarms": 0.25},
        "cloudtrail": {"LookupEvents": 0.50, "DescribeTrails": 0.50},
    },
    "bob-devops": {
        "s3": {"GetObject": 0.25, "PutObject": 0.25, "ListObjectsV2": 0.30, "ListBuckets": 0.10, "GetBucketPolicy": 0.10},
        "iam": {"ListUsers": 0.30, "GetRole": 0.30, "AssumeRole": 0.20, "ListRoles": 0.20},
        "lambda": {"ListFunctions": 0.40, "UpdateFunctionCode": 0.30, "GetFunction": 0.30},
        "ec2": {"DescribeInstances": 0.40, "DescribeSecurityGroups": 0.30, "DescribeVpcs": 0.30},
        "cloudwatch": {"DescribeAlarms": 0.40, "GetMetricStatistics": 0.35, "PutMetricAlarm": 0.25},
        "cloudtrail": {"DescribeTrails": 0.60, "GetTrailStatus": 0.40},
    },
    "carol-sec": {
        "s3": {"GetBucketPolicy": 0.40, "ListBuckets": 0.35, "ListObjectsV2": 0.25},
        "iam": {"ListUsers": 0.25, "ListRoles": 0.20, "ListPolicies": 0.20, "GetUser": 0.15, "ListAttachedUserPolicies": 0.20},
        "lambda": {"ListFunctions": 0.60, "GetFunction": 0.40},
        "ec2": {"DescribeInstances": 0.50, "DescribeSecurityGroups": 0.50},
        "cloudwatch": {"DescribeAlarms": 0.50, "GetMetricStatistics": 0.50},
        "cloudtrail": {"LookupEvents": 0.40, "DescribeTrails": 0.35, "GetTrailStatus": 0.25},
    },
    "dave-admin": {
        "s3": {"GetBucketPolicy": 0.30, "ListBuckets": 0.30, "ListObjectsV2": 0.25, "GetObject": 0.15},
        "iam": {"ListUsers": 0.20, "ListRoles": 0.20, "ListPolicies": 0.15, "GetUser": 0.15, "ListAttachedUserPolicies": 0.15, "ListAccessKeys": 0.15},
        "lambda": {"ListFunctions": 0.50, "GetFunction": 0.50},
        "ec2": {"DescribeInstances": 0.40, "DescribeSecurityGroups": 0.30, "DescribeVpcs": 0.30},
        "cloudwatch": {"DescribeAlarms": 0.40, "PutMetricAlarm": 0.30, "GetMetricStatistics": 0.30},
        "cloudtrail": {"LookupEvents": 0.35, "DescribeTrails": 0.35, "GetTrailStatus": 0.30},
    },
    "eve-analyst": {
        "s3": {"GetObject": 0.55, "ListObjectsV2": 0.30, "HeadObject": 0.10, "ListBuckets": 0.05},
        "iam": {"GetUser": 1.0},  # Very rare — only GetUser in normal behavior
        "lambda": {"ListFunctions": 0.60, "Invoke": 0.40},
        "ec2": {"DescribeInstances": 1.0},
        "cloudwatch": {"GetMetricStatistics": 0.60, "DescribeAlarms": 0.40},
        "cloudtrail": {"LookupEvents": 0.60, "DescribeTrails": 0.40},
    },
    "cicd-service-account": {
        "s3": {"GetObject": 0.20, "PutObject": 0.40, "ListObjectsV2": 0.25, "HeadObject": 0.15},
        "iam": {"AssumeRole": 0.60, "GetRole": 0.40},
        "lambda": {"Invoke": 0.50, "UpdateFunctionCode": 0.30, "ListFunctions": 0.20},
        "ec2": {"DescribeInstances": 0.60, "DescribeSecurityGroups": 0.40},
        "cloudwatch": {"PutMetricData": 0.60, "GetMetricStatistics": 0.40},
        "cloudtrail": {"DescribeTrails": 1.0},
    }
}
