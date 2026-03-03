"""
normal_traffic_generator.py
============================
Assembles normal (non-attack) CloudTrail events by combining:
  - Persona behavioral profiles from config
  - Event templates from event_templates.py
  - Timestamps from temporal_engine.py

Produces a list of raw CloudTrail event dicts representing
realistic day-to-day AWS usage for a small Indian tech company.
"""

import random
import logging
from datetime import datetime, timezone
from typing import List, Dict

import yaml

from data_generation.event_templates import (
    TEMPLATE_REGISTRY,
    PERSONA_EVENT_WEIGHTS,
    get_user_agent,
    s3_get_object,
    s3_put_object,
    s3_list_objects_v2,
    s3_list_buckets,
    s3_head_object,
    s3_get_bucket_policy,
    iam_list_users,
    iam_list_roles,
    iam_list_policies,
    iam_get_user,
    iam_list_attached_user_policies,
    iam_list_groups_for_user,
    iam_get_role,
    iam_list_access_keys,
    iam_assume_role,
    lambda_list_functions,
    lambda_invoke,
    lambda_get_function,
    lambda_update_function_code,
    ec2_describe_instances,
    ec2_describe_security_groups,
    ec2_describe_vpcs,
    cloudwatch_put_metric_data,
    cloudwatch_describe_alarms,
    cloudwatch_get_metric_statistics,
    cloudwatch_put_metric_alarm,
    cloudtrail_lookup_events,
    cloudtrail_describe_trails,
    cloudtrail_get_trail_status,
)
from data_generation.temporal_engine import TemporalEngine

log = logging.getLogger(__name__)

# ── S3 key patterns per bucket ────────────────────────────────────────────────

BUCKET_KEY_PATTERNS = {
    "company-data-lake-prod": [
        "raw/events/{year}/{month}/{day}/data_{n}.parquet",
        "processed/aggregates/{year}/{month}/summary_{n}.json",
        "analytics/reports/{year}/report_{n}.csv",
        "ml-features/{year}/{month}/features_{n}.npy",
    ],
    "company-app-assets": [
        "static/images/img_{n}.png",
        "static/css/style_{n}.css",
        "lambda/{func}/deployment.zip",
        "configs/env_{env}.json",
    ],
    "company-logs-archive": [
        "logs/{year}/{month}/{day}/app_{n}.log.gz",
        "audit/{year}/{month}/audit_{n}.json.gz",
        "metrics/{year}/{month}/{day}/metrics_{n}.json",
    ],
    "company-backups": [
        "db/{year}/{month}/{day}/snapshot_{n}.sql.gz",
        "config-backups/{year}/{month}/config_{n}.tar.gz",
    ],
    "company-public-assets": [
        "assets/images/hero_{n}.jpg",
        "assets/docs/whitepaper_{n}.pdf",
        "assets/videos/demo_{n}.mp4",
    ],
}

LAMBDA_FUNCTIONS = [
    "api-handler", "data-processor", "auth-service",
    "notification-sender", "report-generator", "file-transformer"
]

CLOUDWATCH_NAMESPACES = [
    "CompanyApp/API", "CompanyApp/DataPipeline",
    "AWS/Lambda", "CompanyApp/Auth"
]

IAM_ROLES = [
    "LambdaExecutionRole", "DataPipelineRole",
    "CICDDeployRole", "EC2InstanceRole"
]


def _random_key(bucket: str) -> str:
    """Generate a realistic S3 key for a given bucket."""
    patterns = BUCKET_KEY_PATTERNS.get(bucket, ["data/file_{n}.json"])
    pattern = random.choice(patterns)
    now = datetime.now()
    return pattern.format(
        year=now.year,
        month=str(now.month).zfill(2),
        day=str(random.randint(1, 28)).zfill(2),
        n=random.randint(1, 9999),
        func=random.choice(LAMBDA_FUNCTIONS),
        env=random.choice(["dev", "staging", "prod"]),
    )


def _source_ip(prefix: str) -> str:
    """Generate a realistic IP from a persona's subnet prefix."""
    return f"{prefix}.{random.randint(1, 254)}"


def _build_context(persona: dict, timestamp: datetime, config: dict) -> dict:
    """Build the ctx dict that all event template functions accept."""
    is_cicd = (persona["iam_username"] == "cicd-service-account")
    return {
        "event_time": timestamp,
        "username": persona["iam_username"],
        "account_id": config["aws"]["account_id"],
        "region": config["aws"]["region"],
        "source_ip": _source_ip(persona["source_ip_prefix"]),
        "user_agent": get_user_agent(persona["user_agent_style"]),
        "is_cicd": is_cicd,
    }


def _pick_service(persona: dict) -> str:
    """Pick a service for this persona based on their service weights."""
    services = persona["services"]
    names = list(services.keys())
    weights = [services[s] for s in names]
    return random.choices(names, weights=weights, k=1)[0]


def _pick_event_for_service(persona_name: str, service: str) -> str:
    """Pick a specific event name within a service for this persona."""
    weights_map = PERSONA_EVENT_WEIGHTS.get(persona_name, {})
    service_events = weights_map.get(service, {})
    if not service_events:
        # Fallback: pick first available event for this service
        available = list(TEMPLATE_REGISTRY.get(service, {}).keys())
        return random.choice(available) if available else None

    names = list(service_events.keys())
    weights = [service_events[e] for e in names]
    return random.choices(names, weights=weights, k=1)[0]


def _typical_buckets_for_persona(persona: dict, config: dict) -> List[str]:
    """Return buckets this persona typically accesses."""
    username = persona["iam_username"]
    result = []
    for bucket in config["s3_buckets"]:
        if username in bucket["typical_users"]:
            result.append(bucket["name"])
    return result or [config["s3_buckets"][0]["name"]]


def generate_event(
    persona: dict,
    timestamp: datetime,
    config: dict,
    service_override: str = None,
    event_override: str = None,
) -> dict:
    """
    Generate a single realistic CloudTrail event for a persona
    at a given timestamp.
    """
    ctx = _build_context(persona, timestamp, config)
    error = random.random() < persona.get("error_rate", 0.03)

    service = service_override or _pick_service(persona)
    event_name = event_override or _pick_event_for_service(persona["iam_username"], service)

    if event_name is None:
        # Safe fallback
        return _s3_fallback(ctx, persona, config, error)

    buckets = _typical_buckets_for_persona(persona, config)
    bucket = random.choice(buckets)
    key = _random_key(bucket)

    # ── S3 events ──
    if service == "s3":
        if event_name == "GetObject":
            return s3_get_object(ctx, bucket, key, error=error)
        elif event_name == "PutObject":
            return s3_put_object(ctx, bucket, key, error=error)
        elif event_name == "ListObjectsV2":
            return s3_list_objects_v2(ctx, bucket)
        elif event_name == "ListBuckets":
            return s3_list_buckets(ctx)
        elif event_name == "HeadObject":
            return s3_head_object(ctx, bucket, key)
        elif event_name == "GetBucketPolicy":
            return s3_get_bucket_policy(ctx, bucket)
        else:
            return s3_get_object(ctx, bucket, key, error=error)

    # ── IAM events ──
    elif service == "iam":
        target = random.choice(["alice-dev", "bob-devops", "carol-sec", "dave-admin", "eve-analyst"])
        role = random.choice(IAM_ROLES)
        if event_name == "ListUsers":
            return iam_list_users(ctx, error=error)
        elif event_name == "ListRoles":
            return iam_list_roles(ctx)
        elif event_name == "ListPolicies":
            return iam_list_policies(ctx)
        elif event_name == "GetUser":
            return iam_get_user(ctx, persona["iam_username"])
        elif event_name == "ListAttachedUserPolicies":
            return iam_list_attached_user_policies(ctx, persona["iam_username"])
        elif event_name == "ListGroupsForUser":
            return iam_list_groups_for_user(ctx, persona["iam_username"])
        elif event_name == "GetRole":
            return iam_get_role(ctx, role)
        elif event_name == "ListAccessKeys":
            return iam_list_access_keys(ctx, persona["iam_username"])
        elif event_name == "AssumeRole":
            role_arn = f"arn:aws:iam::{config['aws']['account_id']}:role/{role}"
            return iam_assume_role(ctx, role_arn, f"{persona['iam_username']}-session")
        else:
            return iam_get_user(ctx, persona["iam_username"])

    # ── Lambda events ──
    elif service == "lambda":
        func = random.choice(LAMBDA_FUNCTIONS)
        if event_name == "ListFunctions":
            return lambda_list_functions(ctx)
        elif event_name == "Invoke":
            return lambda_invoke(ctx, func, error=error)
        elif event_name == "GetFunction":
            return lambda_get_function(ctx, func)
        elif event_name == "UpdateFunctionCode":
            return lambda_update_function_code(ctx, func)
        else:
            return lambda_list_functions(ctx)

    # ── EC2 events ──
    elif service == "ec2":
        if event_name == "DescribeInstances":
            return ec2_describe_instances(ctx)
        elif event_name == "DescribeSecurityGroups":
            return ec2_describe_security_groups(ctx)
        elif event_name == "DescribeVpcs":
            return ec2_describe_vpcs(ctx)
        else:
            return ec2_describe_instances(ctx)

    # ── CloudWatch events ──
    elif service == "cloudwatch":
        ns = random.choice(CLOUDWATCH_NAMESPACES)
        if event_name == "PutMetricData":
            return cloudwatch_put_metric_data(ctx, ns)
        elif event_name == "DescribeAlarms":
            return cloudwatch_describe_alarms(ctx)
        elif event_name == "GetMetricStatistics":
            return cloudwatch_get_metric_statistics(ctx, ns, "Requests")
        elif event_name == "PutMetricAlarm":
            return cloudwatch_put_metric_alarm(ctx, f"alarm-{random.randint(1,20)}")
        else:
            return cloudwatch_describe_alarms(ctx)

    # ── CloudTrail events ──
    elif service == "cloudtrail":
        trail = f"arn:aws:cloudtrail:{config['aws']['region']}:{config['aws']['account_id']}:trail/main-trail"
        if event_name == "LookupEvents":
            return cloudtrail_lookup_events(ctx)
        elif event_name == "DescribeTrails":
            return cloudtrail_describe_trails(ctx)
        elif event_name == "GetTrailStatus":
            return cloudtrail_get_trail_status(ctx, trail)
        else:
            return cloudtrail_describe_trails(ctx)

    return _s3_fallback(ctx, persona, config, error)


def _s3_fallback(ctx, persona, config, error):
    """Safe fallback event when routing fails."""
    buckets = _typical_buckets_for_persona(persona, config)
    bucket = random.choice(buckets)
    key = _random_key(bucket)
    return s3_get_object(ctx, bucket, key, error=error)


def generate_normal_traffic(
    config: dict,
    engine: TemporalEngine,
    target_count: int
) -> List[dict]:
    """
    Generate the full corpus of normal traffic events.

    Distributes target_count events across personas by their
    activity_weight, generating realistic timestamps for each.
    """
    personas = config["personas"]
    total_weight = sum(p["activity_weight"] for p in personas)

    all_events = []

    for persona in personas:
        # Number of events for this persona
        n_events = int((persona["activity_weight"] / total_weight) * target_count)
        log.info(f"Generating {n_events} normal events for {persona['name']}")

        working_hours = tuple(persona["working_hours"])
        timestamps = engine.generate_timestamps(
            n=n_events,
            persona_name=persona["iam_username"],
            working_hours=working_hours
        )

        for ts in timestamps:
            try:
                event = generate_event(persona, ts, config)
                all_events.append(event)
            except Exception as e:
                log.warning(f"Event generation failed for {persona['name']}: {e}")
                continue

    # Sort by eventTime
    all_events.sort(key=lambda e: e["eventTime"])
    log.info(f"Generated {len(all_events)} normal events total")
    return all_events
