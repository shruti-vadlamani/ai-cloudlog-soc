"""
attack_injector.py
==================
Injects 5 attack scenarios into the event stream at pre-defined
timestamps. Each scenario produces structurally valid CloudTrail
events — indistinguishable from normal events at the JSON level.
Only the behavioral pattern (timing, volume, sequence, actor)
distinguishes them.

Attack events are returned as a list alongside a ground truth
manifest entry for each event, used later by label_generator.py.

Scenarios:
  1. Privilege Escalation   — alice-dev, 2026-02-17 02:00 IST
  2. Data Exfiltration      — eve-analyst, 2026-02-23 to 2026-02-25
  3. Insider Threat         — bob-devops, 2026-02-27 16:45 IST
  4. Reconnaissance         — eve-analyst, 2026-02-18 to 2026-02-20
  5. Backdoor Creation      — eve-analyst, 2026-02-25 03:15 IST
"""

import random
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Tuple, Dict
import numpy as np

from data_generation.event_templates import (
    get_user_agent,
    iam_create_access_key,
    iam_attach_user_policy,
    iam_create_user,
    iam_create_login_profile,
    iam_list_users,
    iam_list_roles,
    iam_list_policies,
    iam_get_account_authorization_details,
    iam_list_attached_user_policies,
    iam_list_access_keys,
    s3_get_object,
    s3_delete_object,
    s3_delete_objects_batch,
    s3_delete_bucket,
    s3_list_buckets,
    iam_put_user_policy,
)
from data_generation.temporal_engine import TemporalEngine

log = logging.getLogger(__name__)

IST = timezone(timedelta(hours=5, minutes=30))


def _parse_ist(dt_str: str) -> datetime:
    naive = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
    return naive.replace(tzinfo=IST).astimezone(timezone.utc)


def _ctx(username: str, timestamp: datetime, config: dict,
         source_ip: str = None, user_agent_style: str = "aws-cli") -> dict:
    """Build context dict for event template functions."""
    # Find persona config
    persona_cfg = next(
        (p for p in config["personas"] if p["iam_username"] == username), None
    )
    ip_prefix = source_ip or (persona_cfg["source_ip_prefix"] if persona_cfg else "103.21.244")
    ua_style = persona_cfg["user_agent_style"] if persona_cfg else user_agent_style

    return {
        "event_time": timestamp,
        "username": username,
        "account_id": config["aws"]["account_id"],
        "region": config["aws"]["region"],
        "source_ip": f"{ip_prefix}.{random.randint(1, 254)}",
        "user_agent": get_user_agent(ua_style),
        "is_cicd": False,
    }


def _label_entry(event: dict, attack_id: int, attack_name: str) -> dict:
    """Create a ground truth label entry for an attack event."""
    return {
        "eventID": event["eventID"],
        "eventTime": event["eventTime"],
        "eventName": event["eventName"],
        "userName": event["userIdentity"].get("userName", "unknown"),
        "attack_id": attack_id,
        "attack_name": attack_name,
        "is_attack": True,
    }


# ── Attack 1: Privilege Escalation ───────────────────────────────────────────

def inject_privilege_escalation(
    config: dict,
    engine: TemporalEngine
) -> Tuple[List[dict], List[dict]]:
    """
    alice-dev account is compromised at 2 AM IST on 2026-02-17.
    Sequence:
      1. CreateAccessKey for alice-dev (self)          — unusual hour
      2. AttachUserPolicy (AdministratorAccess)        — critical escalation
      3. CreateUser 'backup-admin'                     — persistence
      4. AttachUserPolicy (AdministratorAccess) on new user
      5. CreateAccessKey for new user                 — exfil keys

    Burst of 5 events over ~25 minutes. No prior IAM write activity
    from alice-dev in normal traffic makes this highly anomalous.
    """
    attack_cfg = next(a for a in config["attacks"] if a["id"] == 1)
    center = _parse_ist(attack_cfg["start_datetime"])
    actor = attack_cfg["actor"]
    account_id = config["aws"]["account_id"]
    new_user = "backup-admin"

    # Timestamps: each step a few minutes apart
    timestamps = [
        center,
        center + timedelta(minutes=4),
        center + timedelta(minutes=9),
        center + timedelta(minutes=14),
        center + timedelta(minutes=22),
    ]

    events = []
    labels = []

    admin_policy = "arn:aws:iam::aws:policy/AdministratorAccess"

    # Step 1: CreateAccessKey (self)
    ctx = _ctx(actor, timestamps[0], config)
    ev = iam_create_access_key(ctx, actor)
    events.append(ev)
    labels.append(_label_entry(ev, 1, "privilege_escalation"))

    # Step 2: AttachUserPolicy (self → admin)
    ctx = _ctx(actor, timestamps[1], config)
    ev = iam_attach_user_policy(ctx, actor, admin_policy)
    events.append(ev)
    labels.append(_label_entry(ev, 1, "privilege_escalation"))

    # Step 3: CreateUser for new backdoor user
    ctx = _ctx(actor, timestamps[2], config)
    ev = iam_create_user(ctx, new_user)
    events.append(ev)
    labels.append(_label_entry(ev, 1, "privilege_escalation"))

    # Step 4: AttachUserPolicy to new user
    ctx = _ctx(actor, timestamps[3], config)
    ev = iam_attach_user_policy(ctx, new_user, admin_policy)
    events.append(ev)
    labels.append(_label_entry(ev, 1, "privilege_escalation"))

    # Step 5: CreateAccessKey for new user
    ctx = _ctx(actor, timestamps[4], config)
    ev = iam_create_access_key(ctx, new_user)
    events.append(ev)
    labels.append(_label_entry(ev, 1, "privilege_escalation"))

    log.info(f"Attack 1 (Privilege Escalation): injected {len(events)} events")
    return events, labels


# ── Attack 2: Data Exfiltration ───────────────────────────────────────────────

def inject_data_exfiltration(
    config: dict,
    engine: TemporalEngine,
    normal_events: List[dict]
) -> Tuple[List[dict], List[dict]]:
    """
    eve-analyst gradually increases S3 GetObject volume over 3 days.
    
    Eve's normal baseline: compute her average hourly GetObject rate
    from normal events, then inject 50%/100%/200% excess on Mon/Tue/Wed.

    Spread across business hours to avoid spike detection — this is
    the attack that tests your 3-day rolling slope feature.
    """
    attack_cfg = next(a for a in config["attacks"] if a["id"] == 2)
    actor = attack_cfg["actor"]
    account_id = config["aws"]["account_id"]

    # Target bucket for exfiltration — the sensitive data lake
    exfil_bucket = "company-data-lake-prod"
    exfil_prefix = "analytics/reports/"

    # Compute eve's normal hourly S3 GetObject rate from normal events
    eve_normal_gets = [
        e for e in normal_events
        if e["userIdentity"].get("userName") == actor
        and e["eventName"] == "GetObject"
    ]
    # Approximate baseline: events per 8-hour business day
    baseline_per_day = max(len(eve_normal_gets) / 14, 20)  # At least 20/day

    # Excess counts per day (50%, 100%, 200% above baseline)
    day_starts = [
        _parse_ist("2026-02-23 09:00:00"),  # Monday
        _parse_ist("2026-02-24 09:00:00"),  # Tuesday
        _parse_ist("2026-02-25 09:00:00"),  # Wednesday
    ]
    multipliers = [0.50, 1.00, 2.00]

    all_events = []
    all_labels = []

    for day_start, multiplier in zip(day_starts, multipliers):
        day_end = day_start + timedelta(hours=8)
        n_excess = int(baseline_per_day * multiplier)
        n_excess = max(n_excess, 30)  # Minimum to be statistically visible

        timestamps = engine.spread_across_window(
            start_ist=day_start.astimezone(timezone(timedelta(hours=5, minutes=30))),
            end_ist=day_end.astimezone(timezone(timedelta(hours=5, minutes=30))),
            n=n_excess,
            business_hours_only=True
        )

        for ts in timestamps:
            ctx = _ctx(actor, ts, config)
            # Exfil keys: systematically going through all reports
            key = f"{exfil_prefix}2026/{random.randint(1, 500):04d}/report_{random.randint(1,9999)}.csv"
            ev = s3_get_object(ctx, exfil_bucket, key)
            all_events.append(ev)
            all_labels.append(_label_entry(ev, 2, "data_exfiltration"))

    log.info(f"Attack 2 (Data Exfiltration): injected {len(all_events)} events")
    return all_events, all_labels


# ── Attack 3: Insider Threat ──────────────────────────────────────────────────

def inject_insider_threat(
    config: dict,
    engine: TemporalEngine
) -> Tuple[List[dict], List[dict]]:
    """
    bob-devops destroys data right before the weekend.
    2026-02-27 (Friday) 4:45 PM IST.

    Sequence:
      1. ListBuckets (reconnaissance of targets)
      2. Mass DeleteObjects on company-data-lake-prod (batches of 50)
      3. Mass DeleteObjects on company-backups
      4. DeleteBucket on company-backups (if empty enough)

    High-volume destructive S3 writes over ~30 minutes.
    """
    attack_cfg = next(a for a in config["attacks"] if a["id"] == 3)
    center = _parse_ist(attack_cfg["start_datetime"])
    actor = attack_cfg["actor"]

    events = []
    labels = []

    # Step 1: ListBuckets (scoping targets)
    ctx = _ctx(actor, center, config)
    ev = s3_list_buckets(ctx)
    events.append(ev)
    labels.append(_label_entry(ev, 3, "insider_threat"))

    # Steps 2-3: Batch deletes — 8 batches of 50 objects on data lake
    current_time = center + timedelta(minutes=2)
    for batch_num in range(8):
        keys = [
            f"raw/events/2026/{random.randint(1,12):02d}/{random.randint(1,28):02d}/data_{i}.parquet"
            for i in range(50)
        ]
        ctx = _ctx(actor, current_time, config)
        ev = s3_delete_objects_batch(ctx, "company-data-lake-prod", keys)
        events.append(ev)
        labels.append(_label_entry(ev, 3, "insider_threat"))
        current_time += timedelta(minutes=2)

    # 4 batches on backups
    for batch_num in range(4):
        keys = [
            f"db/2026/{random.randint(1,12):02d}/{random.randint(1,28):02d}/snapshot_{i}.sql.gz"
            for i in range(50)
        ]
        ctx = _ctx(actor, current_time, config)
        ev = s3_delete_objects_batch(ctx, "company-backups", keys)
        events.append(ev)
        labels.append(_label_entry(ev, 3, "insider_threat"))
        current_time += timedelta(minutes=2)

    # Step 4: DeleteBucket
    ctx = _ctx(actor, current_time, config)
    ev = s3_delete_bucket(ctx, "company-backups")
    events.append(ev)
    labels.append(_label_entry(ev, 3, "insider_threat"))

    log.info(f"Attack 3 (Insider Threat): injected {len(events)} events")
    return events, labels


# ── Attack 4: Reconnaissance ──────────────────────────────────────────────────

def inject_reconnaissance(
    config: dict,
    engine: TemporalEngine
) -> Tuple[List[dict], List[dict]]:
    """
    eve-analyst (data analyst) performs IAM discovery across 3 days.
    2026-02-18 to 2026-02-20, spread during business hours.

    Eve's normal IAM usage: only GetUser (on herself).
    Recon events: ListUsers, ListRoles, ListPolicies, 
    GetAccountAuthorizationDetails, ListAttachedUserPolicies for all users.

    Spread across 3 days to appear like curious browsing.
    The anomaly detector should catch: wrong event types for this user,
    IAM resources she never accesses.
    """
    attack_cfg = next(a for a in config["attacks"] if a["id"] == 4)
    actor = attack_cfg["actor"]

    IST_tz = timezone(timedelta(hours=5, minutes=30))

    start_ist = datetime(2026, 2, 18, 11, 0, 0, tzinfo=IST_tz)
    end_ist = datetime(2026, 2, 20, 16, 0, 0, tzinfo=IST_tz)

    # Recon event sequence: spread 45 events across 3 days
    timestamps = engine.spread_across_window(
        start_ist=start_ist,
        end_ist=end_ist,
        n=45,
        business_hours_only=True
    )

    # Recon event types in realistic discovery order
    recon_sequence = [
        ("list_users", 10),
        ("list_roles", 8),
        ("list_policies", 8),
        ("get_account_auth", 3),
        ("list_attached_policies", 8),
        ("list_access_keys", 8),
    ]

    # Flatten sequence into ordered list
    event_types = []
    for name, count in recon_sequence:
        event_types.extend([name] * count)
    random.shuffle(event_types)  # Shuffle to avoid obvious sequencing

    target_users = ["alice-dev", "bob-devops", "carol-sec", "dave-admin"]
    events = []
    labels = []

    for ts, etype in zip(timestamps, event_types):
        ctx = _ctx(actor, ts, config)

        if etype == "list_users":
            ev = iam_list_users(ctx)
        elif etype == "list_roles":
            ev = iam_list_roles(ctx)
        elif etype == "list_policies":
            ev = iam_list_policies(ctx)
        elif etype == "get_account_auth":
            ev = iam_get_account_authorization_details(ctx)
        elif etype == "list_attached_policies":
            target = random.choice(target_users)
            ev = iam_list_attached_user_policies(ctx, target)
        elif etype == "list_access_keys":
            target = random.choice(target_users)
            ev = iam_list_access_keys(ctx, target)
        else:
            ev = iam_list_users(ctx)

        events.append(ev)
        labels.append(_label_entry(ev, 4, "reconnaissance"))

    log.info(f"Attack 4 (Reconnaissance): injected {len(events)} events")
    return events, labels


# ── Attack 5: Backdoor Creation ───────────────────────────────────────────────

def inject_backdoor_creation(
    config: dict,
    engine: TemporalEngine
) -> Tuple[List[dict], List[dict]]:
    """
    eve-analyst (non-admin) creates a backdoor for herself by:
      1. CreateLoginProfile on dave-admin (sets a password)
      2. CreateAccessKey for dave-admin (programmatic access)
      3. PutUserPolicy (inline admin policy) on dave-admin

    Happens at 3:15 AM IST on 2026-02-25 — extremely unusual hour
    for a data analyst.
    """
    attack_cfg = next(a for a in config["attacks"] if a["id"] == 5)
    center = _parse_ist(attack_cfg["start_datetime"])
    actor = attack_cfg["actor"]
    target = "dave-admin"  # Admin account being backdoored

    timestamps = [
        center,
        center + timedelta(minutes=5),
        center + timedelta(minutes=11),
    ]

    events = []
    labels = []

    # Step 1: CreateLoginProfile for dave-admin
    ctx = _ctx(actor, timestamps[0], config)
    ev = iam_create_login_profile(ctx, target)
    events.append(ev)
    labels.append(_label_entry(ev, 5, "backdoor_creation"))

    # Step 2: CreateAccessKey for dave-admin
    ctx = _ctx(actor, timestamps[1], config)
    ev = iam_create_access_key(ctx, target)
    events.append(ev)
    labels.append(_label_entry(ev, 5, "backdoor_creation"))

    # Step 3: PutUserPolicy (inline) to grant admin to dave-admin (re-assert)
    ctx = _ctx(actor, timestamps[2], config)
    ev = iam_put_user_policy(ctx, target, "EmergencyAdminAccess")
    events.append(ev)
    labels.append(_label_entry(ev, 5, "backdoor_creation"))

    log.info(f"Attack 5 (Backdoor Creation): injected {len(events)} events")
    return events, labels


# ── Master Injector ───────────────────────────────────────────────────────────

def inject_all_attacks(
    config: dict,
    engine: TemporalEngine,
    normal_events: List[dict]
) -> Tuple[List[dict], List[dict], Dict]:
    """
    Run all 5 attack injectors and return:
      - all_attack_events: flat list of attack CloudTrail events
      - all_labels: flat list of ground truth label entries
      - manifest: summary dict for ground_truth/attack_manifest.json
    """
    all_attack_events = []
    all_labels = []

    # Attack 1
    evs, labs = inject_privilege_escalation(config, engine)
    all_attack_events.extend(evs)
    all_labels.extend(labs)

    # Attack 2 (needs normal events to compute baseline)
    evs, labs = inject_data_exfiltration(config, engine, normal_events)
    all_attack_events.extend(evs)
    all_labels.extend(labs)

    # Attack 3
    evs, labs = inject_insider_threat(config, engine)
    all_attack_events.extend(evs)
    all_labels.extend(labs)

    # Attack 4
    evs, labs = inject_reconnaissance(config, engine)
    all_attack_events.extend(evs)
    all_labels.extend(labs)

    # Attack 5
    evs, labs = inject_backdoor_creation(config, engine)
    all_attack_events.extend(evs)
    all_labels.extend(labs)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_attack_events": len(all_attack_events),
        "attacks": {
            "privilege_escalation": {
                "id": 1, "actor": "alice-dev",
                "window_start": "2026-02-17T20:30:00Z",
                "window_end": "2026-02-17T20:55:00Z",
                "event_count": len([l for l in all_labels if l["attack_id"] == 1])
            },
            "data_exfiltration": {
                "id": 2, "actor": "eve-analyst",
                "window_start": "2026-02-23T03:30:00Z",
                "window_end": "2026-02-25T12:30:00Z",
                "event_count": len([l for l in all_labels if l["attack_id"] == 2])
            },
            "insider_threat": {
                "id": 3, "actor": "bob-devops",
                "window_start": "2026-02-27T11:15:00Z",
                "window_end": "2026-02-27T11:45:00Z",
                "event_count": len([l for l in all_labels if l["attack_id"] == 3])
            },
            "reconnaissance": {
                "id": 4, "actor": "eve-analyst",
                "window_start": "2026-02-18T05:30:00Z",
                "window_end": "2026-02-20T10:30:00Z",
                "event_count": len([l for l in all_labels if l["attack_id"] == 4])
            },
            "backdoor_creation": {
                "id": 5, "actor": "eve-analyst",
                "window_start": "2026-02-24T21:45:00Z",
                "window_end": "2026-02-24T22:05:00Z",
                "event_count": len([l for l in all_labels if l["attack_id"] == 5])
            }
        },
        "label_map": {
            "0": "normal",
            "1": "privilege_escalation",
            "2": "data_exfiltration",
            "3": "insider_threat",
            "4": "reconnaissance",
            "5": "backdoor_creation"
        }
    }

    log.info(f"Total attack events injected: {len(all_attack_events)}")
    return all_attack_events, all_labels, manifest
