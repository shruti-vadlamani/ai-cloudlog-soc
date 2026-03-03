import json
import os

# Define cloud-related platforms (lowercase for case-insensitive matching)
CLOUD_PLATFORMS = {"aws", "azure", "gcp", "azure ad", "office 365", "saas", "iaas", "containers"}

# Read the STIX data
input_file = "knowledge_base/raw/enterprise_attack_stix.json"
if not os.path.exists(input_file):
    print(f"Error: {input_file} not found!")
    print("Please ensure the file exists at the correct path.")
    exit(1)

print(f"Reading MITRE ATT&CK data from {input_file}...")
with open(input_file, "r", encoding="utf-8") as f:
    stix = json.load(f)

print(f"Loaded {len(stix['objects'])} STIX objects")

techniques = []
skipped_count = 0

for obj in stix["objects"]:
    # Only process attack-pattern objects (techniques)
    if obj.get("type") != "attack-pattern":
        continue
    
    # Skip revoked or deprecated techniques
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        skipped_count += 1
        continue

    # Check if the technique applies to cloud platforms
    platforms = {p.lower() for p in obj.get("x_mitre_platforms", [])}
    if not platforms & CLOUD_PLATFORMS:
        continue

    # Extract tactics from kill chain phases
    tactic_ids = []
    for phase in obj.get("kill_chain_phases", []):
        if phase["kill_chain_name"] == "mitre-attack":
            tactic_ids.append(phase["phase_name"])

    # Get external references
    external_refs = obj.get("external_references", [])
    technique_id = ""
    technique_url = ""
    
    for ref in external_refs:
        if ref.get("source_name") == "mitre-attack":
            technique_id = ref.get("external_id", "")
            technique_url = ref.get("url", "")
            break

    # Get description (truncate if too long for better RAG performance)
    description = obj.get("description", "")
    if len(description) > 1000:
        description = description[:1000] + "..."

    techniques.append({
        "technique_id": technique_id,
        "name": obj.get("name", ""),
        "description": description,
        "tactics": tactic_ids,
        "platforms": list(platforms),
        "detection": obj.get("x_mitre_detection", "")[:500] if obj.get("x_mitre_detection") else "",
        "url": technique_url,
        "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
        "aws_indicators": [],  # Will be populated below for AWS-specific techniques
    })

print(f"Found {len(techniques)} cloud-related techniques (skipped {skipped_count} revoked/deprecated)")

print(f"Found {len(techniques)} cloud-related techniques (skipped {skipped_count} revoked/deprecated)")

# Map AWS-specific CloudTrail indicators to relevant techniques
# These are common AWS API calls that would appear in CloudTrail logs for each attack type
AWS_INDICATORS_MAP = {
    # Valid Accounts / Credential Access
    "T1078": ["AssumeRole", "GetSessionToken", "ConsoleLogin", "GetCallerIdentity"],
    "T1078.004": ["AssumeRole", "GetFederationToken", "AssumeRoleWithWebIdentity"],  # Cloud Accounts
    
    # Create Account / Account Manipulation
    "T1136": ["CreateUser", "CreateLoginProfile", "CreateAccessKey"],
    "T1136.003": ["CreateUser", "CreateLoginProfile", "CreateAccessKey"],  # Cloud Account
    "T1098": ["AttachUserPolicy", "CreateAccessKey", "PutUserPolicy", "AttachRolePolicy", "UpdateAccessKey"],
    "T1098.001": ["CreateAccessKey", "UpdateAccessKey"],  # Additional Cloud Credentials
    
    # Data from Cloud Storage
    "T1530": ["GetObject", "ListBuckets", "GetBucketLocation", "GetBucketAcl", "ListObjects", "ListObjectsV2"],
    
    # Cloud Storage Object Discovery
    "T1619": ["ListObjects", "ListObjectsV2", "GetObject", "HeadObject", "HeadBucket"],
    
    # Account Discovery
    "T1087": ["ListUsers", "ListRoles", "ListPolicies", "GetAccountAuthorizationDetails", "ListGroups"],
    "T1087.004": ["ListUsers", "ListRoles", "GetUser", "GetRole"],  # Cloud Account
    
    # Data Destruction
    "T1485": ["DeleteObject", "DeleteObjects", "DeleteBucket", "DeleteDBInstance"],
    
    # Transfer Data to Cloud Account
    "T1537": ["PutObject", "CreateMultipartUpload", "UploadPart", "CompleteMultipartUpload"],
    
    # Unused/Unsupported Cloud Regions
    "T1535": ["DescribeRegions", "DescribeAvailabilityZones"],
    
    # Create Snapshot
    "T1578.001": ["CreateSnapshot", "CreateDBSnapshot", "CopySnapshot"],
    
    # Cloud Infrastructure Discovery
    "T1580": ["DescribeInstances", "DescribeVolumes", "DescribeSnapshots", "DescribeImages"],
    
    # Modify Cloud Compute Infrastructure
    "T1578": ["RunInstances", "TerminateInstances", "StopInstances", "ModifyInstanceAttribute"],
    
    # Steal Application Access Token
    "T1528": ["GetSecretValue", "GetParameter", "AssumeRole"],
    
    # Disable Cloud Logs
    "T1562.008": ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"],
    
    # Cloud Service Dashboard
    "T1538": ["ConsoleLogin", "GetSigninToken"],
    
    # Cloud Service Discovery
    "T1526": ["DescribeServices", "ListServices", "GetResources"],
    
    # Implant Internal Image
    "T1525": ["CreateImage", "ModifyImageAttribute", "CopyImage"],
    
    # Exfiltration to Cloud Storage
    "T1567.002": ["PutObject", "CreateMultipartUpload"]
}

# Enrich techniques with AWS indicators
enriched_count = 0
for technique in techniques:
    tid = technique["technique_id"]
    if tid in AWS_INDICATORS_MAP:
        technique["aws_indicators"] = AWS_INDICATORS_MAP[tid]
        enriched_count += 1

print(f"Enriched {enriched_count} techniques with AWS CloudTrail indicators")

# Sort techniques by technique ID for easier navigation
techniques.sort(key=lambda x: x["technique_id"])

# Save enriched techniques to output file
output_file = "knowledge_base/mitre_techniques_enriched.json"
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(techniques, f, indent=2, ensure_ascii=False)

print(f"✓ Successfully saved {len(techniques)} enriched cloud/AWS techniques to {output_file}")

# Print summary statistics
aws_specific = sum(1 for t in techniques if "aws" in [p.lower() for p in t["platforms"]])
iaas_specific = sum(1 for t in techniques if "iaas" in [p.lower() for p in t["platforms"]])
tactics_summary = {}
for technique in techniques:
    for tactic in technique["tactics"]:
        tactics_summary[tactic] = tactics_summary.get(tactic, 0) + 1

print(f"\n=== Summary ===")
print(f"Total cloud-related techniques: {len(techniques)}")
print(f"AWS-specific techniques: {aws_specific}")
print(f"IaaS techniques: {iaas_specific}")
print(f"Techniques with CloudTrail indicators: {enriched_count}")
print(f"\nTop tactics covered:")
for tactic, count in sorted(tactics_summary.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"  - {tactic}: {count} techniques")