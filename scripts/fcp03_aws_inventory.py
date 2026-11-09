"""Read-only AWS inventory collector for the FCP-03 egress preflight.

The collector only invokes Describe/List/Get operations. It never creates, updates,
associates, deletes, or otherwise mutates AWS resources.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from typing import Any


def _all_pages(client: Any, operation: str, result_key: str, **params: Any) -> list[Any]:
    items: list[Any] = []
    request = dict(params)
    while True:
        response = getattr(client, operation)(**request)
        page = response.get(result_key, [])
        if not isinstance(page, list):
            raise ValueError(f"AWS {operation} returned an invalid {result_key} collection")
        items.extend(page)
        token = response.get("NextToken")
        if not token:
            return items
        request["NextToken"] = token


def _route_target(route: Mapping[str, Any]) -> str | None:
    for key in (
        "VpcEndpointId",
        "NatGatewayId",
        "GatewayId",
        "TransitGatewayId",
        "NetworkInterfaceId",
        "EgressOnlyInternetGatewayId",
        "LocalGatewayId",
    ):
        value = route.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _security_group_egress(groups: list[Mapping[str, Any]]) -> list[dict[str, object]]:
    rules: list[dict[str, object]] = []
    for group in groups:
        for permission in group.get("IpPermissionsEgress", []):
            protocol = permission.get("IpProtocol")
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            port = from_port if from_port == to_port else None
            for item in permission.get("IpRanges", []):
                rules.append(
                    {
                        "protocol": protocol,
                        "port": port,
                        "cidr": item.get("CidrIp"),
                    }
                )
            for item in permission.get("Ipv6Ranges", []):
                rules.append(
                    {
                        "protocol": protocol,
                        "port": port,
                        "cidr": item.get("CidrIpv6"),
                    }
                )
            # Prefix-list and security-group references are not expanded here.
            # Preserve them as unclassifiable rules so the preflight fails closed.
            for item in permission.get("PrefixListIds", []) + permission.get(
                "UserIdGroupPairs", []
            ):
                rules.append(
                    {
                        "protocol": protocol,
                        "port": port,
                        "cidr": None,
                        "reference": item.get("PrefixListId") or item.get("GroupId"),
                    }
                )
    return rules


def _firewall_for_vpc(network_firewall: Any, vpc_id: str) -> Mapping[str, Any] | None:
    firewalls = _all_pages(network_firewall, "list_firewalls", "Firewalls")
    matches = [firewall for firewall in firewalls if firewall.get("VpcId") == vpc_id]
    if len(matches) > 1:
        raise ValueError(
            "multiple Network Firewalls found for the worker VPC; select a policy domain"
        )
    return matches[0] if matches else None


def _resolved_ip_validation(policy: Mapping[str, Any]) -> dict[str, object] | None:
    validation = policy.get("Route53ResolvedIPValidation")
    if not isinstance(validation, Mapping):
        return None

    def address_ranges(name: str) -> list[str]:
        values = validation.get(name, [])
        if not isinstance(values, list):
            return []
        return [
            value["AddressDefinition"]
            for value in values
            if isinstance(value, Mapping) and isinstance(value.get("AddressDefinition"), str)
        ]

    return {
        "dns_firewall_rule_group_id": validation.get("DNSFirewallRuleGroupId"),
        "action": validation.get("Action"),
        "dns_expiry_exception_action": validation.get("DNSExpiryExceptionPolicy"),
        "source_ip_ranges": address_ranges("SourceIPRanges"),
        "bypass_destination_validation_ip_ranges": address_ranges(
            "BypassDestinationValidationIPRanges"
        ),
    }


def _dns_firewall_snapshot(
    resolver: Any, *, vpc_id: str, rule_group_id: str | None
) -> dict[str, object]:
    if not rule_group_id:
        return {
            "rule_group_id": None,
            "associated_vpc_ids": [],
            "allowlist_domains": [],
            "terminal_block": False,
            "failure_mode": "UNKNOWN",
            "rule_group_status": "UNKNOWN",
            "association_statuses": [],
            "rule_statuses": [],
            "domain_list_statuses": [],
        }

    group_response = resolver.describe_firewall_rule_group(FirewallRuleGroupId=rule_group_id)
    rule_group_status = group_response.get("FirewallRuleGroup", {}).get("Status", "UNKNOWN")
    associations = _all_pages(
        resolver,
        "list_firewall_rule_group_associations",
        "FirewallRuleGroupAssociations",
        FirewallRuleGroupId=rule_group_id,
    )
    associated_vpcs = sorted(
        {
            association["VpcId"]
            for association in associations
            if isinstance(association.get("VpcId"), str)
        }
    )
    association_statuses = sorted(
        {
            association.get("Status", "UNKNOWN")
            for association in associations
            if isinstance(association.get("Status", "UNKNOWN"), str)
        }
    )
    rules = _all_pages(
        resolver,
        "list_firewall_rules",
        "FirewallRules",
        FirewallRuleGroupId=rule_group_id,
    )
    rule_statuses = sorted(
        {
            rule.get("Status", "UNKNOWN")
            for rule in rules
            if isinstance(rule.get("Status", "UNKNOWN"), str)
        }
    )

    allowlist_domains: set[str] = set()
    allow_priorities: list[int] = []
    wildcard_block_priorities: list[int] = []
    domain_list_statuses: set[str] = set()
    domain_list_cache: dict[str, list[str]] = {}
    for rule in rules:
        domain_list_id = rule.get("FirewallDomainListId")
        priority = rule.get("Priority")
        if not isinstance(domain_list_id, str):
            continue
        if domain_list_id not in domain_list_cache:
            metadata = resolver.get_firewall_domain_list(FirewallDomainListId=domain_list_id).get(
                "FirewallDomainList", {}
            )
            status = metadata.get("Status", "UNKNOWN")
            if isinstance(status, str):
                domain_list_statuses.add(status)
            domain_list_cache[domain_list_id] = _all_pages(
                resolver,
                "list_firewall_domains",
                "Domains",
                FirewallDomainListId=domain_list_id,
            )
        domains = domain_list_cache[domain_list_id]
        if rule.get("Action") == "ALLOW":
            allowlist_domains.update(domain for domain in domains if isinstance(domain, str))
            if isinstance(priority, int):
                allow_priorities.append(priority)
        if rule.get("Action") == "BLOCK" and "*" in domains and isinstance(priority, int):
            wildcard_block_priorities.append(priority)
    terminal_block = (
        bool(allow_priorities)
        and bool(wildcard_block_priorities)
        and (min(wildcard_block_priorities) > max(allow_priorities))
    )

    config = resolver.get_firewall_config(ResourceId=vpc_id).get("FirewallConfig", {})
    fail_open = config.get("FirewallFailOpen")
    failure_mode = (
        "CLOSED" if fail_open == "DISABLED" else "OPEN" if fail_open == "ENABLED" else "UNKNOWN"
    )

    return {
        "rule_group_id": rule_group_id,
        "associated_vpc_ids": associated_vpcs,
        "allowlist_domains": sorted(allowlist_domains),
        "terminal_block": terminal_block,
        "failure_mode": failure_mode,
        "rule_group_status": rule_group_status,
        "association_statuses": association_statuses,
        "rule_statuses": rule_statuses,
        "domain_list_statuses": sorted(domain_list_statuses),
    }



def _stateful_rule_group_snapshots(
    network_firewall: Any, policy: Mapping[str, Any]
) -> list[dict[str, object]]:
    """Read every stateful rule group referenced by the worker's firewall policy."""
    references = policy.get("StatefulRuleGroupReferences", [])
    if not isinstance(references, list):
        return []

    snapshots: list[dict[str, object]] = []
    for reference in references:
        arn = reference.get("ResourceArn") if isinstance(reference, Mapping) else None
        if not isinstance(arn, str) or not arn:
            snapshots.append(
                {
                    "status": "UNKNOWN",
                    "type": "UNKNOWN",
                    "rule_order": None,
                    "generated_rules_type": None,
                    "targets": [],
                    "target_types": [],
                }
            )
            continue

        response = network_firewall.describe_rule_group(RuleGroupArn=arn)
        raw_rule_group = response.get("RuleGroup")
        rule_group = raw_rule_group if isinstance(raw_rule_group, Mapping) else {}
        raw_metadata = response.get("RuleGroupResponse")
        response_metadata = raw_metadata if isinstance(raw_metadata, Mapping) else {}
        raw_rules_source = rule_group.get("RulesSource")
        rules_source = raw_rules_source if isinstance(raw_rules_source, Mapping) else {}
        raw_domain_list = rules_source.get("RulesSourceList")
        domain_list = raw_domain_list if isinstance(raw_domain_list, Mapping) else {}
        raw_stateful_options = rule_group.get("StatefulRuleOptions")
        stateful_options = (
            raw_stateful_options if isinstance(raw_stateful_options, Mapping) else {}
        )
        targets = domain_list.get("Targets", [])
        target_types = domain_list.get("TargetTypes", [])
        snapshots.append(
            {
                "status": response_metadata.get("RuleGroupStatus", "UNKNOWN"),
                "type": response_metadata.get("Type", "UNKNOWN"),
                "rule_order": stateful_options.get("RuleOrder"),
                "generated_rules_type": domain_list.get("GeneratedRulesType"),
                "targets": sorted(
                    value for value in targets if isinstance(value, str)
                ) if isinstance(targets, list) else [],
                "target_types": sorted(
                    value for value in target_types if isinstance(value, str)
                ) if isinstance(target_types, list) else [],
            }
        )
    return snapshots

def collect_fcp03_snapshot(
    *,
    instance_id: str,
    ec2: Any,
    network_firewall: Any,
    resolver: Any,
) -> dict[str, Any]:
    """Collect a normalized read-only topology snapshot for one EC2 worker."""
    if not instance_id or not isinstance(instance_id, str):
        raise ValueError("instance_id must be a non-empty EC2 instance ID")

    instance_response = ec2.describe_instances(InstanceIds=[instance_id])
    instances = [
        instance
        for reservation in instance_response.get("Reservations", [])
        for instance in reservation.get("Instances", [])
        if instance.get("InstanceId") == instance_id
    ]
    if len(instances) != 1:
        raise ValueError("the requested EC2 instance was not found exactly once")
    instance = instances[0]

    vpc_id = instance.get("VpcId")
    subnet_id = instance.get("SubnetId")
    availability_zone = instance.get("Placement", {}).get("AvailabilityZone")
    if not all(
        isinstance(value, str) and value for value in (vpc_id, subnet_id, availability_zone)
    ):
        raise ValueError("the EC2 instance is missing VPC, subnet, or Availability Zone metadata")

    subnets = _all_pages(ec2, "describe_subnets", "Subnets", SubnetIds=[subnet_id])
    subnet = next((item for item in subnets if item.get("SubnetId") == subnet_id), None)
    if subnet is None:
        raise ValueError("the EC2 worker subnet could not be resolved")

    route_tables = _all_pages(
        ec2,
        "describe_route_tables",
        "RouteTables",
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}],
    )
    if not route_tables:
        route_tables = _all_pages(
            ec2,
            "describe_route_tables",
            "RouteTables",
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "association.main", "Values": ["true"]},
            ],
        )
    if len(route_tables) > 1:
        exact = [
            table
            for table in route_tables
            if any(
                association.get("SubnetId") == subnet_id
                for association in table.get("Associations", [])
            )
        ]
        if len(exact) != 1:
            raise ValueError("the worker subnet has an ambiguous route-table association")
        route_tables = exact
    routes = route_tables[0].get("Routes", []) if route_tables else []
    default_route = next(
        (
            route
            for route in routes
            if route.get("DestinationCidrBlock") == "0.0.0.0/0"
            and route.get("State", "active") == "active"
        ),
        None,
    )
    ipv6_default_route = next(
        (
            route
            for route in routes
            if route.get("DestinationIpv6CidrBlock") == "::/0"
            and route.get("State", "active") == "active"
        ),
        None,
    )
    ipv6_addresses = sorted(
        {
            address["Ipv6Address"]
            for interface in instance.get("NetworkInterfaces", [])
            for address in interface.get("Ipv6Addresses", [])
            if isinstance(address.get("Ipv6Address"), str)
        }
    )

    security_group_ids = sorted(
        {
            group["GroupId"]
            for group in instance.get("SecurityGroups", [])
            if isinstance(group.get("GroupId"), str)
        }
    )
    security_groups = (
        _all_pages(ec2, "describe_security_groups", "SecurityGroups", GroupIds=security_group_ids)
        if security_group_ids
        else []
    )

    metadata_options = instance.get("MetadataOptions")
    metadata_options = metadata_options if isinstance(metadata_options, Mapping) else {}

    worker = {
        "vpc_id": vpc_id,
        "subnet_cidr": subnet.get("CidrBlock"),
        "public_ip": instance.get("PublicIpAddress"),
        "map_public_ip_on_launch": subnet.get("MapPublicIpOnLaunch"),
        "metadata_endpoint_enabled": (
            metadata_options.get("HttpEndpoint") == "enabled"
            if metadata_options.get("HttpEndpoint") in {"enabled", "disabled"}
            else None
        ),
        "metadata_tokens_required": (
            metadata_options.get("HttpTokens") == "required"
            if metadata_options.get("HttpTokens") in {"required", "optional"}
            else None
        ),
        "metadata_hop_limit": metadata_options.get("HttpPutResponseHopLimit"),
        "ipv6_enabled": bool(
            subnet.get("AssignIpv6AddressOnCreation") or subnet.get("Ipv6CidrBlockAssociationSet")
        ),
        "availability_zone": availability_zone,
        "default_route_target": _route_target(default_route) if default_route else None,
        "ipv6_default_route_target": (
            _route_target(ipv6_default_route) if ipv6_default_route else None
        ),
        "ipv6_addresses": ipv6_addresses,
        "security_group_egress": _security_group_egress(security_groups),
    }

    firewall_summary = _firewall_for_vpc(network_firewall, vpc_id)
    if firewall_summary is None:
        firewall_snapshot: dict[str, Any] = {
            "endpoints_by_az": {},
            "policy": {"route53_resolved_ip_validation": None},
        }
        dns_snapshot = _dns_firewall_snapshot(resolver, vpc_id=vpc_id, rule_group_id=None)
    else:
        described = network_firewall.describe_firewall(FirewallArn=firewall_summary["FirewallArn"])
        firewall = described.get("Firewall", {})
        firewall_status = described.get("FirewallStatus", {})
        endpoints: dict[str, str] = {}
        if (
            firewall_status.get("Status") == "READY"
            and firewall_status.get("ConfigurationSyncStateSummary") == "IN_SYNC"
        ):
            for az, state in firewall_status.get("SyncStates", {}).items():
                attachment = state.get("Attachment", {})
                endpoint_id = attachment.get("EndpointId")
                if attachment.get("Status") == "READY" and isinstance(endpoint_id, str):
                    endpoints[az] = endpoint_id

        policy_arn = firewall.get("FirewallPolicyArn")
        policy_response = (
            network_firewall.describe_firewall_policy(FirewallPolicyArn=policy_arn)
            if isinstance(policy_arn, str)
            else {}
        )
        policy = policy_response.get("FirewallPolicy", {})
        policy_metadata = policy_response.get("FirewallPolicyResponse", {})
        validation = _resolved_ip_validation(policy)
        policy_errors = policy_metadata.get("Errors")
        raw_engine_options = policy.get("StatefulEngineOptions")
        engine_options = (
            raw_engine_options if isinstance(raw_engine_options, Mapping) else {}
        )
        firewall_snapshot = {
            "endpoints_by_az": endpoints,
            "policy": {
                "route53_resolved_ip_validation": validation,
                "status": policy_metadata.get("FirewallPolicyStatus", "UNKNOWN"),
                "errors": policy_errors if isinstance(policy_errors, list) else None,
                "stateful_rule_order": engine_options.get("RuleOrder"),
                "stateful_default_actions": policy.get("StatefulDefaultActions", []),
                "stateful_rule_groups": _stateful_rule_group_snapshots(
                    network_firewall, policy
                ),
            },
        }
        group_id = validation.get("dns_firewall_rule_group_id") if validation else None
        dns_snapshot = _dns_firewall_snapshot(
            resolver,
            vpc_id=vpc_id,
            rule_group_id=group_id if isinstance(group_id, str) else None,
        )

    return {
        "worker": worker,
        "firewall": firewall_snapshot,
        "dns_firewall": dns_snapshot,
    }


def main(argv: list[str] | None = None) -> int:
    """Collect and print one worker's normalized AWS inventory as JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--region", required=True)
    args = parser.parse_args(argv)
    try:
        import boto3

        session = boto3.Session(region_name=args.region)
        snapshot = collect_fcp03_snapshot(
            instance_id=args.instance_id,
            ec2=session.client("ec2"),
            network_firewall=session.client("network-firewall"),
            resolver=session.client("route53resolver"),
        )
    except Exception as exc:
        parser.error(f"read-only AWS inventory collection failed: {exc}")
    print(json.dumps(snapshot, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
