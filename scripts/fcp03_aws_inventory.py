"""Read-only AWS inventory collector for the FCP-03 egress preflight.

The collector only invokes Describe/List/Get operations. It never creates, updates,
associates, deletes, or otherwise mutates AWS resources.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from collections.abc import Mapping, Sequence
from typing import Any


def _all_pages(client: Any, operation: str, result_key: str, **params: Any) -> list[Any]:
    items: list[Any] = []
    request = dict(params)
    seen_tokens: set[str] = set()
    while True:
        response = getattr(client, operation)(**request)
        page = response.get(result_key, [])
        if not isinstance(page, list):
            raise ValueError(f"AWS {operation} returned an invalid {result_key} collection")
        items.extend(page)
        token = response.get("NextToken")
        if token is None or token == "":
            return items
        if not isinstance(token, str):
            raise ValueError(f"AWS {operation} returned an invalid pagination token")
        if token in seen_tokens:
            raise ValueError(f"AWS {operation} returned a repeated pagination token")
        seen_tokens.add(token)
        request["NextToken"] = token


def _route_entries_for_subnet(
    ec2: Any, *, vpc_id: str, subnet_id: str
) -> tuple[list[dict[str, object]], list[object]]:
    """Return the complete route table for a subnet, failing on ambiguity."""
    tables = _all_pages(
        ec2,
        "describe_route_tables",
        "RouteTables",
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}],
    )
    if not tables:
        tables = _all_pages(
            ec2,
            "describe_route_tables",
            "RouteTables",
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "association.main", "Values": ["true"]},
            ],
        )
    if len(tables) > 1:
        exact = [
            table
            for table in tables
            if any(
                association.get("SubnetId") == subnet_id
                for association in table.get("Associations", [])
            )
        ]
        if len(exact) != 1:
            raise ValueError(f"subnet {subnet_id} has an ambiguous route-table association")
        tables = exact
    if len(tables) != 1:
        return [], []
    raw_associations = tables[0].get("Associations", [])
    associated_subnets: list[object] = []
    if isinstance(raw_associations, list):
        for association in raw_associations:
            if not isinstance(association, Mapping):
                associated_subnets.append(None)
                continue
            subnet_value = association.get("SubnetId")
            associated_subnets.append(
                subnet_value if isinstance(subnet_value, str) and subnet_value else None
            )
    else:
        associated_subnets.append(None)
    if all(isinstance(value, str) for value in associated_subnets):
        associated_subnets = sorted(associated_subnets)
    return (
        [
            {
                "destination": (
                    route.get("DestinationCidrBlock")
                    or route.get("DestinationIpv6CidrBlock")
                    or route.get("DestinationPrefixListId")
                ),
                "target": _route_target(route),
                "state": route.get("State", "UNKNOWN"),
            }
            for route in tables[0].get("Routes", [])
        ],
        associated_subnets,
    )


def _route_target(route: Mapping[str, Any]) -> str | None:
    """Return a route target only when the AWS response has exactly one valid target."""
    target_keys = (
        "CarrierGatewayId",
        "CoreNetworkArn",
        "EgressOnlyInternetGatewayId",
        "GatewayId",
        "InstanceId",
        "IpAddress",
        "LocalGatewayId",
        "NatGatewayId",
        "NetworkInterfaceId",
        "OdbNetworkArn",
        "TransitGatewayId",
        "VpcEndpointId",
        "VpcPeeringConnectionId",
    )
    values = [route[key] for key in target_keys if key in route and route[key] is not None]
    if len(values) != 1:
        return None
    target = values[0]
    return target if isinstance(target, str) and target else None


def _security_group_egress(
    groups: Sequence[Mapping[str, Any]],
) -> list[dict[str, object]] | None:
    """Normalize egress rules, returning None when any attached group is incomplete."""
    if not isinstance(groups, Sequence) or isinstance(groups, (str, bytes)) or not groups:
        return None

    rules: list[dict[str, object]] = []
    for group in groups:
        if not isinstance(group, Mapping):
            return None
        permissions = group.get("IpPermissionsEgress")
        if not isinstance(permissions, Sequence) or isinstance(permissions, (str, bytes)):
            return None

        for permission in permissions:
            if not isinstance(permission, Mapping):
                return None
            protocol = permission.get("IpProtocol")
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            port = from_port if from_port == to_port else None
            initial_rule_count = len(rules)

            for field, cidr_field in (
                ("IpRanges", "CidrIp"),
                ("Ipv6Ranges", "CidrIpv6"),
            ):
                items = permission.get(field, [])
                if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
                    return None
                for item in items:
                    if not isinstance(item, Mapping):
                        return None
                    rules.append(
                        {
                            "protocol": protocol,
                            "port": port,
                            "cidr": item.get(cidr_field),
                        }
                    )

            # Prefix-list and security-group references are not expanded here.
            # Preserve them as unclassifiable rules so the preflight fails closed.
            for field, reference_field in (
                ("PrefixListIds", "PrefixListId"),
                ("UserIdGroupPairs", "GroupId"),
            ):
                items = permission.get(field, [])
                if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
                    return None
                for item in items:
                    if not isinstance(item, Mapping):
                        return None
                    rules.append(
                        {
                            "protocol": protocol,
                            "port": port,
                            "cidr": None,
                            "reference": item.get(reference_field),
                        }
                    )

            if len(rules) == initial_rule_count:
                return None

    return rules


def _security_group_ingress(
    groups: Sequence[Mapping[str, Any]],
) -> list[dict[str, object]] | None:
    """Normalize ingress rules, returning None when source inventory is incomplete."""
    if not isinstance(groups, Sequence) or isinstance(groups, (str, bytes)):
        return None

    rules: list[dict[str, object]] = []
    for group in groups:
        if not isinstance(group, Mapping):
            return None
        permissions = group.get("IpPermissions")
        if not isinstance(permissions, Sequence) or isinstance(permissions, (str, bytes)):
            return None

        for permission in permissions:
            if not isinstance(permission, Mapping):
                return None
            protocol = permission.get("IpProtocol")
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            port = from_port if from_port == to_port else None
            initial_rule_count = len(rules)

            for field, cidr_field in (
                ("IpRanges", "CidrIp"),
                ("Ipv6Ranges", "CidrIpv6"),
            ):
                items = permission.get(field, [])
                if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
                    return None
                for item in items:
                    if not isinstance(item, Mapping):
                        return None
                    rules.append(
                        {
                            "protocol": protocol,
                            "port": port,
                            "cidr": item.get(cidr_field),
                        }
                    )

            for field, reference_field in (
                ("PrefixListIds", "PrefixListId"),
                ("UserIdGroupPairs", "GroupId"),
            ):
                items = permission.get(field, [])
                if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
                    return None
                for item in items:
                    if not isinstance(item, Mapping):
                        return None
                    rules.append(
                        {
                            "protocol": protocol,
                            "port": port,
                            "cidr": None,
                            "reference": item.get(reference_field),
                        }
                    )

            if len(rules) == initial_rule_count:
                return None

    return rules


def _firewall_for_vpc(network_firewall: Any, vpc_id: str) -> Mapping[str, Any] | None:
    firewalls = _all_pages(network_firewall, "list_firewalls", "Firewalls")
    if any(
        not isinstance(firewall, Mapping)
        or not isinstance(firewall.get("VpcId"), str)
        or not firewall.get("VpcId")
        or not isinstance(firewall.get("FirewallArn"), str)
        or not firewall.get("FirewallArn")
        for firewall in firewalls
    ):
        raise ValueError("AWS Network Firewall returned incomplete firewall inventory")
    matches = [firewall for firewall in firewalls if firewall["VpcId"] == vpc_id]
    if len(matches) > 1:
        raise ValueError(
            "multiple Network Firewalls found for the worker VPC; select a policy domain"
        )
    return matches[0] if matches else None


def _resolved_ip_validation(policy: Mapping[str, Any]) -> dict[str, object] | None:
    validation = policy.get("Route53ResolvedIPValidation")
    if not isinstance(validation, Mapping):
        return None

    def address_ranges(name: str) -> list[str] | None:
        values = validation.get(name, [])
        if not isinstance(values, list):
            return None
        normalized: list[str] = []
        for value in values:
            if (
                not isinstance(value, Mapping)
                or not isinstance(value.get("AddressDefinition"), str)
                or not value.get("AddressDefinition")
            ):
                return None
            normalized.append(value["AddressDefinition"])
        return normalized

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
            "rule_actions": [],
            "rule_priorities": [],
            "domain_list_statuses": [],
        }

    group_response = resolver.describe_firewall_rule_group(FirewallRuleGroupId=rule_group_id)
    raw_group = group_response.get("FirewallRuleGroup")
    group = raw_group if isinstance(raw_group, Mapping) else {}
    rule_group_status = group.get("Status", "UNKNOWN")

    associations = _all_pages(
        resolver,
        "list_firewall_rule_group_associations",
        "FirewallRuleGroupAssociations",
        FirewallRuleGroupId=rule_group_id,
    )
    associated_vpcs: list[object] = []
    association_statuses: list[object] = []
    for association in associations:
        if not isinstance(association, Mapping):
            associated_vpcs.append(None)
            association_statuses.append(None)
            continue
        vpc_value = association.get("VpcId")
        associated_vpcs.append(vpc_value if isinstance(vpc_value, str) and vpc_value else None)
        status = association.get("Status", "UNKNOWN")
        association_statuses.append(status if isinstance(status, str) and status else None)

    rules = _all_pages(
        resolver,
        "list_firewall_rules",
        "FirewallRules",
        FirewallRuleGroupId=rule_group_id,
    )
    rule_statuses: list[object] = []
    rule_actions: list[object] = []
    rule_priorities: list[object] = []
    allowlist_domains: set[str] = set()
    allowlist_has_malformed_domain = False
    allow_priorities: list[int] = []
    wildcard_block_priorities: list[int] = []
    domain_list_statuses: list[object] = []
    domain_list_cache: dict[str, list[object]] = {}

    for rule in rules:
        if not isinstance(rule, Mapping):
            rule_statuses.append(None)
            rule_actions.append(None)
            rule_priorities.append(None)
            domain_list_statuses.append(None)
            allowlist_has_malformed_domain = True
            continue

        status = rule.get("Status", "UNKNOWN")
        rule_statuses.append(status if isinstance(status, str) and status else None)
        domain_list_id = rule.get("FirewallDomainListId")
        priority = rule.get("Priority")
        action = rule.get("Action")
        priority_is_valid = type(priority) is int and 1 <= priority <= 10000
        action_is_valid = isinstance(action, str) and action in {"ALLOW", "BLOCK"}
        rule_actions.append(action if action_is_valid else None)
        rule_priorities.append(priority if priority_is_valid else None)
        if (
            not isinstance(domain_list_id, str)
            or not domain_list_id
            or not priority_is_valid
            or not action_is_valid
        ):
            domain_list_statuses.append(None)
            allowlist_has_malformed_domain = True
            continue

        if domain_list_id not in domain_list_cache:
            metadata_response = resolver.get_firewall_domain_list(
                FirewallDomainListId=domain_list_id
            )
            raw_metadata = metadata_response.get("FirewallDomainList")
            metadata = raw_metadata if isinstance(raw_metadata, Mapping) else {}
            domain_status = metadata.get("Status", "UNKNOWN")
            domain_list_statuses.append(
                domain_status if isinstance(domain_status, str) and domain_status else None
            )
            raw_domains = _all_pages(
                resolver,
                "list_firewall_domains",
                "Domains",
                FirewallDomainListId=domain_list_id,
            )
            domains: list[object] = [
                value if isinstance(value, str) and value else None for value in raw_domains
            ]
            domain_list_cache[domain_list_id] = domains
            if any(value is None for value in domains):
                allowlist_has_malformed_domain = True

        domains = domain_list_cache[domain_list_id]
        if action == "ALLOW":
            allowlist_domains.update(value for value in domains if isinstance(value, str))
        if action == "BLOCK" and "*" in domains:
            wildcard_block_priorities.append(priority)
        if action == "ALLOW":
            allow_priorities.append(priority)

    terminal_block = (
        bool(allow_priorities)
        and bool(wildcard_block_priorities)
        and min(wildcard_block_priorities) > max(allow_priorities)
    )

    config_response = resolver.get_firewall_config(ResourceId=vpc_id)
    raw_config = config_response.get("FirewallConfig")
    config = raw_config if isinstance(raw_config, Mapping) else {}
    fail_open = config.get("FirewallFailOpen")
    failure_mode = (
        "CLOSED" if fail_open == "DISABLED" else "OPEN" if fail_open == "ENABLED" else "UNKNOWN"
    )

    normalized_allowlist: list[object] = sorted(allowlist_domains)
    if allowlist_has_malformed_domain:
        normalized_allowlist.append(None)

    return {
        "rule_group_id": rule_group_id,
        "associated_vpc_ids": associated_vpcs,
        "allowlist_domains": normalized_allowlist,
        "terminal_block": terminal_block,
        "failure_mode": failure_mode,
        "rule_group_status": rule_group_status,
        "association_statuses": association_statuses,
        "rule_statuses": rule_statuses,
        "rule_actions": rule_actions,
        "rule_priorities": rule_priorities,
        "domain_list_statuses": domain_list_statuses,
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
        stateful_options = raw_stateful_options if isinstance(raw_stateful_options, Mapping) else {}
        targets = domain_list.get("Targets", [])
        target_types = domain_list.get("TargetTypes", [])

        def preserve_string_collection(values: object) -> list[object] | None:
            if not isinstance(values, list):
                return None
            if all(isinstance(value, str) and value for value in values):
                return sorted(values)
            return list(values)

        snapshots.append(
            {
                "status": response_metadata.get("RuleGroupStatus", "UNKNOWN"),
                "type": response_metadata.get("Type", "UNKNOWN"),
                "rule_order": stateful_options.get("RuleOrder"),
                "generated_rules_type": domain_list.get("GeneratedRulesType"),
                "targets": preserve_string_collection(targets),
                "target_types": preserve_string_collection(target_types),
            }
        )
    return snapshots


def _network_acl_snapshot(ec2: Any, subnet_id: str) -> dict[str, object]:
    """Return the worker subnet's exact NACL association and normalized egress rules."""
    network_acls = _all_pages(
        ec2,
        "describe_network_acls",
        "NetworkAcls",
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}],
    )
    invalid_snapshot = {
        "associated": False,
        "network_acl_id": None,
        "subnet_ids": [],
        "egress_rules": None,
        "ingress_rules": None,
    }
    matches = []
    for acl in network_acls:
        # The API filter scopes this response to the requested subnet. Any
        # malformed record or association therefore makes the scoped inventory
        # incomplete; never ignore it just because another record looks valid.
        if not isinstance(acl, Mapping):
            return invalid_snapshot
        associations = acl.get("Associations")
        if not isinstance(associations, list):
            return invalid_snapshot
        for association in associations:
            if (
                not isinstance(association, Mapping)
                or not isinstance(association.get("SubnetId"), str)
                or not association.get("SubnetId")
            ):
                return invalid_snapshot
        if any(association["SubnetId"] == subnet_id for association in associations):
            matches.append(acl)
    if len(matches) != 1:
        return invalid_snapshot

    acl = matches[0]
    raw_associations = acl.get("Associations", [])
    subnet_ids: list[object] = []
    if isinstance(raw_associations, list):
        for association in raw_associations:
            if not isinstance(association, Mapping):
                subnet_ids.append(None)
                continue
            subnet_value = association.get("SubnetId")
            subnet_ids.append(
                subnet_value if isinstance(subnet_value, str) and subnet_value else None
            )
    else:
        subnet_ids.append(None)
    if all(isinstance(value, str) for value in subnet_ids):
        subnet_ids = sorted(subnet_ids)

    ingress_rules: list[dict[str, object]] | None = []
    egress_rules: list[dict[str, object]] | None = []
    entries = acl.get("Entries")
    invalid_entry_inventory = "Entries" not in acl or not isinstance(entries, list)
    if not isinstance(entries, list):
        entries = []
    for entry in entries:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("Egress"), bool):
            invalid_entry_inventory = True
            continue
        raw_port_range = entry.get("PortRange")
        if raw_port_range is not None and not isinstance(raw_port_range, Mapping):
            invalid_entry_inventory = True
            continue
        port_range = raw_port_range if isinstance(raw_port_range, Mapping) else {}
        rule = {
            "rule_number": entry.get("RuleNumber"),
            "protocol": entry.get("Protocol"),
            "action": entry.get("RuleAction"),
            "cidr": entry.get("CidrBlock") or entry.get("Ipv6CidrBlock"),
            "from_port": port_range.get("From"),
            "to_port": port_range.get("To"),
        }
        if entry["Egress"] is True:
            egress_rules.append(rule)
        else:
            ingress_rules.append(rule)

    if invalid_entry_inventory:
        ingress_rules = None
        egress_rules = None
    else:

        def sort_key(rule: dict[str, object]) -> int:
            rule_number = rule["rule_number"]
            return rule_number if isinstance(rule_number, int) else 2**31

        ingress_rules.sort(key=sort_key)
        egress_rules.sort(key=sort_key)

    return {
        "associated": True,
        "network_acl_id": acl.get("NetworkAclId"),
        "subnet_ids": subnet_ids,
        "ingress_rules": ingress_rules,
        "egress_rules": egress_rules,
    }


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

    vpcs = _all_pages(ec2, "describe_vpcs", "Vpcs", VpcIds=[vpc_id])
    vpc = next((item for item in vpcs if item.get("VpcId") == vpc_id), None)
    vpc_cidr = vpc.get("CidrBlock") if isinstance(vpc, Mapping) else None
    raw_cidr_associations = (
        vpc.get("CidrBlockAssociationSet", []) if isinstance(vpc, Mapping) else []
    )
    vpc_cidr_associations: list[dict[str, object]] = []
    if isinstance(raw_cidr_associations, list):
        for association in raw_cidr_associations:
            if not isinstance(association, Mapping):
                vpc_cidr_associations.append({"cidr": None, "state": None})
                continue
            raw_state = association.get("CidrBlockState")
            state = raw_state.get("State") if isinstance(raw_state, Mapping) else None
            vpc_cidr_associations.append({"cidr": association.get("CidrBlock"), "state": state})
    else:
        vpc_cidr_associations.append({"cidr": None, "state": None})
    try:
        vpc_network = ipaddress.ip_network(vpc_cidr, strict=False)
        resolver_ip = str(vpc_network.network_address + 2) if vpc_network.version == 4 else None
    except ValueError:
        resolver_ip = None

    network_acl = _network_acl_snapshot(ec2, subnet_id)

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
    raw_route_associations = route_tables[0].get("Associations", []) if route_tables else []
    route_table_subnet_ids: list[object] = []
    if isinstance(raw_route_associations, list):
        for association in raw_route_associations:
            if not isinstance(association, Mapping):
                route_table_subnet_ids.append(None)
                continue
            subnet_value = association.get("SubnetId")
            route_table_subnet_ids.append(
                subnet_value if isinstance(subnet_value, str) and subnet_value else None
            )
    else:
        route_table_subnet_ids.append(None)
    if all(isinstance(value, str) for value in route_table_subnet_ids):
        route_table_subnet_ids = sorted(route_table_subnet_ids)
    routes = route_tables[0].get("Routes", []) if route_tables else []
    route_entries = [
        {
            "destination": (
                route.get("DestinationCidrBlock")
                or route.get("DestinationIpv6CidrBlock")
                or route.get("DestinationPrefixListId")
            ),
            "target": _route_target(route),
            "state": route.get("State", "UNKNOWN"),
        }
        for route in routes
    ]
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
    raw_interfaces = instance.get("NetworkInterfaces")
    ipv6_address_values: list[str] = []
    invalid_ipv6_inventory = not isinstance(raw_interfaces, list) or not raw_interfaces
    if isinstance(raw_interfaces, list):
        for interface in raw_interfaces:
            if not isinstance(interface, Mapping):
                invalid_ipv6_inventory = True
                continue
            raw_ipv6_addresses = interface.get("Ipv6Addresses", [])
            if not isinstance(raw_ipv6_addresses, list):
                invalid_ipv6_inventory = True
                continue
            for address in raw_ipv6_addresses:
                if not isinstance(address, Mapping):
                    invalid_ipv6_inventory = True
                    continue
                ipv6_address = address.get("Ipv6Address")
                if not isinstance(ipv6_address, str) or not ipv6_address:
                    invalid_ipv6_inventory = True
                    continue
                ipv6_address_values.append(ipv6_address)
    ipv6_addresses: list[object] = sorted(set(ipv6_address_values))
    if invalid_ipv6_inventory:
        # A truthy sentinel makes the existing topology policy reject an
        # incomplete ENI/IPv6 inventory rather than infer "no IPv6" from it.
        ipv6_addresses.append(None)

    raw_security_groups = instance.get("SecurityGroups", [])
    security_group_inventory_valid = isinstance(raw_security_groups, list) and all(
        isinstance(group, Mapping)
        and isinstance(group.get("GroupId"), str)
        and bool(group.get("GroupId"))
        for group in raw_security_groups
    )
    security_group_ids = (
        sorted({group["GroupId"] for group in raw_security_groups})
        if security_group_inventory_valid
        else []
    )
    security_groups = (
        _all_pages(ec2, "describe_security_groups", "SecurityGroups", GroupIds=security_group_ids)
        if security_group_ids and security_group_inventory_valid
        else []
    )

    metadata_options = instance.get("MetadataOptions")
    metadata_options = metadata_options if isinstance(metadata_options, Mapping) else {}
    raw_ipv6_auto_assign = subnet.get("AssignIpv6AddressOnCreation")
    raw_ipv6_cidr_associations = subnet.get("Ipv6CidrBlockAssociationSet")
    ipv6_subnet_inventory_valid = isinstance(raw_ipv6_auto_assign, bool) and isinstance(
        raw_ipv6_cidr_associations, list
    )
    ipv6_enabled = (
        raw_ipv6_auto_assign or bool(raw_ipv6_cidr_associations)
        if ipv6_subnet_inventory_valid
        else None
    )

    worker = {
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "vpc_cidr": vpc_cidr,
        "vpc_cidr_associations": vpc_cidr_associations,
        "resolver_ip": resolver_ip,
        "network_acl": network_acl,
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
        "ipv6_enabled": ipv6_enabled,
        "availability_zone": availability_zone,
        "default_route_target": _route_target(default_route) if default_route else None,
        "route_table_subnet_ids": route_table_subnet_ids,
        "route_entries": route_entries,
        "ipv6_default_route_target": (
            _route_target(ipv6_default_route) if ipv6_default_route else None
        ),
        "ipv6_addresses": ipv6_addresses,
        "security_group_ingress": (
            _security_group_ingress(security_groups) if security_group_inventory_valid else None
        ),
        "security_group_egress": (
            _security_group_egress(security_groups) if security_group_inventory_valid else None
        ),
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

        # Capture the reverse service-chain path as well as the worker route.
        # AWS Network Firewall is stateful: the firewall subnet must send approved
        # traffic to NAT, and the NAT subnet must return worker-subnet traffic
        # through the same-AZ firewall endpoint.
        sync_states = firewall_status.get("SyncStates", {})
        az_state = (
            sync_states.get(availability_zone, {}) if isinstance(sync_states, Mapping) else {}
        )
        attachment = az_state.get("Attachment", {}) if isinstance(az_state, Mapping) else {}
        firewall_subnet_id = attachment.get("SubnetId")
        if not isinstance(firewall_subnet_id, str):
            mappings = firewall.get("SubnetMappings")
            mappings_are_complete = isinstance(mappings, list) and all(
                isinstance(mapping, Mapping)
                and isinstance(mapping.get("SubnetId"), str)
                and bool(mapping.get("SubnetId"))
                for mapping in mappings
            )
            matching_mappings = (
                [
                    mapping
                    for mapping in mappings
                    if mapping.get("AvailabilityZone") == availability_zone
                ]
                if mappings_are_complete
                else []
            )
            if len(matching_mappings) == 1:
                firewall_subnet_id = matching_mappings[0]["SubnetId"]

        firewall_subnet = None
        firewall_route_entries: list[dict[str, object]] = []
        firewall_route_table_subnet_ids: list[str] = []
        nat_gateway_id = None
        nat_gateway_state = "UNKNOWN"
        nat_subnet_id = None
        nat_route_entries: list[dict[str, object]] = []
        nat_route_table_subnet_ids: list[str] = []
        nat_az = None
        firewall_az = None
        if isinstance(firewall_subnet_id, str):
            firewall_subnets = _all_pages(
                ec2, "describe_subnets", "Subnets", SubnetIds=[firewall_subnet_id]
            )
            firewall_subnet = next(
                (item for item in firewall_subnets if item.get("SubnetId") == firewall_subnet_id),
                None,
            )
            if isinstance(firewall_subnet, Mapping):
                firewall_az = firewall_subnet.get("AvailabilityZone")
                (
                    firewall_route_entries,
                    firewall_route_table_subnet_ids,
                ) = _route_entries_for_subnet(ec2, vpc_id=vpc_id, subnet_id=firewall_subnet_id)
                nat_route = next(
                    (
                        route
                        for route in firewall_route_entries
                        if route.get("destination") == "0.0.0.0/0"
                    ),
                    None,
                )
                candidate_nat_id = (
                    nat_route.get("target") if isinstance(nat_route, Mapping) else None
                )
                if isinstance(candidate_nat_id, str) and candidate_nat_id.startswith("nat-"):
                    nat_gateway_id = candidate_nat_id
                    nat_gateways = _all_pages(
                        ec2,
                        "describe_nat_gateways",
                        "NatGateways",
                        NatGatewayIds=[nat_gateway_id],
                    )
                    nat_gateway = next(
                        (
                            item
                            for item in nat_gateways
                            if item.get("NatGatewayId") == nat_gateway_id
                        ),
                        None,
                    )
                    if isinstance(nat_gateway, Mapping):
                        nat_gateway_state = nat_gateway.get("State", "UNKNOWN")
                        raw_nat_subnet_id = nat_gateway.get("SubnetId")
                        if isinstance(raw_nat_subnet_id, str):
                            nat_subnet_id = raw_nat_subnet_id
                            (
                                nat_route_entries,
                                nat_route_table_subnet_ids,
                            ) = _route_entries_for_subnet(
                                ec2, vpc_id=vpc_id, subnet_id=nat_subnet_id
                            )
                            nat_subnets = _all_pages(
                                ec2, "describe_subnets", "Subnets", SubnetIds=[nat_subnet_id]
                            )
                            nat_subnet = next(
                                (
                                    item
                                    for item in nat_subnets
                                    if item.get("SubnetId") == nat_subnet_id
                                ),
                                None,
                            )
                            if isinstance(nat_subnet, Mapping):
                                nat_az = nat_subnet.get("AvailabilityZone")

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
        engine_options = raw_engine_options if isinstance(raw_engine_options, Mapping) else {}
        firewall_snapshot = {
            "endpoints_by_az": endpoints,
            "subnet_id": firewall_subnet_id,
            "availability_zone": firewall_az,
            "nat_gateway_id": nat_gateway_id,
            "nat_gateway_state": nat_gateway_state,
            "nat_subnet_id": nat_subnet_id,
            "route_entries": firewall_route_entries,
            "route_table_subnet_ids": firewall_route_table_subnet_ids,
            "nat_route_entries": nat_route_entries,
            "nat_route_table_subnet_ids": nat_route_table_subnet_ids,
            "nat_availability_zone": nat_az,
            "policy": {
                "route53_resolved_ip_validation": validation,
                "status": policy_metadata.get("FirewallPolicyStatus", "UNKNOWN"),
                "errors": policy_errors if isinstance(policy_errors, list) else None,
                "stateful_rule_order": engine_options.get("RuleOrder"),
                "stateful_default_actions": policy.get("StatefulDefaultActions", []),
                "stateful_rule_groups": _stateful_rule_group_snapshots(network_firewall, policy),
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
