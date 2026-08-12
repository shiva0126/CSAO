"""
===============================================================================
Cloud Security Assessment Orchestrator (CSAO)

Attack Path Engine

Methodology step: Threat Correlation / Attack Path Identification.

Purpose
-------
Builds a directed relationship graph from ACTUAL cloud relationships found
in collected evidence (asset inventory + IAM policy documents), then walks
that graph from internet-facing findings toward Crown Jewel resources.
Findings are only ever chained together when the underlying resources are
genuinely connected in the graph - this engine never correlates findings
just because they share a severity or a tool.

Relationship types modeled (derived from evidence actually collected today):

  EC2         --ATTACHED_TO-->     IAM_ROLE   (instance profile)
  EC2         --SECURED_BY-->      SECURITY_GROUP
  EC2         --CONNECTS_TO-->     VPC
  LAMBDA      --EXECUTION_ROLE-->  IAM_ROLE
  IAM_ROLE    --CAN_ACCESS-->      S3_BUCKET  (from IAM policy Resource ARNs)
  IAM_ROLE    --ASSUME_ROLE-->     IAM_ROLE   (cross-account trust policy)

Not yet modeled (no evidence collector exists yet for these - left as an
explicit extension point rather than faked):
  API Gateway -> backend resource

Every discovered path is written as an Attack Path CANDIDATE - this engine
never asserts exploitability, only connectivity + control gaps along the
way.

READ ONLY

===============================================================================
"""

import json
import re
from pathlib import Path

import networkx as nx

from rich.console import Console
from loguru import logger

from core.engines.assessment_knowledge_engine import AssessmentKnowledgeEngine


console = Console()


def short_name(arn_or_name):

    if not arn_or_name:

        return arn_or_name

    return str(arn_or_name).split("/")[-1].split(":")[-1]


class AttackPathEngine:

    def __init__(self, config, crown_jewel_engine, knowledge_engine=None):

        self.config = config

        self.crown_jewel_engine = crown_jewel_engine
        self.knowledge = knowledge_engine or AssessmentKnowledgeEngine(config)

        self.max_hops = config.get("attack_path", {}).get("max_hops", 5)

        self.inventory_dir = Path("output/raw/aws_inventory")

        self.output_directory = Path("output/attack_paths")

        self.output_directory.mkdir(parents=True, exist_ok=True)

        self.graph = nx.DiGraph()

        # resource_id/resource_name -> node_id, so Findings can be mapped
        # onto graph nodes without re-deriving inventory parsing logic.
        self.resource_index = {}

    ###########################################################################
    # Load helpers
    ###########################################################################

    def load_json(self, path):

        path = Path(path)

        if not path.exists():

            return None

        try:

            return json.load(open(path))

        except Exception:

            return None

    ###########################################################################
    # Graph construction
    ###########################################################################

    def add_node(self, node_type, key, resource_id=None, resource_name=None):

        node_id = f"{node_type}:{key}"

        resource_id = resource_id or key
        resource_name = resource_name or key

        if not self.graph.has_node(node_id):

            self.graph.add_node(

                node_id,

                type=node_type,
                resource_id=resource_id,
                resource_name=resource_name,
                internet_facing=False,
                crown_jewel=self.crown_jewel_engine.is_crown_jewel(
                    resource_id, resource_name
                ),

            )

        self.resource_index[resource_id] = node_id
        self.resource_index[resource_name] = node_id

        return node_id

    def build_from_inventory(self):

        ec2 = self.load_json(self.inventory_dir / "ec2.json") or []
        roles = self.load_json(self.inventory_dir / "iam_roles.json") or []
        buckets = self.load_json(self.inventory_dir / "s3.json") or []
        functions = self.load_json(self.inventory_dir / "lambda.json") or []
        security_groups = self.load_json(self.inventory_dir / "security_groups.json") or []
        vpcs = self.load_json(self.inventory_dir / "vpc.json") or []

        for vpc in vpcs:

            self.add_node("VPC", vpc.get("VpcId"))

        for sg in security_groups:

            self.add_node("SECURITY_GROUP", sg.get("GroupId"), resource_name=sg.get("GroupName"))

        for role in roles:

            self.add_node("IAM_ROLE", role.get("RoleName"), resource_id=role.get("Arn"))

        for bucket in buckets:

            self.add_node("S3_BUCKET", bucket.get("Name"))

        for instance in ec2:

            instance_id = instance.get("InstanceId")

            if not instance_id:

                continue

            node = self.add_node("EC2", instance_id)

            if instance.get("PublicIpAddress"):

                self.graph.nodes[node]["internet_facing"] = True

            # Instance profile -> IAM role. describe_instances only returns
            # the instance PROFILE arn, not the role name directly; in the
            # overwhelming majority of environments the profile name
            # matches the role name 1:1, which we use as a stand-in until
            # a dedicated iam:get-instance-profile collector is added.
            profile = (instance.get("IamInstanceProfile") or {}).get("Arn")

            if profile:

                role_node = self.add_node("IAM_ROLE", short_name(profile))

                self.graph.add_edge(node, role_node, relationship="ATTACHED_TO")

            for sg in instance.get("SecurityGroups", []):

                sg_node = self.add_node(
                    "SECURITY_GROUP", sg.get("GroupId"), resource_name=sg.get("GroupName")
                )

                self.graph.add_edge(node, sg_node, relationship="SECURED_BY")

            vpc_id = instance.get("VpcId")

            if vpc_id:

                vpc_node = self.add_node("VPC", vpc_id)

                self.graph.add_edge(node, vpc_node, relationship="CONNECTS_TO")

        for function in functions:

            function_name = function.get("FunctionName")

            if not function_name:

                continue

            node = self.add_node(
                "LAMBDA", function_name, resource_id=function.get("FunctionArn")
            )

            role_arn = function.get("Role")

            if role_arn:

                role_node = self.add_node("IAM_ROLE", short_name(role_arn))

                self.graph.add_edge(node, role_node, relationship="EXECUTION_ROLE")

    ###########################################################################
    # IAM policy -> CAN_ACCESS / ASSUME_ROLE edges
    ###########################################################################

    S3_ARN_PATTERN = re.compile(r"arn:aws:s3:::([^/\"]+)")

    def resolve_policy_documents(self, role, all_policies):

        documents = []

        for inline in role.get("RolePolicyList", []) or []:

            document = inline.get("PolicyDocument")

            if document:

                documents.append(document)

        attached_arns = {
            p.get("PolicyArn")
            for p in role.get("AttachedManagedPolicies", []) or []
        }

        for policy in all_policies:

            if policy.get("Arn") not in attached_arns:

                continue

            for version in policy.get("PolicyVersionList", []) or []:

                if version.get("IsDefaultVersion") and version.get("Document"):

                    documents.append(version["Document"])

        return documents

    def statements(self, document):

        statement = document.get("Statement", [])

        return statement if isinstance(statement, list) else [statement]

    def build_from_iam_policies(self):

        auth = self.load_json(
            "output/raw/cloudsplaining/authorization-details.json"
        )

        if not auth:

            return

        all_policies = auth.get("Policies", []) or []

        for role in auth.get("RoleDetailList", []) or []:

            role_name = role.get("RoleName")

            if not role_name:

                continue

            role_node = self.add_node("IAM_ROLE", role_name, resource_id=role.get("Arn"))

            # CAN_ACCESS S3 - scan every attached/inline policy's Allow
            # statements for S3 bucket ARNs and link to matching inventory.

            for document in self.resolve_policy_documents(role, all_policies):

                for statement in self.statements(document):

                    if statement.get("Effect") != "Allow":

                        continue

                    resources = statement.get("Resource", [])

                    resources = resources if isinstance(resources, list) else [resources]

                    for resource in resources:

                        for bucket_name in self.S3_ARN_PATTERN.findall(str(resource)):

                            if bucket_name == "*":

                                continue

                            bucket_node = self.add_node("S3_BUCKET", bucket_name)

                            self.graph.add_edge(
                                role_node, bucket_node, relationship="CAN_ACCESS"
                            )

            # ASSUME_ROLE - cross-account / role-chained trust relationships.

            trust_document = role.get("AssumeRolePolicyDocument") or {}

            for statement in self.statements(trust_document):

                if statement.get("Effect") != "Allow":

                    continue

                principal = statement.get("Principal", {})

                aws_principals = principal.get("AWS", []) if isinstance(principal, dict) else []

                aws_principals = aws_principals if isinstance(aws_principals, list) else [aws_principals]

                for principal_arn in aws_principals:

                    if ":role/" in str(principal_arn):

                        principal_node = self.add_node("IAM_ROLE", short_name(principal_arn))

                        self.graph.add_edge(
                            principal_node, role_node, relationship="ASSUME_ROLE"
                        )

    ###########################################################################
    # Mark internet-facing nodes from Findings (covers S3/Lambda/etc. where
    # "is this public" can only be determined from tool findings, not raw
    # inventory alone).
    ###########################################################################

    def mark_internet_facing(self, findings):

        for finding in findings:

            if finding.internet_facing != "Yes":

                continue

            node_id = (
                self.resource_index.get(finding.resource_id)
                or self.resource_index.get(finding.resource_name)
            )

            if node_id:

                self.graph.nodes[node_id]["internet_facing"] = True

    def records_to_findings(self, records):

        return [getattr(record, "_finding", record) for record in records]

    ###########################################################################
    # Crown Jewel proximity (graph distance), used by the Risk Engine
    ###########################################################################

    def compute_crown_jewel_proximity(self, findings):

        jewel_nodes = [
            n for n, data in self.graph.nodes(data=True) if data.get("crown_jewel")
        ]

        if not jewel_nodes:

            return

        reverse = self.graph.reverse(copy=True)

        distances = {}

        for jewel in jewel_nodes:

            for node, distance in nx.single_source_shortest_path_length(
                reverse, jewel, cutoff=self.max_hops
            ).items():

                if node not in distances or distance < distances[node]:

                    distances[node] = distance

        for finding in findings:

            node_id = (
                self.resource_index.get(finding.resource_id)
                or self.resource_index.get(finding.resource_name)
            )

            if node_id in distances:

                finding._crown_jewel_proximity = distances[node_id]

    ###########################################################################
    # Attack path discovery
    ###########################################################################

    def find_candidates(self, findings, correlated_threats=None):

        if correlated_threats is None:
            correlated_threats = []

        if not correlated_threats:
            return []

        return self.find_candidates_from_threats(findings, correlated_threats)

    def find_candidates_from_threats(self, records, correlated_threats):

        candidates = []
        findings = self.records_to_findings(records)

        findings_by_node = {}

        for record in records:
            finding = getattr(record, "_finding", record)
            node_id = (
                self.resource_index.get(finding.resource_id)
                or self.resource_index.get(finding.resource_name)
            )

            if node_id:
                findings_by_node.setdefault(node_id, []).append((record, finding))

        for threat in correlated_threats:

            source_nodes = [
                self.resource_index.get(resource)
                for resource in threat.source_resources
                if self.resource_index.get(resource)
            ]
            target_nodes = [
                self.resource_index.get(resource)
                for resource in threat.target_resources
                if self.resource_index.get(resource)
            ]

            if not source_nodes:
                source_nodes = [
                    node_id
                    for node_id, data in self.graph.nodes(data=True)
                    if data.get("internet_facing")
                ]

            if not target_nodes:
                target_nodes = [
                    node_id
                    for node_id, data in self.graph.nodes(data=True)
                    if data.get("crown_jewel")
                ]

            template_refs = set(threat.attack_path_refs)
            for scenario_id in threat.scenario_ids:
                scenario = self.knowledge.threat_scenario(scenario_id)
                if scenario:
                    template_refs.update(scenario.attack_path_refs)

            for entry in source_nodes:
                for jewel in target_nodes:
                    if entry == jewel:
                        continue

                    if not nx.has_path(self.graph, entry, jewel):
                        continue

                    for path in nx.all_simple_paths(self.graph, entry, jewel, cutoff=self.max_hops):
                        candidate_id = f"AP-{len(candidates) + 1:03d}"
                        hops = []

                        for index, node_id in enumerate(path):
                            data = self.graph.nodes[node_id]
                            relationship = None

                            if index > 0:
                                edge = self.graph.get_edge_data(path[index - 1], node_id)
                                relationship = edge.get("relationship") if edge else None

                            hop_findings = []

                            for record, finding in findings_by_node.get(node_id, []):
                                hop_findings.append(finding.title)
                                finding.attack_path_candidate = (
                                    candidate_id
                                    if not finding.attack_path_candidate
                                    else f"{finding.attack_path_candidate},{candidate_id}"
                                )
                                if candidate_id not in getattr(finding, "attack_path_ids", []):
                                    finding.attack_path_ids.append(candidate_id)

                                if hasattr(record, "attack_path_references") and candidate_id not in record.attack_path_references:
                                    record.attack_path_references.append(candidate_id)

                            hops.append({
                                "node": node_id,
                                "type": data.get("type"),
                                "resource_id": data.get("resource_id"),
                                "relationship_from_previous": relationship,
                                "findings": hop_findings,
                            })

                        candidates.append({
                            "id": candidate_id,
                            "label": "correlated threat path - connectivity confirmed, exploitability not asserted",
                            "entry_point": entry,
                            "crown_jewel_target": jewel,
                            "hop_count": len(path) - 1,
                            "hops": hops,
                            "correlated_threats": threat.scenario_ids,
                            "template_refs": sorted(template_refs),
                            "analyst_decision": threat.analyst_decision,
                        })

        return candidates

    ###########################################################################
    # Save
    ###########################################################################

    def save(self, candidates):

        output_file = self.output_directory / "attack_path_candidates.json"

        with open(output_file, "w") as f:

            json.dump(candidates, f, indent=4, default=str)

        logger.success(
            f"Attack path candidates saved : {output_file}"
        )

    ###########################################################################
    # Run
    ###########################################################################

    def run(self, records, correlated_threats=None):

        console.rule(
            "[bold cyan]Attack Path Identification"
        )

        findings = self.records_to_findings(records)

        self.build_from_inventory()

        self.build_from_iam_policies()

        self.mark_internet_facing(findings)

        self.compute_crown_jewel_proximity(findings)

        candidates = self.find_candidates(records, correlated_threats=correlated_threats)

        self.save(candidates)

        console.print(
            f"[green]Attack Path graph : {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges[/green]"
        )

        console.print(
            f"[green]Identified {len(candidates)} attack path candidate(s)[/green]"
        )

        return candidates
