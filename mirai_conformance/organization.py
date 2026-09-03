"""Independent, bounded checks for the 2.3 local organization corpus.

This module does not execute providers or import the TypeScript implementation.
Recorded acceptance is checked for consistency, not treated as authorization.
"""
from __future__ import annotations

import argparse
import copy
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from .canonical import digest_value
from .validator import value_matches_type


def require(condition, code):
    if not condition:
        raise ValueError(code)


def sealed(value):
    return {**value, "digest": digest_value(value)}


def check_digest(value):
    require(value.get("digest") == digest_value({k: v for k, v in value.items() if k != "digest"}), "digest_mismatch")


def check_graph(graph, schemas):
    Draft202012Validator(schemas["graph-operation-snapshot"], format_checker=FormatChecker()).validate(graph)
    check_digest(graph)
    objects = {item["id"]: item for item in graph["objects"]}
    sources = {item["id"]: item for item in graph["sources"]}
    require(len(objects) == len(graph["objects"]) and len(sources) == len(graph["sources"]), "duplicate_identity")
    require(len({r["id"] for r in graph["relations"]}) == len(graph["relations"]), "duplicate_relation")
    for obj in objects.values():
        require(all(ref in sources for ref in obj["source_refs"]), "unknown_source")
    for relation in graph["relations"]:
        require(all(p["ref"] in objects for p in relation["participants"]), "unknown_participant")
        require(len({p["role"] for p in relation["participants"]}) == len(relation["participants"]), "duplicate_role")
        require(all(p["source_ref"] in sources and ("evidence_ref" not in p or p["evidence_ref"] in sources) for p in relation["provenance"]), "unknown_provenance")


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def neighborhood_members(graph, policy, group, group_count):
    neighborhood = policy["neighborhood"]
    now = timestamp(neighborhood["now"])
    objects = {obj["id"] for obj in graph["objects"] if obj["scope"] == group["scope"]}
    edges = []
    for edge in graph["relations"]:
        if edge["type"] not in neighborhood["relation_types"] or not {p["ref"] for p in edge["participants"]} <= objects:
            continue
        if edge.get("scope", group["scope"]) != group["scope"] or edge.get("activation_rule") or edge.get("conditions"):
            continue
        if ("valid_from" in edge and now < timestamp(edge["valid_from"])) or ("valid_until" in edge and now > timestamp(edge["valid_until"])):
            continue
        edges.append(edge)
    selected, traversed = set(group["member_ids"]), set()
    frontier, depth, visits = set(selected), 0, 0
    while frontier:
        reached = set()
        for edge in edges:
            visits += len(edge["participants"])
            require(visits <= max(1, 1000000 // group_count), "neighborhood_work_budget")
            members = {p["ref"] for p in edge["participants"]}
            if members & frontier:
                traversed.add(edge["id"])
                reached.update(members - selected)
        require(len(traversed) <= 10000 and len(selected | reached) <= policy["max_group_size"], "neighborhood_size_budget")
        require(not reached or depth < neighborhood["max_depth"], "neighborhood_depth_budget")
        selected.update(reached)
        frontier = reached
        depth += 1
    return sorted(selected)


def finish_groups(graph, policy, groups, origin, provider_record=None):
    objects = {obj["id"]: obj for obj in graph["objects"]}
    counts = Counter()
    for group in groups.values():
        members = group["member_ids"]
        require(0 < len(members) == len(set(members)) <= policy["max_group_size"], "group_members")
        require(group["key"] in policy["keys"] and all(m in objects and objects[m]["scope"] == group["scope"] for m in members), "group_scope")
        group["member_ids"] = sorted(members)
        group["evidence_refs"] = sorted({ref for member in members for ref in objects[member]["source_refs"]})
        counts.update(members)
        group["revision_digest"] = digest_value(group)
    require(len(groups) <= policy["max_groups"] and sum(counts.values()) <= policy["max_memberships"], "cluster_budget")
    return sealed({"contract_version": "1.0.0", "base_digest": graph["digest"], "policy": policy,
                   "policy_digest": digest_value(policy), "origin": origin, "groups": sorted(groups.values(), key=lambda g: g["id"]),
                   "unassigned_ids": sorted(set(objects) - set(counts)), "overlapping_ids": sorted(k for k, v in counts.items() if v > 1),
                   "status": "proposed", "canonical_write_allowed": False,
                   **({"provider_record": provider_record} if provider_record is not None else {})})


def rule_proposal(graph, policy):
    groups = {}
    objects = {obj["id"]: obj for obj in graph["objects"]}
    for obj in graph["objects"]:
        for key in sorted(policy["keys"]):
            if key not in obj["metadata"]:
                continue
            raw = obj["metadata"][key]
            for value in raw if isinstance(raw, list) else [raw]:
                identity = "cluster." + digest_value([policy["id"], obj["scope"], key, value])[7:]
                group = groups.setdefault(identity, {"id": identity, "scope": obj["scope"], "key": key, "value": value, "member_ids": []})
                group["member_ids"].append(obj["id"])
    require(sum(len(g["member_ids"]) for g in groups.values()) <= policy["max_memberships"], "initial_membership_budget")
    for group in groups.values():
        require(len(group["member_ids"]) <= policy["max_group_size"], "group_budget")
        if "neighborhood" in policy:
            group["member_ids"] = neighborhood_members(graph, policy, group, len(groups))
        group["reason"] = "metadata_and_dependencies" if "neighborhood" in policy else "metadata_match"
    return finish_groups(graph, policy, groups, "rules")


def check_cluster(graph, proposal, schemas):
    check_graph(graph, schemas)
    Draft202012Validator(schemas["cluster-proposal"]).validate(proposal)
    check_digest(proposal)
    policy = proposal["policy"]
    require(policy["keys"] == sorted(policy["keys"]), "policy_not_canonical")
    if "neighborhood" in policy:
        require(policy["neighborhood"]["relation_types"] == sorted(policy["neighborhood"]["relation_types"]), "policy_not_canonical")
    if proposal["origin"] == "rules":
        require(rule_proposal(graph, policy) == proposal, "cluster_semantics_mismatch")
    else:
        record = proposal.get("provider_record")
        require(record and record["input_digest"] == digest_value({"graph_digest": graph["digest"], "policy_digest": digest_value(policy)}), "provider_input_binding")
        groups = {}
        for item in proposal["groups"]:
            identity = "cluster." + digest_value([policy["id"], item["scope"], item["key"], item["value"]])[7:]
            require(identity not in groups, "provider_duplicate_group")
            groups[identity] = {"id": identity, **{k: item[k] for k in ("scope", "key", "value", "member_ids")}, "reason": "provider_proposal"}
        require(finish_groups(graph, policy, groups, "provider", record) == proposal, "provider_membership_binding")


def subset_graph(graph, ids, allowed_sources=None):
    objects = [obj for obj in graph["objects"] if obj["id"] in ids]
    relations = [edge for edge in graph["relations"] if all(p["ref"] in ids for p in edge["participants"])
                 and (allowed_sources is None or all(p["source_ref"] in allowed_sources and ("evidence_ref" not in p or p["evidence_ref"] in allowed_sources) for p in edge["provenance"]))]
    refs = {ref for obj in objects for ref in obj["source_refs"]}
    for edge in relations:
        for provenance in edge["provenance"]:
            refs.add(provenance["source_ref"])
            if "evidence_ref" in provenance:
                refs.add(provenance["evidence_ref"])
    return sealed({"contract_version": "1.0.0", "id": graph["id"], "objects": objects, "relations": relations,
                   "sources": [s for s in graph["sources"] if s["id"] in refs], "canonical_write_allowed": False})


def check_tasks(bundle):
    graph, policy, record = (bundle[k] for k in ("graph", "policy", "record"))
    check_digest(policy)
    check_digest(record)
    require(record["canonical_write_allowed"] is False, "replay_canonical_authority")
    ledger = record["ledger"]
    if ledger.get("contract_version") == "1.2.0":
        check_history(bundle)
        return
    require("history" not in ledger, "legacy_history_forbidden")
    scoped = ledger.get("contract_version") == "1.1.0"
    require(scoped or ledger.get("contract_version") == "1.0.0", "task_ledger_version")
    if scoped:
        require(isinstance(ledger.get("execution_scope"), str) and re.fullmatch(r"sha256:[a-f0-9]{64}", ledger["execution_scope"]), "execution_scope_invalid")
    else:
        require("execution_scope" not in ledger, "legacy_execution_scope_forbidden")
    plan = ledger["plan"]
    check_digest(plan)
    check_digest(bundle["catalog"])
    require(plan["catalog_digest"] == bundle["catalog"]["digest"], "catalog_binding")
    require(plan["canonical_write_allowed"] is False, "plan_canonical_authority")
    require(plan["graph_digest"] == ledger["graph_digest"] == graph["digest"], "graph_binding")
    require(plan["policy_digest"] == ledger["policy_digest"] == policy["digest"], "policy_binding")
    receivers = {r["id"]: r for r in bundle["receivers"]}
    require(len(receivers) == len(bundle["receivers"]), "duplicate_receiver")
    require(digest_value(sorted(receivers.values(), key=lambda r: r["id"])) == ledger["receiver_catalog_digest"], "receiver_binding")
    require(0 <= ledger["reserved_model_calls"] <= policy["max_model_calls"], "model_budget")
    require(0 < len(plan["requests"]) <= policy["max_tasks"], "task_budget")
    requests = {r["id"]: r for r in plan["requests"]}
    require(len(requests) == len(plan["requests"]) and set(requests) == set(ledger["tasks"]), "task_inventory")
    participants = {p["id"]: p for p in policy["participants"]}
    visiting, visited = set(), set()

    def visit(task_id):
        require(task_id not in visiting, "dependency_cycle")
        if task_id in visited:
            return
        visiting.add(task_id)
        for dep in requests[task_id]["dependencies"]:
            require(dep["task_id"] in requests, "dependency_missing")
            visit(dep["task_id"])
        visiting.remove(task_id)
        visited.add(task_id)

    views = {}
    for task_id, request in requests.items():
        visit(task_id)
        task = ledger["tasks"][task_id]
        require(task["request"] == request and task["request_digest"] == digest_value(request), "request_binding")
        key = {"plan": plan["digest"], "task": task_id, "request": digest_value(request)}
        if scoped:
            key["execution_scope"] = ledger["execution_scope"]
        require(task["idempotency_key"] == digest_value(key), "idempotency_binding")
        receiver = receivers[request["receiver_id"]]
        require(receiver["digest"] == request["receiver_digest"], "receiver_digest")
        require(value_matches_type(request["input"], receiver["input_type"]), "input_type")
        chain = [participants[request["receiver_id"]]]
        current, seen = request, {task_id}
        while current["parent_id"]:
            parent = requests[current["parent_id"]]
            require(parent["id"] not in seen and len(seen) <= policy["max_depth"], "parent_depth_or_cycle")
            seen.add(parent["id"])
            parent_scope = participants[parent["receiver_id"]]
            require(current["receiver_id"] in parent_scope["delegate_to"] and set(current["object_ids"]) <= set(parent["object_ids"]), "parent_attenuation")
            require(timestamp(current["deadline"]) <= timestamp(parent["deadline"]), "parent_deadline")
            chain.append(parent_scope)
            current = parent
        owner = participants[policy["owner"]]
        require(current["receiver_id"] in owner["delegate_to"], "owner_delegation")
        chain.append(owner)
        allowed = set.intersection(*(set(p["object_ids"]) for p in chain))
        require(set(request["object_ids"]) <= allowed, "object_scope")
        sources = set.intersection(*(set(p["source_ids"]) for p in chain))
        authorized = subset_graph(graph, {obj["id"] for obj in graph["objects"] if obj["id"] in allowed and set(obj["source_refs"]) <= sources}, sources)
        require(set(request["object_ids"]) <= {obj["id"] for obj in authorized["objects"]}, "source_scope")
        view = sealed({"contract_version": "1.0.0", "base_digest": authorized["digest"], "object_ids": sorted(request["object_ids"]),
                       "graph": subset_graph(authorized, set(request["object_ids"])), "canonical_write_allowed": False})
        require(task["input_snapshot_digest"] == view["digest"], "context_snapshot_binding")
        views[task_id] = view["graph"]
        require(task["state"] in {"submitted", "running", "blocked", "completed", "failed", "cancelled"}, "task_state")
        require(task["receipt_state"] in {"prepared", "executed", "verified", "failed", "uncertain"}, "receipt_state")
        require(task["acceptance"] in {"pending", "accepted", "rejected"}, "acceptance_state")
        if task["state"] == "completed":
            require(task["receipt_state"] == "verified" and "result" in task, "false_completion")
        if "result" in task:
            result = task["result"]
            require(task["result_digest"] == digest_value(result), "result_digest")
            require(value_matches_type(result["output"], receiver["output_type"]), "output_type")
            require(set(request["required_evidence"]) <= {e["id"] for e in result["evidence"]}, "missing_evidence")
            for dep in request["dependencies"]:
                previous = ledger["tasks"][dep["task_id"]]
                require(previous["state"] == "completed" and previous["receipt_state"] == "verified", "dependency_unverified")
                require(dep["requires"] != "accepted" or previous["acceptance"] == "accepted", "dependency_unaccepted")
        if task["acceptance"] != "pending":
            require(task["state"] == "completed" and task["receipt_state"] == "verified", "acceptance_without_completion")
            receipt = task["acceptance_receipt"]
            require(receipt["reviewer"] in policy["reviewers"] and receipt["reviewer"] != request["receiver_id"], "self_acceptance")
            require(receipt["result_digest"] == task["result_digest"], "acceptance_result_binding")
            require(receipt["decision_digest"] == digest_value({"reviewer": receipt["reviewer"], "task_id": task_id, "result_digest": task["result_digest"], "verdict": task["acceptance"], "plan_digest": plan["digest"]}), "acceptance_decision_binding")
    require(sum(t["state"] == "running" for t in ledger["tasks"].values()) <= policy["max_parallel"], "parallel_budget")
    for task_id, request in requests.items():
        for dep in request["dependencies"]:
            previous = requests[dep["task_id"]]
            require(set(previous["object_ids"]) <= set(request["object_ids"]), "dependency_object_leak")
            require(all(source in views[task_id]["sources"] for source in views[previous["id"]]["sources"]), "dependency_source_leak")
            require(all(edge in views[task_id]["relations"] for edge in views[previous["id"]]["relations"]), "dependency_relation_leak")


def check_history(bundle):
    """Replay deltas independently; hashes never substitute for transition rules."""
    ledger = bundle["record"]["ledger"]
    history = ledger.get("history")
    require(isinstance(history, list) and len(history) <= bundle["policy"]["max_tasks"] * 6 + 2, "history_budget")
    target = copy.deepcopy(ledger)
    target.pop("history")
    target["contract_version"] = "1.1.0" if "execution_scope" in target else "1.0.0"
    state = copy.deepcopy(target)
    state["cancelled"] = False
    state["reserved_model_calls"] = 0
    static = {"request", "request_digest", "input_snapshot_digest", "idempotency_key"}
    state["tasks"] = {key: {**{k: v for k, v in task.items() if k in static},
        "state": "submitted", "receipt_state": "prepared", "acceptance": "pending"} for key, task in state["tasks"].items()}
    kinds = {"reserve": {"state"}, "deadline": {"state", "blocker"},
             "output": {"result", "result_digest", "receipt_state"},
             "verify": {"state", "receipt_state"}, "reconcile": {"state", "receipt_state"},
             "uncertain": {"state", "receipt_state", "blocker"}, "accept": {"acceptance", "acceptance_receipt"},
             "cancel": {"state", "receipt_state"}}
    receivers = {r["id"]: r for r in bundle["receivers"]}
    previous = digest_value(state)

    def validate(current):
        check_tasks({**bundle, "record": sealed({"contract_version": "1.0.0", "ledger": current, "canonical_write_allowed": False})})

    validate(state)
    for index, event in enumerate(history, start=1):
        require(set(event) == {"sequence", "kind", "previous_digest", "before_digest", "after_digest", "changes", "cancelled", "reserved_model_calls", "digest"}, "history_shape")
        check_digest(event)
        require(event["sequence"] == index and event["previous_digest"] == previous and event["before_digest"] == digest_value(state), "history_chain")
        kind, changes = event["kind"], event["changes"]
        require(kind in kinds and isinstance(changes, dict) and (kind == "cancel" or len(changes) == 1), "history_operation")
        require((not state["cancelled"] and event["cancelled"] is True) if kind == "cancel" else state["cancelled"] == event["cancelled"], "history_cancel")
        after = copy.deepcopy(state)
        reservation = 0
        for task_id, delta in changes.items():
            require(task_id in state["tasks"] and isinstance(delta, dict) and set(delta) <= kinds[kind], "history_fields")
            old = state["tasks"][task_id]
            new = {**old, **delta}
            before_pair = old["state"], old["receipt_state"]
            after_pair = new["state"], new["receipt_state"]
            if kind == "reserve":
                require(not state["cancelled"] and before_pair == ("submitted", "prepared") and after_pair == ("running", "prepared"), "history_reserve")
                reservation += receivers[old["request"]["receiver_id"]]["kind"] == "ai"
                for dep in old["request"]["dependencies"]:
                    prior = state["tasks"][dep["task_id"]]
                    require(prior["state"] == "completed" and prior["receipt_state"] == "verified" and (dep["requires"] != "accepted" or prior["acceptance"] == "accepted"), "history_dependency")
            elif kind == "deadline":
                require(not state["cancelled"] and before_pair == ("submitted", "prepared") and after_pair == ("blocked", "prepared") and new.get("blocker") == "task_deadline_expired", "history_deadline")
            elif kind == "output":
                require(not state["cancelled"] and before_pair == ("running", "prepared") and after_pair == ("running", "executed"), "history_output")
            elif kind in {"verify", "reconcile"}:
                require(not state["cancelled"] and before_pair == ("running", "executed") and after_pair == ("completed", "verified"), "history_verify")
            elif kind == "accept":
                require(not state["cancelled"] and before_pair == ("completed", "verified") and old["acceptance"] == "pending" and new["acceptance"] in {"accepted", "rejected"}, "history_accept")
            elif kind == "uncertain":
                require((old["state"] == "running" or (state["cancelled"] and old["state"] == "cancelled")) and after_pair == ("cancelled" if state["cancelled"] else "blocked", "uncertain"), "history_uncertain")
            else:
                require((before_pair == ("submitted", "prepared") and after_pair == ("cancelled", "prepared")) or (old["state"] == "running" and after_pair == ("cancelled", "uncertain")), "history_cancel_transition")
            after["tasks"][task_id] = new
        after["cancelled"] = event["cancelled"]
        after["reserved_model_calls"] = event["reserved_model_calls"]
        require(after["reserved_model_calls"] == state["reserved_model_calls"] + reservation, "history_reservation")
        if kind == "cancel":
            require(all(t["state"] not in {"submitted", "running"} for t in after["tasks"].values()), "history_cancel_incomplete")
        validate(after)
        require(event["after_digest"] == digest_value(after), "history_state_digest")
        previous, state = event["digest"], after
    require(state == target, "history_final_state")


def check_bundle(bundle, schema_root):
    schemas = {name: json.loads((schema_root / (name + ".schema.json")).read_text()) for name in ("graph-operation-snapshot", "cluster-proposal")}
    check_cluster(bundle["graph"], bundle["clusters"], schemas)
    check_cluster(bundle["public_graph"], bundle["public_clusters"], schemas)
    check_tasks(bundle)
    return {"valid": True, "implementation": "independent_python", "scope": "rule_neighborhood_recorded_provider_clusters_task_context_and_history",
            "authority_verified": False, "provider_calls": 0,
            "limitations": ["Recorded provider groups are checked for consistency, not inference quality or output authenticity.",
                            "Does not prove external evidence truth, approval authenticity or full Runtime conformance."]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--schemas", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(args.bundle.stat().st_size <= 8 * 1024 * 1024, "input_budget")
        result = check_bundle(json.loads(args.bundle.read_text()), args.schemas)
    except Exception as error:
        result = {"valid": False, "error": type(error).__name__ + ":" + str(error)[:200]}
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
