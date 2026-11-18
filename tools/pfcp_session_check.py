# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# *
# * Offline consistency checker for PFCP Session Modification rule groups
# * (PDR / FAR / URR / QER / BAR / Traffic Endpoint), built on top of the
# * pycrate TS 29.244 decoder. No UPF is driven: the checker only decodes one
# * PFCP Session Modification Request against one already-installed session,
# * validates the cross-IE forwarding policy and computes the resulting state
# * transactionally.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *--------------------------------------------------------
#*/

"""Offline PFCP session-modification rule-group consistency checker.

Scope (intentionally limited):
  * one already-installed PFCP session, modelled by :class:`PFCPSessionState`;
  * one PFCP Session Modification Request (TS 29.244 section 7.5.4), carrying
    create / update / remove operations on PDR, FAR, URR, QER, BAR and Traffic
    Endpoint rules;
  * per-session rule-ID spaces (TS 29.244 rule IDs are scoped to a session).

Per-IE decode success is not enough: a message whose every IE decodes can still
install an incoherent forwarding policy. The checker therefore validates:
  1. duplicate rule IDs, inside the message and against the installed session;
  2. update / remove operations targeting rules that do not exist;
  3. references (PDR -> FAR/URR/QER, nested PDI -> Traffic Endpoint,
     FAR -> BAR / Traffic Endpoint, URR -> linked URR / FAR), including
     references to objects created inside the same message;
  4. removal of rules still referenced by surviving rules;
  5. session scope (SEID) and message-type scope.

The check is transactional. :func:`check_modification` never mutates the
installed session: it builds a candidate state on the side. Both the raw
declared rule inventory and the derived, reference-resolved effective view are
returned for the state *before* and *after* the operation. The candidate is
installed only through :meth:`ModificationResult.commit`, which refuses to
commit a rejected transaction, so a failed check can never leave half of the
new rule set installed.

MAR / SRR steering rules and the Aggregated-URR ID namespace are outside this
checker's scope and silently ignored (documented limitation).
"""

import copy

from pycrate_mobile.TS29244_PFCP import (
    PFCPIEType,
    PFCPMsgType,
    parse_PFCP,
    ERR_PFCP_BUF_TOO_SHORT,
    ERR_PFCP_BUF_INVALID,
    ERR_PFCP_TYPE_NONEXIST,
    ERR_PFCP_MAND_IE_MISS,
    )


#------------------------------------------------------------------------------#
# Check codes and findings
#------------------------------------------------------------------------------#

class CheckCode(object):
    DECODE_ERROR            = 'DECODE_ERROR'
    SCOPE_MISMATCH          = 'SCOPE_MISMATCH'
    MALFORMED_RULE          = 'MALFORMED_RULE'
    DUP_RULE_ID             = 'DUP_RULE_ID'
    UPDATE_TARGET_MISSING   = 'UPDATE_TARGET_MISSING'
    REMOVE_TARGET_MISSING   = 'REMOVE_TARGET_MISSING'
    DANGLING_REFERENCE      = 'DANGLING_REFERENCE'
    DELETE_IN_USE           = 'DELETE_IN_USE'


_PFCP_PARSE_ERR = {
    ERR_PFCP_BUF_TOO_SHORT: 'buffer too short',
    ERR_PFCP_BUF_INVALID:   'invalid PFCP encoding',
    ERR_PFCP_TYPE_NONEXIST: 'unknown PFCP message type',
    ERR_PFCP_MAND_IE_MISS:  'decoded with missing mandatory IE(s)',
    }


class Finding(object):
    """One consistency failure, with an exact IE path and impacted rules."""

    def __init__(self, code, path, message, affected=()):
        self.code = code
        # path is a tuple of IE-type names / positional indexes, e.g.
        # ('PFCPSessionModificationReq', 'IEs[2]', 'CreatePDR#1', 'FARID')
        self.path = tuple(path)
        self.message = message
        # affected is a tuple of human-readable rule references,
        # e.g. 'PDR id=20 at .../CreatePDR#0'
        self.affected = tuple(affected)

    def path_str(self):
        return '.'.join(self.path)

    def __repr__(self):
        return 'Finding(%s, %s, %r, affected=%r)' % (
            self.code, self.path_str(), self.message, list(self.affected))

    def __eq__(self, other):
        return isinstance(other, Finding) and \
            (self.code, self.path, self.message, self.affected) == \
            (other.code, other.path, other.message, other.affected)

    def __hash__(self):
        return hash((self.code, self.path, self.message, self.affected))


#------------------------------------------------------------------------------#
# Rule family metadata
#------------------------------------------------------------------------------#

# family -> (rule-ID IE type, create IE type, update IE type, remove IE type)
FAMILY_META = {
    'PDR': (PFCPIEType.PDRID.value,
            PFCPIEType.CreatePDR.value,
            PFCPIEType.UpdatePDR.value,
            PFCPIEType.RemovePDR.value),
    'FAR': (PFCPIEType.FARID.value,
            PFCPIEType.CreateFAR.value,
            PFCPIEType.UpdateFAR.value,
            PFCPIEType.RemoveFAR.value),
    'URR': (PFCPIEType.URRID.value,
            PFCPIEType.CreateURR.value,
            PFCPIEType.UpdateURR.value,
            PFCPIEType.RemoveURR.value),
    'QER': (PFCPIEType.QERID.value,
            PFCPIEType.CreateQER.value,
            PFCPIEType.UpdateQER.value,
            PFCPIEType.RemoveQER.value),
    'BAR': (PFCPIEType.BARID.value,
            PFCPIEType.CreateBAR.value,
            PFCPIEType.UpdateBARSessionModReq.value,
            PFCPIEType.RemoveBAR.value),
    'TE':  (PFCPIEType.TrafficEndpointID.value,
            PFCPIEType.CreateTrafficEndpoint.value,
            PFCPIEType.UpdateTrafficEndpoint.value,
            PFCPIEType.RemoveTrafficEndpoint.value),
    }

# IE type -> (family, operation) for every top-level rule container
OP_BY_IE_TYPE = {}
for _fam, (_idt, _ct, _ut, _rt) in FAMILY_META.items():
    OP_BY_IE_TYPE[_ct] = (_fam, 'create')
    OP_BY_IE_TYPE[_ut] = (_fam, 'update')
    OP_BY_IE_TYPE[_rt] = (_fam, 'remove')

# reference IE type -> family holding the referenced object.
# A rule's own identifier IE is excluded before this map is applied.
REF_IE_TYPE = {
    PFCPIEType.FARID.value:             'FAR',
    PFCPIEType.URRID.value:             'URR',
    PFCPIEType.QERID.value:             'QER',
    PFCPIEType.BARID.value:             'BAR',
    PFCPIEType.TrafficEndpointID.value: 'TE',
    PFCPIEType.LinkedURRID.value:       'URR',
    }

_CREATE_RULE_IE = {fam: meta[1] for fam, meta in FAMILY_META.items()}


def _ie_name(ie_type):
    try:
        return PFCPIEType(ie_type).name
    except ValueError:
        return 'IE_%u' % ie_type


def _rule_ref(family, rule_id, path):
    return '%s id=%u at %s' % (family, rule_id, '.'.join(path))


def _is_grouped(obj):
    # pycrate grouped IEs (PFCPIEs) carry the MAND/OPT class attributes
    return hasattr(obj, 'MAND') and hasattr(obj, 'OPT')


#------------------------------------------------------------------------------#
# Installed session state
#------------------------------------------------------------------------------#

class PFCPSessionState(object):
    """Declared rule inventory of one installed PFCP session.

    For every rule family it keeps a dict keyed by rule ID. Each record stores
    the plain pycrate value tree (`tree`), the references extracted from it
    (`refs`: target family -> list of (target id, IE path)) and the origin path
    of the declaration (`origin`).
    """

    def __init__(self, seid):
        self.seid = seid
        self.rules = dict((fam, {}) for fam in FAMILY_META)

    # -- inventory ----------------------------------------------------------#

    def ids(self, family):
        return set(self.rules[family].keys())

    def get(self, family, rule_id):
        return self.rules[family].get(rule_id)

    def install_rule(self, family, rule_id, tree, refs, origin):
        self.rules[family][rule_id] = {
            'tree':   tree,
            'refs':   refs,
            'origin': tuple(origin),
            }

    def remove_rule(self, family, rule_id):
        self.rules[family].pop(rule_id, None)

    def clone(self):
        cloned = PFCPSessionState(self.seid)
        cloned.rules = copy.deepcopy(self.rules)
        return cloned

    # -- seeding ------------------------------------------------------------#

    def seed_from_establishment(self, msg):
        """Seed the session from a decoded PFCP Session Establishment Request."""
        msg = _coerce_message(msg)
        if isinstance(msg, Finding):
            raise ValueError('cannot seed session: %s' % msg.message)
        if msg[0]['Type'].get_val() != PFCPMsgType.PFCPSessionEstablishmentReq.value:
            raise ValueError('seed_from_establishment expects a '
                             'PFCPSessionEstablishmentReq')
        for idx, top in enumerate(msg[1]):
            ie_type = top[0].get_val()
            if ie_type not in _CREATE_RULE_IE.values():
                continue
            family = _family_of_create_type(ie_type)
            inner = top[3]
            rule_id = _extract_rule_id(inner, FAMILY_META[family][0])
            if rule_id is None:
                continue
            base = (_msg_name(msg), 'IEs[%u]' % idx, _ie_name(ie_type))
            refs = _extract_refs(family, inner, base)
            self.install_rule(family, rule_id,
                              copy.deepcopy(inner.get_val()), refs, base)
        return self

    # -- views --------------------------------------------------------------#

    def declared_view(self):
        """Raw declared inventory: family -> {rule id: origin path}."""
        view = {}
        for family in FAMILY_META:
            view[family] = dict((rid, list(rec['origin']))
                                for rid, rec in self.rules[family].items())
        return view

    def effective_view(self):
        """Derived view with reference resolution against this inventory."""
        view = {}
        for family, records in self.rules.items():
            view[family] = {}
            for rule_id, rec in records.items():
                refs = {}
                for target_family, entries in rec['refs'].items():
                    known = self.ids(target_family)
                    refs[target_family] = [
                        {'id': target_id,
                         'path': list(path),
                         'resolves': target_id in known}
                        for target_id, path in entries]
                view[family][rule_id] = {
                    'origin': list(rec['origin']),
                    'refs': refs,
                    }
        return view


def _family_of_create_type(ie_type):
    for family, meta in FAMILY_META.items():
        if meta[1] == ie_type:
            return family
    return None


#------------------------------------------------------------------------------#
# Message / IE helpers
#------------------------------------------------------------------------------#

def _coerce_message(msg):
    """Normalize bytes / pycrate message input into a decoded PFCP message.

    Returns either the decoded message object or a Finding(DECODE_ERROR).
    """
    if isinstance(msg, (bytes, bytearray)):
        decoded, err = parse_PFCP(bytes(msg))
        if decoded is None:
            return Finding(CheckCode.DECODE_ERROR,
                           ('PFCP input',),
                           'PFCP decode failed: %s' % _PFCP_PARSE_ERR.get(
                               err, 'error %u' % err))
        if err:
            return Finding(CheckCode.DECODE_ERROR,
                           ('PFCP input',),
                           'PFCP decoded with parser warning: %s'
                           % _PFCP_PARSE_ERR.get(err, 'error %u' % err))
        return decoded
    return msg


def _msg_name(msg):
    return type(msg).__name__


def _extract_rule_id(inner, id_ie_type):
    """Return the rule ID value from a grouped rule IE, or None."""
    for sub in inner:
        if sub[0].get_val() == id_ie_type:
            data = sub[3]
            try:
                return data['Val'].get_val()
            except Exception:
                return None
    return None


def _tree_ie_type(node):
    """IE type of a plain pycrate value-tree node ([Type, Len, EID, Data])."""
    return node[0]


def _tree_is_ie(node):
    """True for a value-tree IE node (4-element list starting with an int)."""
    return isinstance(node, list) and len(node) == 4 and \
        isinstance(node[0], int)


def _tree_is_grouped(node):
    """True when a value-tree node's Data is itself a list of IE nodes."""
    data = node[3]
    if not isinstance(data, list) or not data:
        return False
    first = data[0]
    return _tree_is_ie(first)


def _extract_refs_from_tree(family, tree, base_path):
    """Reference extraction on plain pycrate value trees (see _extract_refs)."""
    own_id_type = FAMILY_META[family][0]
    refs = {}

    def walk(nodes, path):
        for node in nodes:
            if not _tree_is_ie(node):
                continue
            ie_type = _tree_ie_type(node)
            sub_path = path + (_ie_name(ie_type),)
            if ie_type == own_id_type:
                continue
            if ie_type in REF_IE_TYPE:
                data = node[3]
                target_id = data[0] if isinstance(data, (list, tuple)) else data
                refs.setdefault(REF_IE_TYPE[ie_type], []).append(
                    (target_id, sub_path))
            if _tree_is_grouped(node):
                walk(node[3], sub_path)

    walk(tree, base_path)
    return refs


def _merge_rule_tree(family, base_tree, update_tree):
    """Field-level merge of an Update* IE value tree onto an installed tree.

    Scalar sub-IEs present in the update override same-typed installed sub-IEs;
    grouped sub-IEs (e.g. PDI, Update Forwarding Parameters) replace the
    installed grouped IE of the same type. Unchanged sub-IEs are retained.
    """
    update_by_type = {}
    for node in update_tree:
        if not _tree_is_ie(node):
            continue
        # keep the first occurrence of each type, mirroring create handling
        update_by_type.setdefault(_tree_ie_type(node), node)
    overridden = set(update_by_type)
    merged = [copy.deepcopy(node) for node in base_tree
              if _tree_is_ie(node) and _tree_ie_type(node) not in overridden]
    # install updates in the order in which they appear on the wire
    for node in update_tree:
        if not _tree_is_ie(node):
            continue
        ie_type = _tree_ie_type(node)
        if update_by_type.get(ie_type) is node:
            merged.append(copy.deepcopy(node))
    return merged


def _extract_refs(family, inner, base_path):
    """Walk a live rule grouped IE and collect cross-rule references.

    Returns {target family: [(target id, full IE path), ...]}. The rule's own
    identifier IE is skipped so a CreateURR's URRID is not seen as a self-ref.
    Grouped child IEs (PDI, ForwardingParameters, ...) are recursed into.
    """
    own_id_type = FAMILY_META[family][0]
    refs = {}

    def walk(container, path):
        for sub in container:
            ie_type = sub[0].get_val()
            sub_path = path + (_ie_name(ie_type),)
            if ie_type == own_id_type:
                continue
            if ie_type in REF_IE_TYPE:
                target_family = REF_IE_TYPE[ie_type]
                try:
                    target_id = sub[3]['Val'].get_val()
                except Exception:
                    pass
                else:
                    refs.setdefault(target_family, []).append(
                        (target_id, sub_path))
            if _is_grouped(sub[3]):
                walk(sub[3], sub_path)

    walk(inner, base_path)
    return refs


#------------------------------------------------------------------------------#
# Transaction
#------------------------------------------------------------------------------#

class ModificationResult(object):
    """Outcome of checking one Session Modification Request.

    The installed session is never modified by the check. `accepted` tells
    whether the transaction is coherent; `declared_before/after` hold the raw
    rule inventories and `effective_before/after` the derived reference-resolved
    views. Call :meth:`commit` to atomically install an accepted transaction.
    """

    def __init__(self, msg_name, seid, findings, state_before, candidate):
        self.msg_name = msg_name
        self.seid = seid
        self.findings = findings
        self.accepted = not findings
        self.declared_before = state_before.declared_view()
        self.effective_before = state_before.effective_view()
        self.declared_after = candidate.declared_view()
        self.effective_after = candidate.effective_view()
        self._state_before = state_before
        self._candidate = candidate

    def commit(self):
        """Atomically install the candidate into the original session.

        Raises if the transaction was rejected: a failed check can never end up
        half-installed. Returns the resulting :class:`PFCPSessionState`.
        """
        if not self.accepted:
            raise RuntimeError(
                'rejected PFCP modification cannot be committed: %u finding(s)'
                % len(self.findings))
        self._state_before.rules = self._candidate.rules
        return self._state_before

    def summary(self):
        lines = ['%s on SEID 0x%x: %s (%u finding(s))' % (
            self.msg_name, self.seid,
            'ACCEPTED' if self.accepted else 'REJECTED',
            len(self.findings))]
        for finding in self.findings:
            lines.append('  - %s @ %s' % (finding.code, finding.path_str()))
            lines.append('      %s' % finding.message)
            for ref in finding.affected:
                lines.append('      affected: %s' % ref)
        return '\n'.join(lines)


def check_modification(state, msg):
    """Check one PFCP Session Modification Request against an installed session.

    `state` is a :class:`PFCPSessionState`; `msg` is either a decoded
    PFCPSessionModificationReq or its encoded bytes. The installed state is
    never mutated. Returns a :class:`ModificationResult`.
    """
    findings = []
    decoded = _coerce_message(msg)
    if isinstance(decoded, Finding):
        findings.append(decoded)
        return ModificationResult('undecodable PFCP', state.seid, findings,
                                  state, state.clone())

    name = _msg_name(decoded)
    base = (name,)

    # -- message-type scope -------------------------------------------------#
    if decoded[0]['Type'].get_val() != PFCPMsgType.PFCPSessionModificationReq.value:
        findings.append(Finding(
            CheckCode.SCOPE_MISMATCH, base,
            'expected PFCPSessionModificationReq (type %u), got %s (type %u)'
            % (PFCPMsgType.PFCPSessionModificationReq.value, name,
               decoded[0]['Type'].get_val())))
        return ModificationResult(name, state.seid, findings,
                                  state, state.clone())

    # -- session scope (SEID) -----------------------------------------------#
    msg_seid = decoded[0]['SEID'].get_val()
    if msg_seid != state.seid:
        findings.append(Finding(
            CheckCode.SCOPE_MISMATCH,
            base + ('Hdr', 'SEID'),
            'message SEID 0x%x does not match installed session 0x%x'
            % (msg_seid, state.seid)))
        return ModificationResult(name, state.seid, findings,
                                  state, state.clone())

    # -- 1. parse all rule containers in wire order -------------------------#
    # ops[family][op] -> list of (rule_id|None, path, inner grouped IE)
    ops = dict((fam, {'create': [], 'update': [], 'remove': []})
               for fam in FAMILY_META)
    type_counters = {}

    for idx, top in enumerate(decoded[1]):
        ie_type = top[0].get_val()
        if ie_type not in OP_BY_IE_TYPE:
            continue
        family, operation = OP_BY_IE_TYPE[ie_type]
        occ = type_counters.get(ie_type, 0)
        type_counters[ie_type] = occ + 1
        path = base + ('IEs[%u]' % idx, '%s#%u' % (_ie_name(ie_type), occ))
        inner = top[3]
        rule_id = _extract_rule_id(inner, FAMILY_META[family][0])
        if rule_id is None:
            findings.append(Finding(
                CheckCode.MALFORMED_RULE, path,
                '%s %s carries no %s rule-ID IE'
                % (operation, family,
                   _ie_name(FAMILY_META[family][0]))))
            continue
        ops[family][operation].append((rule_id, path, inner))

    # -- 2. duplicate IDs (inside the message and against installed state) --#
    for family, per_op in ops.items():
        seen = {}
        for operation in ('create', 'update', 'remove'):
            for rule_id, path, _inner in per_op[operation]:
                key = (operation, rule_id)
                if key in seen:
                    findings.append(Finding(
                        CheckCode.DUP_RULE_ID, path,
                        '%s %s id=%u is declared twice in the same message'
                        % (operation, family, rule_id),
                        [_rule_ref(family, rule_id, seen[key])]))
                else:
                    seen[key] = path
        # same ID manipulated by two different operations in one message
        id_ops = {}
        for operation in ('create', 'update', 'remove'):
            for rule_id, path, _inner in per_op[operation]:
                id_ops.setdefault(rule_id, []).append((operation, path))
        for rule_id, entries in id_ops.items():
            if len({op for op, _p in entries}) > 1:
                for operation, path in entries:
                    findings.append(Finding(
                        CheckCode.DUP_RULE_ID, path,
                        '%s id=%u is targeted by conflicting operations: %s'
                        % (family, rule_id,
                           ', '.join(sorted({op for op, _p in entries})))))
        # create on an ID already installed in the session
        installed = state.ids(family)
        for rule_id, path, _inner in per_op['create']:
            if rule_id in installed:
                findings.append(Finding(
                    CheckCode.DUP_RULE_ID, path,
                    'cannot create %s id=%u: rule ID already installed '
                    'in the session' % (family, rule_id),
                    [_rule_ref(family, rule_id,
                               state.get(family, rule_id)['origin'])]))

    # -- 3. update / remove target existence --------------------------------#
    for family, per_op in ops.items():
        created_here = {rid for rid, _p, _i in per_op['create']}
        for rule_id, path, _inner in per_op['update']:
            if rule_id not in state.ids(family) and rule_id not in created_here:
                findings.append(Finding(
                    CheckCode.UPDATE_TARGET_MISSING, path,
                    'update targets %s id=%u which is neither installed nor '
                    'created in this message' % (family, rule_id)))
        for rule_id, path, _inner in per_op['remove']:
            if rule_id not in state.ids(family) and rule_id not in created_here:
                findings.append(Finding(
                    CheckCode.REMOVE_TARGET_MISSING, path,
                    'remove targets %s id=%u which is not installed in the '
                    'session' % (family, rule_id)))

    # -- 4. build the candidate declared state (no mutation of `state`) -----#
    candidate = state.clone()
    for family, per_op in ops.items():
        for rule_id, path, inner in per_op['remove']:
            candidate.remove_rule(family, rule_id)
        # first well-formed declaration wins on duplicate creates
        created = set()
        for rule_id, path, inner in per_op['create']:
            if rule_id in created:
                continue
            created.add(rule_id)
            refs = _extract_refs(family, inner, path)
            candidate.install_rule(family, rule_id,
                                   copy.deepcopy(inner.get_val()), refs, path)
        for rule_id, path, inner in per_op['update']:
            if rule_id not in candidate.rules[family]:
                # update of a missing target: nothing to install
                continue
            # TS 29.244: an Update* IE only carries modified fields, so it is
            # merged onto the installed rule instead of replacing it. Sub-IEs
            # present in the update override same-typed installed sub-IEs; every
            # untouched field (and its references) is retained.
            merged_tree = _merge_rule_tree(family,
                                           candidate.rules[family][rule_id]['tree'],
                                           inner.get_val())
            refs = _extract_refs_from_tree(family, merged_tree, path)
            candidate.install_rule(family, rule_id, merged_tree, refs, path)

    # -- 5. removal of rules still in use (computed before dangling scan) ---#
    # removed-but-still-referenced IDs per family: the DELETE_IN_USE finding is
    # the complete diagnosis for these, so the dangling scan skips them to
    # avoid reporting the same broken link twice from two viewpoints.
    removed_in_use = dict((fam, set()) for fam in FAMILY_META)
    for family, per_op in ops.items():
        removed = [(rid, path) for rid, path, _i in per_op['remove']
                   if rid in state.ids(family)]
        for removed_id, remove_path in removed:
            users = []
            for ref_family, records in candidate.rules.items():
                for rule_id, rec in records.items():
                    for target_id, ref_path in rec['refs'].get(family, []):
                        if target_id == removed_id:
                            users.append(_rule_ref(ref_family, rule_id,
                                                   rec['origin']))
            if users:
                removed_in_use[family].add(removed_id)
                findings.append(Finding(
                    CheckCode.DELETE_IN_USE, remove_path,
                    'cannot remove %s id=%u: still referenced by %u surviving '
                    'rule(s)' % (family, removed_id, len(users)),
                    users))

    # -- 6. dangling references on the candidate effective state ------------#
    for family, records in candidate.rules.items():
        for rule_id, rec in records.items():
            for target_family, entries in rec['refs'].items():
                known = candidate.ids(target_family)
                for target_id, ref_path in entries:
                    if target_id in removed_in_use.get(target_family, set()):
                        continue
                    if target_id not in known:
                        findings.append(Finding(
                            CheckCode.DANGLING_REFERENCE, ref_path,
                            '%s id=%u references %s id=%u which does not '
                            'exist after the modification'
                            % (family, rule_id, target_family, target_id),
                            [_rule_ref(family, rule_id, rec['origin'])]))

    return ModificationResult(name, state.seid, findings, state, candidate)


#------------------------------------------------------------------------------#
# Minimal demo (self-contained, no external packet capture required)
#------------------------------------------------------------------------------#

def _demo():
    """Build one coherent and one dangling-reference modification and check both."""
    from pycrate_mobile.TS29244_PFCP import PFCPSessionModificationReq

    seid = 0x1122334455667788

    def ie(ie_type, data=None):
        value = {'Type': ie_type}
        if data is not None:
            value['Data'] = data
        return value

    def msg(containers):
        m = PFCPSessionModificationReq()
        m[0]['SEID'].set_val(seid)
        m[1].clear()
        for container in containers:
            m[1].add_ie(container['Type'], container.get('Data'))
        return m.to_bytes()

    # baseline session: PDR 10 -> FAR 10 -> BAR 10
    state = PFCPSessionState(seid)
    state.install_rule(
        'BAR', 10, None,
        {}, ('baseline', 'CreateBAR'))
    state.install_rule(
        'FAR', 10, None,
        {'BAR': [(10, ('baseline', 'CreateFAR', 'BARID'))]},
        ('baseline', 'CreateFAR'))
    state.install_rule(
        'PDR', 10, None,
        {'FAR': [(10, ('baseline', 'CreatePDR', 'FARID'))]},
        ('baseline', 'CreatePDR'))

    good = msg([
        ie(PFCPIEType.CreateFAR.value, [
            ie(PFCPIEType.FARID.value, {'Val': 20}),
            ie(PFCPIEType.ApplyAction.value, {'Octet1': {'FORW': 1}}),
            ie(PFCPIEType.BARID.value, {'Val': 10}),
            ]),
        ie(PFCPIEType.CreatePDR.value, [
            ie(PFCPIEType.PDRID.value, {'Val': 20}),
            ie(PFCPIEType.Precedence.value, {'Val': 100}),
            ie(PFCPIEType.PDI.value, [
                ie(PFCPIEType.SourceInterface.value, {'If': 0})]),
            ie(PFCPIEType.FARID.value, {'Val': 20}),
            ]),
        ])

    bad = msg([
        ie(PFCPIEType.CreatePDR.value, [
            ie(PFCPIEType.PDRID.value, {'Val': 30}),
            ie(PFCPIEType.Precedence.value, {'Val': 100}),
            ie(PFCPIEType.PDI.value, [
                ie(PFCPIEType.SourceInterface.value, {'If': 0})]),
            ie(PFCPIEType.FARID.value, {'Val': 99}),
            ]),
        ie(PFCPIEType.RemoveFAR.value, [
            ie(PFCPIEType.FARID.value, {'Val': 10})]),
        ])

    for label, packet in (('coherent modification', good),
                          ('dangling modification', bad)):
        print('--- %s ---' % label)
        result = check_modification(state, packet)
        print(result.summary())
        print()


if __name__ == '__main__':
    _demo()
