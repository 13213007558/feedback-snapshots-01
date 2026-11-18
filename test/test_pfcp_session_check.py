# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# *
# * Offline consistency tests for tools/pfcp_session_check.py. Every test case
# * carries a manual annotation describing the intended rule-group semantics and
# * the exact checker verdict expected from it. Messages are built with pycrate,
# * encoded to bytes and re-parsed before checking, so the same code path is
# * exercised as for a wire-observed PFCP packet. No UPF is involved.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *--------------------------------------------------------
#*/

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pycrate_mobile.TS29244_PFCP import (
    PFCPSessionEstablishmentReq,
    PFCPSessionModificationReq,
    PFCPSessionModificationResp,
    PFCPIEType as T,
    parse_PFCP,
    )

from tools.pfcp_session_check import (
    CheckCode,
    PFCPSessionState,
    check_modification,
    )


SEID = 0x1122334455667788


#------------------------------------------------------------------------------#
# Message builders
#------------------------------------------------------------------------------#

def _ie(ie_type, data=None):
    value = {'Type': ie_type}
    if data is not None:
        value['Data'] = data
    return value


def _pdi(source_if=0, te_id=None):
    inner = [_ie(T.SourceInterface.value, {'If': source_if})]
    if te_id is not None:
        inner.append(_ie(T.TrafficEndpointID.value, {'Val': te_id}))
    return _ie(T.PDI.value, inner)


def create_pdr(rule_id, far_id=None, urr_id=None, qer_id=None,
               precedence=100, te_id=None):
    inner = [
        _ie(T.PDRID.value, {'Val': rule_id}),
        _ie(T.Precedence.value, {'Val': precedence}),
        _pdi(te_id=te_id),
        ]
    if far_id is not None:
        inner.append(_ie(T.FARID.value, {'Val': far_id}))
    if urr_id is not None:
        inner.append(_ie(T.URRID.value, {'Val': urr_id}))
    if qer_id is not None:
        inner.append(_ie(T.QERID.value, {'Val': qer_id}))
    return _ie(T.CreatePDR.value, inner)


def update_pdr(rule_id, far_id=None, urr_id=None, qer_id=None, te_id=None):
    inner = [_ie(T.PDRID.value, {'Val': rule_id})]
    if far_id is not None:
        inner.append(_ie(T.FARID.value, {'Val': far_id}))
    if urr_id is not None:
        inner.append(_ie(T.URRID.value, {'Val': urr_id}))
    if qer_id is not None:
        inner.append(_ie(T.QERID.value, {'Val': qer_id}))
    if te_id is not None:
        inner.append(_ie(T.PDI.value,
                         [_ie(T.SourceInterface.value, {'If': 0}),
                          _ie(T.TrafficEndpointID.value, {'Val': te_id})]))
    return _ie(T.UpdatePDR.value, inner)


def remove_pdr(rule_id):
    return _ie(T.RemovePDR.value, [_ie(T.PDRID.value, {'Val': rule_id})])


def create_far(rule_id, action='FORW', bar_id=None, te_id=None):
    inner = [
        _ie(T.FARID.value, {'Val': rule_id}),
        _ie(T.ApplyAction.value, {'Octet1': {action: 1}}),
        ]
    if bar_id is not None:
        inner.append(_ie(T.BARID.value, {'Val': bar_id}))
    if te_id is not None:
        inner.append(_ie(T.ForwardingParameters.value, [
            _ie(T.DestinationInterface.value, {'Val': 0}),
            _ie(T.TrafficEndpointID.value, {'Val': te_id}),
            ]))
    return _ie(T.CreateFAR.value, inner)


def update_far(rule_id, action=None, bar_id=None, te_id=None):
    inner = [_ie(T.FARID.value, {'Val': rule_id})]
    if action is not None:
        inner.append(_ie(T.ApplyAction.value, {'Octet1': {action: 1}}))
    if bar_id is not None:
        inner.append(_ie(T.BARID.value, {'Val': bar_id}))
    if te_id is not None:
        inner.append(_ie(T.UpdateForwardingParameters.value, [
            _ie(T.TrafficEndpointID.value, {'Val': te_id})]))
    return _ie(T.UpdateFAR.value, inner)


def remove_far(rule_id):
    return _ie(T.RemoveFAR.value, [_ie(T.FARID.value, {'Val': rule_id})])


def create_urr(rule_id, linked_urr_id=None, far_id=None):
    inner = [
        _ie(T.URRID.value, {'Val': rule_id}),
        _ie(T.MeasurementMethod.value, b'\x00'),
        _ie(T.ReportingTriggers.value, b'\x00\x00\x00'),
        ]
    if linked_urr_id is not None:
        inner.append(_ie(T.LinkedURRID.value, {'Val': linked_urr_id}))
    if far_id is not None:
        inner.append(_ie(T.FARID.value, {'Val': far_id}))
    return _ie(T.CreateURR.value, inner)


def update_urr(rule_id, linked_urr_id=None):
    inner = [_ie(T.URRID.value, {'Val': rule_id})]
    if linked_urr_id is not None:
        inner.append(_ie(T.LinkedURRID.value, {'Val': linked_urr_id}))
    return _ie(T.UpdateURR.value, inner)


def remove_urr(rule_id):
    return _ie(T.RemoveURR.value, [_ie(T.URRID.value, {'Val': rule_id})])


def create_qer(rule_id):
    return _ie(T.CreateQER.value, [
        _ie(T.QERID.value, {'Val': rule_id}),
        _ie(T.GateStatus.value, {'ULGate': 0, 'DLGate': 0}),
        ])


def remove_qer(rule_id):
    return _ie(T.RemoveQER.value, [_ie(T.QERID.value, {'Val': rule_id})])


def create_bar(rule_id):
    return _ie(T.CreateBAR.value, [_ie(T.BARID.value, {'Val': rule_id})])


def remove_bar(rule_id):
    return _ie(T.RemoveBAR.value, [_ie(T.BARID.value, {'Val': rule_id})])


def create_te(rule_id):
    return _ie(T.CreateTrafficEndpoint.value, [
        _ie(T.TrafficEndpointID.value, {'Val': rule_id})])


def remove_te(rule_id):
    return _ie(T.RemoveTrafficEndpoint.value, [
        _ie(T.TrafficEndpointID.value, {'Val': rule_id})])


def _session_msg(cls, seid, rule_ies):
    msg = cls()
    ies = msg[1]
    ies.clear()
    if cls is PFCPSessionEstablishmentReq:
        ies.add_ie(T.NodeID.value, b'\x00\x0a\x00\x00\x01')
        ies.add_ie(T.FSEID.value, {'V4': 1, 'SEID': seid,
                                   'IPv4Addr': b'\x0a\x00\x00\x01'})
    else:
        msg[0]['SEID'].set_val(seid)
    for rule_ie in rule_ies:
        ies.add_ie(rule_ie['Type'], rule_ie.get('Data'))
    return msg


def build_establishment(rule_ies, seid=SEID):
    return _session_msg(PFCPSessionEstablishmentReq, seid, rule_ies)


def build_modification(rule_ies, seid=SEID):
    return _session_msg(PFCPSessionModificationReq, seid, rule_ies)


def roundtrip(msg):
    """Encode a message and return the re-parsed pycrate object."""
    buf = msg.to_bytes()
    decoded, err = parse_PFCP(buf)
    assert err == 0, 'unexpected parse error %u' % err
    return decoded, buf


def seeded_session(rule_ies, seid=SEID):
    est, _ = roundtrip(build_establishment(rule_ies, seid))
    return PFCPSessionState(seid).seed_from_establishment(est)


def codes(result):
    return sorted(f.code for f in result.findings)


#------------------------------------------------------------------------------#
# Test cases
#------------------------------------------------------------------------------#

class PFCPSessionCheckTest(unittest.TestCase):

    # -- baseline session ---------------------------------------------------#

    def _baseline(self):
        # Manual annotation - baseline installed session:
        #   PDR 10 -> FAR 10, URR 10, QER 10
        #   PDR 11 -> FAR 11, QER 10
        #   FAR 10 -> BAR 10 ; FAR 11 (forward, no BAR)
        #   URR 10 ; QER 10 ; BAR 10 ; Traffic Endpoint 10
        return seeded_session([
            create_te(10),
            create_bar(10),
            create_qer(10),
            create_urr(10),
            create_far(10, bar_id=10),
            create_far(11),
            create_pdr(10, far_id=10, urr_id=10, qer_id=10),
            create_pdr(11, far_id=11, qer_id=10),
            ])

    #-- Group A: one coherent, chained modification ------------------------#

    def test_group_a_coherent_chained_modification(self):
        # Manual annotation - legal linked modification in one message:
        #   * create BAR 11 and TE 11 (new objects)
        #   * create FAR 20 referencing BAR 11 and TE 11 (same-packet refs)
        #   * create URR 20 linked to existing URR 10 and referencing new FAR 20
        #   * create PDR 20 referencing new FAR 20 / URR 20 / existing QER 10
        #   * update existing FAR 10 to point at new TE 11
        #   * remove PDR 11, then FAR 11 (only user was PDR 11, same message)
        # Expected: ACCEPTED, zero findings; candidate resolves every reference.
        state = self._baseline()
        msg = build_modification([
            create_bar(11),
            create_te(11),
            create_far(20, bar_id=11, te_id=11),
            create_urr(20, linked_urr_id=10, far_id=20),
            create_pdr(20, far_id=20, urr_id=20, qer_id=10),
            update_far(10, te_id=11),
            remove_pdr(11),
            remove_far(11),
            ])
        decoded, buf = roundtrip(msg)

        # wire input is accepted as well as the live pycrate object
        result_bytes = check_modification(state, buf)
        result = check_modification(state, decoded)
        self.assertTrue(result_bytes.accepted)
        self.assertTrue(result.accepted)
        self.assertEqual(result.findings, [])

        # before/after declared inventory
        self.assertEqual(set(result.declared_before['PDR']), {10, 11})
        self.assertEqual(set(result.declared_after['PDR']), {10, 20})
        self.assertEqual(set(result.declared_after['FAR']), {10, 20})
        self.assertEqual(set(result.declared_after['BAR']), {10, 11})
        self.assertEqual(set(result.declared_after['TE']), {10, 11})

        # derived effective view: every reference resolves on the candidate
        pdr20 = result.effective_after['PDR'][20]
        resolved = {(fam, entry['id'])
                    for fam, entries in pdr20['refs'].items()
                    for entry in entries if entry['resolves']}
        self.assertEqual(resolved, {('FAR', 20), ('URR', 20), ('QER', 10)})
        far20 = result.effective_after['FAR'][20]
        self.assertTrue(all(e['resolves']
                            for entries in far20['refs'].values() for e in entries))
        # exact nested IE path is reported in the derived view
        self.assertIn(
            ['PFCPSessionModificationReq', 'IEs[2]', 'CreateFAR#0',
             'ForwardingParameters', 'TrafficEndpointID'],
            [e['path'] for e in far20['refs']['TE']])

        # transactional: state untouched until commit, then atomically updated
        self.assertEqual(set(state.rules['PDR']), {10, 11})
        result.commit()
        self.assertEqual(set(state.rules['PDR']), {10, 20})
        self.assertEqual(set(state.rules['FAR']), {10, 20})
        self.assertNotIn(11, state.rules['FAR'])

    #-- Group B: dangling / incoherent modifications -----------------------#

    def test_group_b1_dangling_far_reference(self):
        # Manual annotation: new PDR 30 references FAR 99, which is neither
        # installed nor created in this message.
        # Expected: REJECTED, one DANGLING_REFERENCE at the PDR's FARID path;
        # the installed session must stay unchanged.
        state = self._baseline()
        msg, buf = roundtrip(build_modification([
            create_pdr(30, far_id=99),
            ]))
        result = check_modification(state, buf)
        self.assertFalse(result.accepted)
        self.assertEqual(codes(result), [CheckCode.DANGLING_REFERENCE])
        finding = result.findings[0]
        self.assertEqual(finding.path, (
            'PFCPSessionModificationReq', 'IEs[0]', 'CreatePDR#0', 'FARID'))
        self.assertEqual(finding.affected,
                         ('PDR id=30 at PFCPSessionModificationReq.IEs[0].'
                          'CreatePDR#0',))
        with self.assertRaises(RuntimeError):
            result.commit()
        self.assertEqual(set(state.rules['PDR']), {10, 11})

    def test_group_b2_delete_far_still_in_use(self):
        # Manual annotation: remove FAR 10 while PDR 10 still references it and
        # is not removed in the same message.
        # Expected: REJECTED, DELETE_IN_USE naming PDR 10 as the surviving user.
        state = self._baseline()
        _, buf = roundtrip(build_modification([remove_far(10)]))
        result = check_modification(state, buf)
        self.assertFalse(result.accepted)
        self.assertEqual(codes(result), [CheckCode.DELETE_IN_USE])
        finding = result.findings[0]
        self.assertEqual(finding.path, (
            'PFCPSessionModificationReq', 'IEs[0]', 'RemoveFAR#0'))
        self.assertTrue(any('PDR id=10' in ref for ref in finding.affected))
        # FAR 10 stays installed because the transaction is rejected
        self.assertIn(10, state.rules['FAR'])

    def test_group_b3_duplicate_rule_ids(self):
        # Manual annotation: two CreatePDR IEs both use PDR ID 40, and another
        # CreatePDR reuses installed PDR ID 10.
        # Expected: REJECTED with DUP_RULE_ID findings pointing at both paths;
        # none of the new PDRs is installed.
        state = self._baseline()
        _, buf = roundtrip(build_modification([
            create_pdr(40, far_id=10),
            create_pdr(40, far_id=11),
            create_pdr(10, far_id=11),
            ]))
        result = check_modification(state, buf)
        self.assertFalse(result.accepted)
        self.assertEqual(codes(result).count(CheckCode.DUP_RULE_ID), 2)
        paths = [f.path for f in result.findings]
        self.assertIn((
            'PFCPSessionModificationReq', 'IEs[1]', 'CreatePDR#1'), paths)
        self.assertIn((
            'PFCPSessionModificationReq', 'IEs[2]', 'CreatePDR#2'), paths)
        self.assertEqual(set(state.rules['PDR']), {10, 11})

    def test_group_b4_update_missing_target(self):
        # Manual annotation: UpdateFAR 77 and RemoveURR 77 target rules that do
        # not exist in the session and are not created in the message.
        # Expected: REJECTED with UPDATE_TARGET_MISSING and REMOVE_TARGET_MISSING.
        state = self._baseline()
        _, buf = roundtrip(build_modification([
            update_far(77, action='DROP'),
            remove_urr(77),
            ]))
        result = check_modification(state, buf)
        self.assertFalse(result.accepted)
        self.assertEqual(codes(result),
                         [CheckCode.REMOVE_TARGET_MISSING,
                          CheckCode.UPDATE_TARGET_MISSING])
        self.assertEqual(result.findings[0].path, (
            'PFCPSessionModificationReq', 'IEs[0]', 'UpdateFAR#0'))

    def test_group_b5_same_packet_create_then_dangling(self):
        # Manual annotation: URR 30 is created and linked to URR 31 which is
        # never created; simultaneously URR 10, still referenced by surviving
        # PDR 10, is removed. One message therefore contains a same-packet
        # dangling reference and a delete-in-use at the same time.
        # Expected: REJECTED with DANGLING_REFERENCE (nested LinkedURRID path)
        # and DELETE_IN_USE; both pre-existing and non-installed candidate views
        # are retained for inspection.
        state = self._baseline()
        _, buf = roundtrip(build_modification([
            create_urr(30, linked_urr_id=31),
            remove_urr(10),
            ]))
        result = check_modification(state, buf)
        self.assertFalse(result.accepted)
        self.assertEqual(codes(result),
                         [CheckCode.DANGLING_REFERENCE, CheckCode.DELETE_IN_USE])
        dangling = next(f for f in result.findings
                        if f.code == CheckCode.DANGLING_REFERENCE)
        self.assertEqual(dangling.path, (
            'PFCPSessionModificationReq', 'IEs[0]', 'CreateURR#0',
            'LinkedURRID'))
        delete_use = next(f for f in result.findings
                          if f.code == CheckCode.DELETE_IN_USE)
        self.assertEqual(delete_use.path, (
            'PFCPSessionModificationReq', 'IEs[1]', 'RemoveURR#0'))
        self.assertTrue(
            'PDR id=10' in {ref.split(' at ')[0] for ref in delete_use.affected})
        # declared/effective views remain available on both sides
        self.assertNotIn(30, result.declared_before['URR'])
        self.assertIn(30, result.declared_after['URR'])
        self.assertIn(10, result.declared_before['URR'])
        # candidate dangling link is visibly unresolved in the derived view
        self.assertFalse(result.effective_after['URR'][30]['refs']['URR'][0][
            'resolves'])
        # and nothing is installed
        self.assertEqual(set(state.rules['URR']), {10})
        self.assertNotIn(30, state.rules['URR'])

    #-- scope and transaction semantics -------------------------------------#

    def test_scope_mismatch_wrong_seid_and_msg_type(self):
        # Manual annotation: a Modification Request addressed to another SEID is
        # out of scope; a Session Modification Response fed into the checker is
        # rejected by the message-type scope guard.
        state = self._baseline()
        _, wrong_seid = roundtrip(build_modification(
            [remove_far(11)], seid=SEID ^ 0xff))
        result = check_modification(state, wrong_seid)
        self.assertEqual(codes(result), [CheckCode.SCOPE_MISMATCH])
        self.assertEqual(result.findings[0].path,
                         ('PFCPSessionModificationReq', 'Hdr', 'SEID'))

        resp = PFCPSessionModificationResp()
        resp[1].clear()
        resp[1].add_ie(T.Cause.value, b'\x01')
        resp_buf = resp.to_bytes()
        result_resp = check_modification(state, resp_buf)
        self.assertEqual(codes(result_resp), [CheckCode.SCOPE_MISMATCH])

    def test_decode_error_rejected(self):
        # Manual annotation: truncated bytes cannot be a valid modification and
        # must produce DECODE_ERROR rather than any partial rule installation.
        state = self._baseline()
        result = check_modification(state, b'\x21\x34\x00')
        self.assertEqual(codes(result), [CheckCode.DECODE_ERROR])
        with self.assertRaises(RuntimeError):
            result.commit()
        self.assertEqual(set(state.rules['PDR']), {10, 11})

    def test_nested_pdi_traffic_endpoint_dangling(self):
        # Manual annotation: a new PDR references Traffic Endpoint 99 from inside
        # its PDI; the path must reach through the grouped PDI IE.
        # Expected: REJECTED, DANGLING_REFERENCE with a PDI-qualified path.
        state = self._baseline()
        _, buf = roundtrip(build_modification([
            create_pdr(40, far_id=10, te_id=99),
            ]))
        result = check_modification(state, buf)
        self.assertEqual(codes(result), [CheckCode.DANGLING_REFERENCE])
        self.assertEqual(result.findings[0].path, (
            'PFCPSessionModificationReq', 'IEs[0]', 'CreatePDR#0',
            'PDI', 'TrafficEndpointID'))

    def test_update_merge_retains_untouched_references(self):
        # Manual annotation: UpdatePDR 10 only carries a new FARID; per TS 29.244
        # the update is field-level, so the installed URR/QER references must be
        # retained while FAR moves to FAR 11. Pointing the update at a missing
        # FAR 98 must instead be rejected with the update's IE path.
        state = self._baseline()
        _, ok_buf = roundtrip(build_modification([update_pdr(10, far_id=11)]))
        ok_result = check_modification(state, ok_buf)
        self.assertTrue(ok_result.accepted)
        refs = ok_result.effective_after['PDR'][10]['refs']
        self.assertEqual(sorted(e['id'] for e in refs['FAR']), [11])
        self.assertEqual(sorted(e['id'] for e in refs['URR']), [10])
        self.assertEqual(sorted(e['id'] for e in refs['QER']), [10])

        _, bad_buf = roundtrip(build_modification([update_pdr(10, far_id=98)]))
        bad_result = check_modification(state, bad_buf)
        self.assertEqual(codes(bad_result), [CheckCode.DANGLING_REFERENCE])
        self.assertEqual(bad_result.findings[0].path, (
            'PFCPSessionModificationReq', 'IEs[0]', 'UpdatePDR#0', 'FARID'))
        self.assertEqual(set(state.rules['PDR']), {10, 11})


if __name__ == '__main__':
    unittest.main(verbosity=2)
