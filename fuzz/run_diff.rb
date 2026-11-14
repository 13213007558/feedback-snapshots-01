# frozen_string_literal: true

require_relative 'harness'
require_relative 'corpus'

module DiffFuzz
  class Runner
    # Three-dimensional oracle. A difference is any mismatch across:
    #   verdict (accept/reject/crash), trusted-payload readability, finder
    #   invocation, plus (secondary) the concrete exception class on rejection.
    def divergent?(legacy, new_api)
      legacy.verdict != new_api.verdict ||
        legacy.trusted != new_api.trusted ||
        legacy.finder_called != new_api.finder_called ||
        error_class_differs?(legacy, new_api)
    end

    # Only count an exception-class gap when both sides reject cleanly. A crash
    # is handled separately and is never equated with a normal JWT rejection.
    def error_class_differs?(legacy, new_api)
      return false if legacy.crash? || new_api.crash?
      return false unless legacy.rejected? && new_api.rejected?

      legacy.error_class != new_api.error_class
    end

    def run(cases)
      cases.filter_map do |c|
        legacy, new_api = DiffFuzz.compare(c.token,
                                           payload_override: c.payload_override,
                                           use_finder: c.use_finder)
        next unless divergent?(legacy, new_api)

        DiffRow.new(case_meta: c, legacy: legacy, new_api: new_api,
                    kind: classify(c, legacy, new_api))
      end
    end

    # Classification into vulnerability / compatibility / needs-clarification.
    def classify(c, legacy, new_api)
      # A non-JWT exception on either side is a robustness crash, never a clean reject.
      return :vulnerability_crash if legacy.crash? || new_api.crash?

      # Trusted payload readable on one side but not the other (possible exposure).
      if new_api.trusted != legacy.trusted
        return new_api.trusted ? :vulnerability_payload_exposure : :clarify_payload_exposure
      end

      # New API accepts while legacy rejects the same compact token.
      if new_api.accepted? && legacy.rejected?
        # Detached payload (RFC 7515 Appendix F) is an intentional new-API feature
        # the legacy entry point cannot express; not a bypass.
        return c.category == 'detached_payload' ? :compatibility_detached_payload
                                                 : :vulnerability_acceptance_bypass
      end

      # Legacy looser than new: triage as a compatibility/contract gap.
      return :compatibility_legacy_looser if legacy.accepted? && new_api.rejected?

      # Both reject cleanly but the key-finder callback differs.
      return :compatibility_finder_timing if legacy.finder_called != new_api.finder_called

      # Both reject cleanly with different exception classes.
      return :clarify_error_class if error_class_differs?(legacy, new_api)

      :clarify_other
    end
  end

  DiffRow = Struct.new(:case_meta, :legacy, :new_api, :kind, keyword_init: true)
end
