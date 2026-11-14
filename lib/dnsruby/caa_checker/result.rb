# --
# Copyright 2007 Nominet UK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

module Dnsruby
  module CaaChecker
    # One step of the CAA lookup path.  Every CAA query issued by the
    # checker (including alias chases and tree climbs) produces a trace
    # entry, so a reviewer can reconstruct exactly which offline answers
    # were consulted and why the lookup stopped where it did.
    class TraceEntry
      # @return [String] the name the CAA query was sent for
      attr_reader :queried_name
      # @return [Integer] the DNS rcode of the provider response
      attr_reader :rcode
      # @return [String, nil] the alias target when the answer contained a
      #   CNAME/DNAME, otherwise nil
      attr_reader :alias_target
      # @return [Array<Dnsruby::RR::CAA>] CAA records returned in the answer
      attr_reader :records
      # @return [Symbol] one of :empty, :nxdomain, :failed, :alias, :rrset
      attr_reader :outcome

      def initialize(queried_name:, rcode:, alias_target:, records:, outcome:)
        @queried_name = queried_name
        @rcode = rcode
        @alias_target = alias_target
        @records = records
        @outcome = outcome
      end

      def to_h
        {
          queried_name: @queried_name,
          rcode: @rcode,
          alias_target: @alias_target,
          outcome: @outcome,
          records: @records.map(&:rdata_to_string)
        }
      end
    end

    # The reviewable outcome of a CAA authorization decision.
    #
    # +decision+ is one of:
    #
    # [:allow]           the Relevant RRset authorizes the named issuer
    # [:deny]            a Relevant RRset exists but does not authorize
    #                    the named issuer (includes empty issuer
    #                    requests and unknown critical Properties)
    # [:no_policy]       the lookup completed but no CAA RRset exists
    #                    anywhere on the path, so CAA imposes no
    #                    restriction
    # [:lookup_incomplete] one or more queries could not be completed;
    #                    the authorization question is unanswered
    class Result
      # @return [Symbol] :allow, :deny, :no_policy or :lookup_incomplete
      attr_reader :decision
      # @return [String, nil] machine-readable reason code for the decision
      attr_reader :reason
      # @return [String] human-readable explanation
      attr_reader :reason_message
      # @return [String] the requested domain (wildcard prefix stripped)
      attr_reader :domain
      # @return [Boolean] whether the request was for a wildcard name
      attr_reader :wildcard
      # @return [String] the issuer identifier that was tested
      attr_reader :issuer
      # @return [String, nil] owner name of the Relevant RRset; nil when no
      #   RRset was found or the lookup was incomplete
      attr_reader :relevant_name
      # @return [Array<Dnsruby::RR::CAA>] the Relevant RRset (possibly empty)
      attr_reader :relevant_records
      # @return [Array<TraceEntry>] every query made along the lookup path
      attr_reader :trace
      # @return [Array<Hash>] per-record issuer evaluation details
      attr_reader :evaluations
      # @return [Hash, nil] the failed-query details when decision is
      #   :lookup_incomplete
      attr_reader :failure

      def initialize(decision:, reason:, reason_message:, domain:, wildcard:, issuer:,
                     relevant_name:, relevant_records:, trace:, evaluations: [], failure: nil)
        @decision = decision
        @reason = reason
        @reason_message = reason_message
        @domain = domain
        @wildcard = wildcard
        @issuer = issuer
        @relevant_name = relevant_name
        @relevant_records = relevant_records
        @trace = trace
        @evaluations = evaluations
        @failure = failure
      end

      # Convenience predicates.
      %i[allow deny no_policy lookup_incomplete].each do |state|
        define_method("#{state}?") { @decision == state }
      end

      def to_h
        {
          decision: @decision,
          reason: @reason,
          reason_message: @reason_message,
          domain: @domain,
          wildcard: @wildcard,
          issuer: @issuer,
          relevant_name: @relevant_name,
          relevant_records: @relevant_records.map(&:rdata_to_string),
          trace: @trace.map(&:to_h),
          evaluations: @evaluations,
          failure: @failure
        }
      end
    end
  end
end
