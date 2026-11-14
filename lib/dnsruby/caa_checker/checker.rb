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
    # Offline, reviewable CAA authorization decision per RFC 8659.
    #
    # The checker takes the domain to be certified, whether the request is
    # for a wildcard name, the issuer identifier to test, and an offline
    # answer provider.  It never touches the network: every DNS response
    # comes from the provider, and every query is recorded in the trace of
    # the returned Result.
    #
    # Processing follows RFC 8659 section 3:
    #
    # * the DNS name tree is climbed from the requested label up to, but
    #   not including, the root, and the first non-empty CAA RRset found is
    #   the Relevant RRset;
    # * CNAME and DNAME aliases are chased at each label (RFC 1034
    #   section 4.3.2, as updated by RFC 6672), so a name aliased to
    #   another policy is evaluated against that policy only - policies at
    #   different names are never merged;
    # * a query that cannot be completed (SERVFAIL, REFUSED, NOTIMP,
    #   timeout, truncated response, alias loop, missing fixture) is a
    #   separate +lookup_incomplete+ outcome and is never mistaken for
    #   "no CAA policy".
    class Checker
      # Property Tags this checker understands.  A critical Property with
      # any other tag forbids issuance (RFC 8659 section 4.5).
      SUPPORTED_TAGS = %w[issue issuewild iodef].freeze

      # Maximum alias redirections followed for one logical CAA query.
      MAX_ALIAS_HOPS = 16

      # LDH label / issuer-domain-name grammar from RFC 8659 section 4.2.
      LDH_DOMAIN =
        /\A(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\z/.freeze

      # @param provider [Provider] offline DNS answer provider
      def initialize(provider)
        @provider = provider
      end

      # Determine whether +issuer+ is authorized for +domain+.
      #
      # @param domain [String, Dnsruby::Name] the FQDN to be certified.
      #   A leading "*." is accepted and implies a wildcard request.
      # @param wildcard [Boolean] whether the request is for a Wildcard
      #   Domain Name (*.domain)
      # @param issuer [String] the issuer-domain-name being tested, e.g.
      #   "ca.example.net"
      # @return [Result]
      def authorize(domain:, wildcard: false, issuer:)
        base_name, wildcard = normalize_input(domain, wildcard)
        issuer_name = normalize_issuer(issuer)
        trace = []

        begin
          relevant_name, relevant_records =
            find_relevant_rrset(base_name, trace)
        rescue LookupIncomplete => e
          return result(
            decision: :lookup_incomplete,
            reason: :lookup_failed,
            reason_message: "CAA query could not be completed (#{e.message}); authorization is undetermined",
            domain: base_name.to_s, wildcard: wildcard, issuer: issuer,
            relevant_name: nil, relevant_records: [], trace: trace,
            failure: { reason: :lookup_failed, name: e.name, rcode: e.rcode, message: e.message }
          )
        end

        if relevant_records.empty?
          return result(
            decision: :no_policy,
            reason: :no_policy,
            reason_message: "lookup completed and no CAA RRset exists on the path; CAA imposes no restriction",
            domain: base_name.to_s, wildcard: wildcard, issuer: issuer,
            relevant_name: nil, relevant_records: [], trace: trace
          )
        end

        evaluate(relevant_name, relevant_records, wildcard, issuer, issuer_name, trace)
      end

      private

      # Strip an optional wildcard prefix, validate the name and return an
      # absolute Dnsruby::Name plus the effective wildcard flag.
      def normalize_input(domain, wildcard)
        text = domain.to_s.strip.downcase
        if text.start_with?("*.")
          text = text[2..]
          wildcard = true
        end
        raise InvalidInput, "domain must not be empty" if text.empty?

        name =
          begin
            Dnsruby::Name.create(text)
          rescue Dnsruby::DecodeError => e
            raise InvalidInput, "invalid domain #{domain.inspect}: #{e.message}"
          end
        raise InvalidInput, "domain #{domain.inspect} has no issuable labels" if name.labels.empty?

        [name, !!wildcard]
      end

      def normalize_issuer(issuer)
        text = issuer.to_s.strip.downcase.sub(/\.\z/, "")
        raise InvalidInput, "issuer identifier must not be empty" if text.empty?
        unless text.match?(LDH_DOMAIN)
          raise InvalidInput, "issuer identifier #{issuer.inspect} is not a valid LDH domain name"
        end
        text
      end

      # Dnsruby::Name#== distinguishes absolute from relative names, while
      # DNS comparison does not.  Compare the label sequences instead.
      def same_name?(left, right)
        left.labels.map(&:string) == right.labels.map(&:string)
      end

      # RFC 8659 section 3: climb the tree until a non-empty CAA RRset is
      # found or the root is reached.  Returns [name, records]; an empty
      # array means the whole path was traversed without any policy.
      def find_relevant_rrset(base_name, trace)
        name = base_name
        until name.labels.empty?
          terminal_name, message = chase_aliases(name, trace)
          records = message.answer.select do |rr|
            rr.type == Dnsruby::Types::CAA && same_name?(rr.name, terminal_name)
          end
          return [terminal_name.to_s, records] unless records.empty?

          name = name.strip_label
        end
        [nil, []]
      end

      # Resolve one logical CAA query for +start_name+, following CNAME and
      # DNAME redirections.  Returns [terminal_name, final_message].
      # Raises LookupIncomplete when any query cannot be completed or an
      # alias loop / over-long chain is encountered.
      def chase_aliases(start_name, trace)
        current = start_name
        visited = {}
        hops = 0

        loop do
          message = query_provider(current, trace)
          check_response!(message, current)

          alias_rr = find_alias_rr(message, current)

          return [current, message] unless alias_rr

          target = alias_target(current, alias_rr)
          hops += 1
          if hops > MAX_ALIAS_HOPS || visited.key?(target.to_s) || same_name?(target, current)
            raise LookupIncomplete.new(
              "alias loop or chain longer than #{MAX_ALIAS_HOPS} hops at #{current}",
              name: current.to_s
            )
          end
          visited[current.to_s] = true
          visited[target.to_s] = true
          current = target
        end
      end

      def query_provider(name, trace)
        message = @provider.query(name)
        unless message.is_a?(Dnsruby::Message)
          raise LookupIncomplete.new(
            "provider returned #{message.class} instead of Dnsruby::Message for #{name}",
            name: name.to_s
          )
        end
        trace << build_trace_entry(name, message)
        message
      rescue LookupIncomplete
        raise
      rescue StandardError => e
        raise LookupIncomplete.new(
          "provider failed CAA query for #{name}: #{e.class}: #{e.message}",
          name: name.to_s
        )
      end

      def check_response!(message, name)
        rcode = message.rcode.to_i
        if message.header.tc
          raise LookupIncomplete.new(
            "truncated CAA response for #{name}", name: name.to_s, rcode: rcode
          )
        end
        # NOERROR and NXDOMAIN are completed answers.  NXDOMAIN is treated
        # as an empty answer (the name exists in the tree only via the
        # parent zone, which publishes no CAA at this label).  Every other
        # rcode means the lookup cannot be completed.
        return if rcode == Dnsruby::RCode::NOERROR || rcode == Dnsruby::RCode::NXDOMAIN

        raise LookupIncomplete.new(
          "CAA query for #{name} returned rcode #{rcode}",
          name: name.to_s, rcode: rcode
        )
      end

      # CNAME only matches the exact queried name.  A DNAME applies to a
      # whole subtree: its owner is a suffix of the queried name, and the
      # synthesized CNAME substitutes that suffix with the DNAME target
      # (RFC 6672).  Exact-name CNAME/DNAME records take precedence.
      def find_alias_rr(message, current)
        exact = message.answer.find do |rr|
          same_name?(rr.name, current) &&
            (rr.type == Dnsruby::Types::CNAME || rr.type == Dnsruby::Types::DNAME)
        end
        return exact if exact

        message.answer.find do |rr|
          rr.type == Dnsruby::Types::DNAME && suffix_of?(rr.name, current)
        end
      end

      def suffix_of?(suffix_name, name)
        suffix = suffix_name.labels.map(&:string)
        labels = name.labels.map(&:string)
        labels.length >= suffix.length && labels.last(suffix.length) == suffix
      end

      # Compute the redirection target of a CNAME or DNAME RR.  For DNAME,
      # the target is the DNAME target plus the labels of the queried name
      # below the DNAME owner (RFC 6672); a query for the owner itself
      # redirects to the bare DNAME target.
      def alias_target(query_name, alias_rr)
        return alias_rr.domainname if alias_rr.type == Dnsruby::Types::CNAME
        return alias_rr.domainname if same_name?(alias_rr.name, query_name)

        owner_labels = alias_rr.name.labels.map(&:string)
        query_labels = query_name.labels.map(&:string)
        suffix_labels = query_labels[0, query_labels.length - owner_labels.length]
        target = alias_rr.domainname.to_s.sub(/\.\z/, "")
        target = "#{suffix_labels.join('.')}.#{target}" unless suffix_labels.empty?
        Dnsruby::Name.create(target)
      end

      def build_trace_entry(name, message)
        rcode = message.rcode.to_i
        alias_rr = find_alias_rr(message, name)
        # Only the records at the terminal (post-alias) name can become a
        # Relevant RRset; CAA RRs elsewhere in a chained answer belong to a
        # different lookup step and must not be merged into this one.
        terminal = alias_rr ? alias_target(name, alias_rr) : name
        records = message.answer.select do |rr|
          rr.type == Dnsruby::Types::CAA && same_name?(rr.name, terminal)
        end
        outcome =
          if alias_rr
            :alias
          elsif records.any?
            :rrset
          elsif rcode == Dnsruby::RCode::NXDOMAIN
            :nxdomain
          elsif rcode != Dnsruby::RCode::NOERROR
            :failed
          else
            :empty
          end
        TraceEntry.new(
          queried_name: name.to_s,
          rcode: rcode,
          alias_target: alias_rr&.domainname&.to_s,
          records: records,
          outcome: outcome
        )
      end

      # Apply RFC 8659 section 4 semantics to the Relevant RRset.
      def evaluate(relevant_name, records, wildcard, issuer, issuer_name, trace)
        critical_unknown = records.find do |rr|
          (rr.flag & 0x80).nonzero? && !SUPPORTED_TAGS.include?(rr.property_tag.to_s.downcase)
        end
        if critical_unknown
          return deny(
            records, relevant_name, wildcard, issuer, trace,
            :unknown_critical_property,
            "critical Property #{critical_unknown.property_tag.inspect} is not supported; issuance is forbidden"
          )
        end

        candidates = candidate_records(records, wildcard)
        if candidates.empty?
          return result(
            decision: :allow,
            reason: :no_restricting_properties,
            reason_message: "Relevant RRset contains no issue/issuewild Property that restricts this request",
            domain: trace_domain(trace), wildcard: wildcard, issuer: issuer,
            relevant_name: relevant_name, relevant_records: records, trace: trace
          )
        end

        evaluations = candidates.map { |rr| evaluate_record(rr, issuer_name) }
        authorized = evaluations.any? { |ev| ev[:decision] == :authorized }

        if authorized
          return result(
            decision: :allow,
            reason: :authorized,
            reason_message: "Relevant RRset at #{relevant_name} authorizes #{issuer}",
            domain: trace_domain(trace), wildcard: wildcard, issuer: issuer,
            relevant_name: relevant_name, relevant_records: records,
            trace: trace, evaluations: evaluations
          )
        end

        reason =
          if evaluations.any? { |ev| ev[:reason] == :empty_issuer }
            :empty_issuer
          elsif evaluations.any? { |ev| ev[:reason] == :unsupported_parameters }
            :unsupported_parameters
          else
            :issuer_not_listed
          end
        deny(records, relevant_name, wildcard, issuer, trace, reason,
             "Relevant RRset at #{relevant_name} does not authorize #{issuer}",
             evaluations)
      end

      # RFC 8659 section 4.3: issuewild only applies to wildcard requests;
      # for a wildcard request, any issuewild Property makes all issue
      # Properties irrelevant.
      def candidate_records(records, wildcard)
        issuewild = records.select { |rr| rr.property_tag.to_s.downcase == "issuewild" }
        issue = records.select { |rr| rr.property_tag.to_s.downcase == "issue" }
        if wildcard
          issuewild.any? ? issuewild : issue
        else
          issue
        end
      end

      def evaluate_record(rr, issuer_name)
        parsed = parse_property_value(rr.property_value.to_s)
        base = {
          tag: rr.property_tag.to_s.downcase,
          flag: rr.flag,
          raw_value: rr.property_value.to_s
        }

        if parsed[:empty] || parsed[:malformed_domain]
          base.merge(decision: :deny, reason: :empty_issuer,
                     detail: "empty or malformed issuer-domain-name requests no issuance")
        elsif parsed[:parameters].any?
          base.merge(decision: :deny, reason: :unsupported_parameters,
                     detail: "issuer parameters #{parsed[:parameters].inspect} cannot be satisfied by this checker")
        elsif parsed[:domain] == issuer_name
          base.merge(decision: :authorized, reason: :authorized,
                     detail: "issuer-domain-name matches")
        else
          base.merge(decision: :deny, reason: :issuer_not_listed,
                     detail: "record authorizes #{parsed[:domain].inspect}, not #{issuer_name.inspect}")
        end
      end

      # Parse an issue/issuewild Property Value per RFC 8659 section 4.2.
      def parse_property_value(value)
        head, *param_segments = value.split(";")
        domain = head.to_s.strip
        parameters = param_segments.filter_map do |segment|
          tag, raw_value = segment.split("=", 2)
          tag = tag.to_s.strip
          tag.empty? ? nil : { tag: tag.downcase, value: raw_value.to_s.strip }
        end
        {
          domain: domain,
          empty: domain.empty?,
          malformed_domain: !domain.empty? && !domain.match?(LDH_DOMAIN),
          parameters: parameters
        }
      end

      def deny(records, relevant_name, wildcard, issuer, trace, reason, message, evaluations = [])
        result(
          decision: :deny,
          reason: reason,
          reason_message: message,
          domain: trace_domain(trace), wildcard: wildcard, issuer: issuer,
          relevant_name: relevant_name, relevant_records: records,
          trace: trace, evaluations: evaluations
        )
      end

      def trace_domain(trace)
        trace.first&.queried_name || ""
      end

      def result(**attributes)
        Result.new(**attributes)
      end
    end
  end
end
