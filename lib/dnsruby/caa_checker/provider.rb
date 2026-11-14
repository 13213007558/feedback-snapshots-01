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
    # A provider answers offline CAA queries.  The checker never performs
    # network I/O itself: it only calls #query on the injected provider.
    #
    # Implementations MUST return a Dnsruby::Message representing the
    # response to a CAA query for +name+.  To signal that a query could not
    # be completed (timeout, SERVFAIL that cannot be resolved, bogus
    # DNSSEC, missing offline fixture, ...), raise
    # Dnsruby::CaaChecker::LookupIncomplete.  A completed response with no
    # CAA records (including an NXDOMAIN name-existence answer) is simply a
    # Message whose answer section contains no CAA RRs; that is "no
    # policy", not a failed query.
    module Provider
      # @param name [Dnsruby::Name] the name being queried for CAA
      # @return [Dnsruby::Message] the offline DNS response
      # @raise [LookupIncomplete] if the query cannot be completed
      def query(name)
        raise NotImplementedError, "#{self.class} must implement #query"
      end
    end

    # A deterministic, in-memory Provider backed by a fixture table.
    #
    # The table is keyed by the absolute, lowercased name queried.  Each
    # entry describes the response returned for a CAA query at that name:
    #
    #   {
    #     "example.com" => {
    #       rcode: "NOERROR",                       # optional, default NOERROR
    #       answer: [                               # RRs in presentation form
    #         'example.com. 300 IN CAA 0 issue "ca.example.net"',
    #         'alias.example.com. IN CNAME target.example.net.'
    #       ]
    #     },
    #     "broken.example.com" => { rcode: "SERVFAIL" },
    #     "gone.example.com"   => { rcode: "NXDOMAIN" }
    #   }
    #
    # A pre-built Dnsruby::Message may be supplied instead of a Hash for
    # full control over the response.
    #
    # Names that are absent from the table do not silently mean "no
    # records".  By default the provider raises LookupIncomplete, because an
    # unrecorded query means the offline dataset cannot answer it.  Pass
    # +missing: :empty+ to treat missing names as completed empty NOERROR
    # responses, or +missing: :nxdomain+ to treat them as NXDOMAIN.
    class StaticProvider
      include Provider

      # @return [Hash{String => Dnsruby::Message}] normalized fixture table
      attr_reader :table

      # @param fixtures [Hash{String, Symbol => Hash, Dnsruby::Message}]
      # @param missing [:raise, :empty, :nxdomain] policy for unlisted names
      def initialize(fixtures = nil, missing: :raise)
        unless %i[raise empty nxdomain].include?(missing)
          raise InvalidInput, "missing must be one of :raise, :empty, :nxdomain"
        end
        @missing = missing
        @table = {}
        Array(fixtures).each { |name, spec| add(name, spec) }
      end

      # Add or replace the response for +name+.
      #
      # @param name [String, Dnsruby::Name]
      # @param spec [Hash, Dnsruby::Message]
      # @return [void]
      def add(name, spec)
        key = normalize_name(name)
        @table[key] = build_message(name, spec)
      end

      # @see Provider#query
      def query(name)
        key = normalize_name(name)
        message = @table[key]

        # A single fixture may describe a whole recursive-style answer:
        # a CNAME at one name together with the target's records, or a
        # DNAME whose owner is a suffix of the queried name.  Serve that
        # message for the derived name too when no more specific fixture
        # exists.
        message ||= @table.each_value.find do |candidate|
          candidate.answer.any? { |rr| covers?(rr, key) }
        end

        return message if message

        case @missing
        when :raise
          raise LookupIncomplete.new(
            "no offline DNS answer recorded for CAA query for #{key}",
            name: key
          )
        when :empty
          empty_message(rcode: Dnsruby::RCode::NOERROR)
        when :nxdomain
          empty_message(rcode: Dnsruby::RCode::NXDOMAIN)
        end
      end

      private

      def covers?(rr, key)
        return true if normalize_name(rr.name) == key

        if rr.type == Dnsruby::Types::DNAME
          owner = normalize_name(rr.name)
          key != owner && key.end_with?(".#{owner}")
        else
          false
        end
      end

      def normalize_name(name)
        Dnsruby::Name.create(name.to_s).downcase.to_s
      end

      def build_message(name, spec)
        return spec if spec.is_a?(Dnsruby::Message)

        unless spec.is_a?(Hash)
          raise InvalidInput,
                "fixture for #{name} must be a Hash or Dnsruby::Message, got #{spec.class}"
        end

        message = Dnsruby::Message.new(name, Dnsruby::Types::CAA)
        message.header.rcode = spec.fetch(:rcode, Dnsruby::RCode::NOERROR)
        Array(spec[:answer]).each do |rr|
          message.add_answer(rr.is_a?(Dnsruby::RR) ? rr : Dnsruby::RR.create(rr))
        end
        message
      end

      def empty_message(rcode:)
        message = Dnsruby::Message.new
        message.header.rcode = rcode
        message
      end
    end
  end
end
