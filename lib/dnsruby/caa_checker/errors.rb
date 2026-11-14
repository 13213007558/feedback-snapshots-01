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
    # Base class for all errors raised by the offline CAA checker.
    class Error < Dnsruby::ResolvError
    end

    # Raised when an input argument is not a valid domain name or when a
    # lookup configuration is internally inconsistent (for example, an
    # alias loop).  These are caller errors, not DNS lookup failures.
    class InvalidInput < Error
    end

    # Raised when the CAA decision cannot be reached because a DNS query
    # could not be completed.  This is deliberately distinct from a
    # completed query that simply returned no CAA records ("no policy").
    #
    # Typical causes are SERVFAIL / REFUSED / NOTIMP responses, timeouts,
    # bogus DNSSEC validation, or an offline answer provider that has no
    # answer recorded for a query that the lookup path actually needed.
    class LookupIncomplete < Error
      # @return [String] the name that could not be looked up
      attr_reader :name
      # @return [String, Integer, nil] the DNS rcode, if a response was seen
      attr_reader :rcode

      def initialize(message, name: nil, rcode: nil)
        @name = name
        @rcode = rcode
        super(message)
      end
    end
  end
end
