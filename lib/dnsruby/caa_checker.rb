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

require 'dnsruby' unless defined?(Dnsruby::ResolvError)
require 'dnsruby/caa_checker/errors'
require 'dnsruby/caa_checker/result'
require 'dnsruby/caa_checker/provider'
require 'dnsruby/caa_checker/checker'

module Dnsruby
  # Offline CAA (Certification Authority Authorization) authorization
  # checking.  See Dnsruby::CaaChecker::Checker for the decision algorithm
  # and Dnsruby::CaaChecker::StaticProvider for a reviewable offline answer
  # source.
  module CaaChecker
    module_function

    # Convenience wrapper around Dnsruby::CaaChecker::Checker#authorize.
    #
    # @param domain [String, Dnsruby::Name] FQDN to be certified (a leading
    #   "*." implies a wildcard request)
    # @param wildcard [Boolean] whether the request is for *.domain
    # @param issuer [String] issuer-domain-name to test
    # @param provider [Provider] offline DNS answer provider
    # @return [Result]
    def authorize(domain:, wildcard: false, issuer:, provider:)
      Checker.new(provider).authorize(
        domain: domain, wildcard: wildcard, issuer: issuer
      )
    end
  end
end
