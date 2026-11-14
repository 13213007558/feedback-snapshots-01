#
# Copyright (c) 2013-2026 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# bundler-audit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# bundler-audit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with bundler-audit.  If not, see <https://www.gnu.org/licenses/>.
#

require 'bundler/audit/results/result'

module Bundler
  module Audit
    module Results
      #
      # Represents a locked gem instance whose vulnerability cannot be proven
      # either way. The instance is sourced from git or a local path, so the
      # contents cannot be shown to be identical to the published public
      # package that the advisory describes; matching the name and version
      # alone is not sufficient evidence for a security conclusion.
      #
      class InconclusiveGem < Result

        # The locked gem instance whose status is unknown.
        #
        # @return [LockedGem]
        attr_reader :gem

        # The advisory that may apply to the published package.
        #
        # @return [Advisory]
        attr_reader :advisory

        # The evidence explaining why no conclusion could be reached.
        #
        # @return [Hash{Symbol => Object}]
        attr_reader :evidence

        #
        # Initializes the inconclusive gem result.
        #
        # @param [LockedGem] gem
        # @param [Advisory] advisory
        #
        def initialize(gem,advisory)
          @gem      = gem
          @advisory = advisory
          @evidence = {
            source_type: gem.source_type,
            source:      gem.source,
            message:     "cannot prove the #{gem.source_type} source is " \
                         "identical to the published package; name and " \
                         "version alone are insufficient evidence"
          }
        end

        #
        # Compares the inconclusive gem to another result.
        #
        # @param [Result] other
        #
        # @return [Boolean]
        #
        def ==(other)
          self.class == other.class && (
            @gem == other.gem &&
            @advisory == other.advisory
          )
        end

        #
        # Converts the result into a String.
        #
        # @return [String]
        #
        def to_s
          @advisory.id
        end

        #
        # Converts the result into a Hash.
        #
        # @return [Hash{Symbol => Object}]
        #
        def to_h
          {
            type:     :inconclusive_gem,
            gem:      @gem.to_h,
            advisory: @advisory.to_h,
            evidence: @evidence
          }
        end

      end
    end
  end
end
