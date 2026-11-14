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
      # Represents a locked gem instance that is explicitly not affected by an
      # advisory. This is used when an advisory restricts the affected
      # platforms or supply sources and the instance falls outside that scope,
      # so that the other locked variants of the same gem remain visible in the
      # report instead of being silently removed.
      #
      class UnaffectedGem < Result

        # The locked gem instance that is not affected.
        #
        # @return [LockedGem]
        attr_reader :gem

        # The advisory whose scope excludes the locked gem instance.
        #
        # @return [Advisory]
        attr_reader :advisory

        # The reason the instance is not affected.
        #
        # @return [Symbol] `:version`, `:platform`, or `:source`.
        attr_reader :reason

        #
        # Initializes the unaffected gem result.
        #
        # @param [LockedGem] gem
        # @param [Advisory] advisory
        # @param [Symbol] reason
        #
        def initialize(gem,advisory,reason)
          @gem      = gem
          @advisory = advisory
          @reason   = reason
        end

        #
        # Compares the unaffected gem to another result.
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
            type:     :unaffected_gem,
            gem:      @gem.to_h,
            advisory: @advisory.to_h,
            reason:   @reason
          }
        end

      end
    end
  end
end
