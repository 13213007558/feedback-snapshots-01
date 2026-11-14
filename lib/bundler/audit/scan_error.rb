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

module Bundler
  module Audit
    #
    # Describes a part of the audit which could not be completed.
    #
    # An incomplete audit is not a clean audit. A {ScanError} records which
    # gem/scope was not checked, where the problem came from, and why, so
    # that callers can distinguish "nothing was found" from "the check could
    # not be performed".
    #
    # @since 0.9.4
    #
    class ScanError

      # The classification of the failure.
      #
      # * `:invalid_advisory` - an advisory could not be trusted or parsed.
      # * `:path_escape` - an advisory path fell outside the database.
      # * `:unchecked_gem` - a gem could not be looked up at all.
      # * `:unchecked_source` - a source could not be inspected.
      # * `:unknown` - any other failure.
      #
      # @return [Symbol]
      attr_reader :code

      # The gem, database, or other scope which was not fully checked.
      #
      # @return [String, Symbol, nil]
      attr_reader :scope

      # The advisory or input path involved, when known.
      #
      # @return [String, nil]
      attr_reader :path

      # The human readable explanation.
      #
      # @return [String]
      attr_reader :message

      # The underlying exception, when available.
      #
      # @return [Exception, nil]
      attr_reader :cause

      #
      # Initializes the scan error.
      #
      # @param [String] message
      #
      # @param [Symbol] code
      #
      # @param [String, Symbol, nil] scope
      #
      # @param [String, nil] path
      #
      # @param [Exception, nil] cause
      #
      def initialize(message,code: :unknown,scope: nil,path: nil,cause: nil)
        @message = message
        @code    = code
        @scope   = scope
        @path    = path
        @cause   = cause
      end

      #
      # Converts the scan error into a String.
      #
      # @return [String]
      #
      def to_s
        if @scope && @path
          "[#{@scope}] #{@message} (#{@path})"
        elsif @scope
          "[#{@scope}] #{@message}"
        elsif @path
          "#{@message} (#{@path})"
        else
          @message
        end
      end

      #
      # Converts the scan error into a Hash.
      #
      # @return [Hash{Symbol => Object}]
      #
      def to_h
        {
          code:    @code,
          scope:   @scope,
          path:    @path,
          message: @message
        }
      end

    end
  end
end
