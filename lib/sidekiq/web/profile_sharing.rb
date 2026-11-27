# frozen_string_literal: true

require "sidekiq/api"
require "sidekiq/web/profile_store"

module Sidekiq
  class Web
    ##
    # Decides whether one specific profile record may be viewed or downloaded
    # and, when allowed, performs the upload to the shared store.
    #
    # Every check is made against the record passed in, so revoking a record's
    # approval takes effect immediately for requests that are already in
    # flight. The store is only contacted for records explicitly approved for
    # transfer and only when no viewer token has been cached yet.
    module ProfileSharing
      module_function

      # @return [String, nil] the public viewer URL, or nil if this record may
      #   not be shown in the shared viewer right now.
      def view_url(record, view_url:, store:, now: Time.now)
        # Remote viewing is disabled unless a store and viewer URL are configured.
        return nil if store.nil? || view_url.nil?
        return nil unless record&.viewable?(now: now)

        sid = record.sid
        if sid.to_s.empty?
          # A read-only approval never uploads; it can only reuse a token
          # cached before sharing was revoked or narrowed.
          return nil unless record.transferable?(now: now)

          data = record.data
          return nil unless data

          sid = store.upload(data)
          return nil if sid.to_s.empty?
          record.cache_sid(sid)
        end

        format(view_url, sid)
      end

      # Downloading from this instance is an internal support operation and
      # follows the record's own internal retention, not the share window.
      # An expired share window does not block support access.
      # @return [String, nil]
      def data(record, now: Time.now)
        return nil unless record&.retained?(now: now)
        record.data
      end
    end
  end
end
