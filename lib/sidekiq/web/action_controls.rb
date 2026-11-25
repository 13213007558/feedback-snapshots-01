# frozen_string_literal: true

require "sidekiq/web/confirmation"

module Sidekiq
  class Web
    ##
    # Confirmation-aware controls for the Retry, Scheduled and Dead listings.
    #
    # Every rendered entry is represented by a signed token which records the
    # source set, the entry key (score + jid), a digest of the stored payload
    # and the actions the entry supports.  A submission only proceeds when the
    # token still matches the entry which is present *now* and the operator is
    # permitted to perform the requested action.
    #
    # Internal API for the Web UI.
    module ActionControls
      SETS = {
        "retry" => %i[retry cancel kill],
        "schedule" => %i[retry cancel],
        "dead" => %i[retry cancel]
      }.freeze

      PERFORMED = "performed"
      COMPLETED = "completed"
      NEEDS_CONFIRMATION = "needs_confirmation"
      FORBIDDEN = "forbidden"

      # Tokens look like "<base64url json>.<hex hmac>".  Anything shaped this
      # way is treated as a confirmation even if its signature is invalid, so
      # a tampered token cannot silently fall back to the legacy key path.
      TOKEN_SHAPE = /\A[A-Za-z0-9_-]+\.[0-9a-f]{64}\z/

      def entry_set_actions(set)
        SETS.fetch(set.to_s)
      end

      def entry_set_class(set)
        case set.to_s
        when "retry" then Sidekiq::RetrySet
        when "schedule" then Sidekiq::ScheduledSet
        when "dead" then Sidekiq::DeadSet
        else
          raise ArgumentError, "Unknown job set #{set.inspect}"
        end
      end

      def action_target(set, entry, action)
        {
          set: set.to_s,
          action: action,
          jid: entry.jid,
          key: entry_key(entry),
          queue: entry.queue,
          klass: entry.display_class,
          score: entry.score
        }
      end

      def action_permitted?(action, target)
        hook = config.authorize_action
        return true unless hook

        !!hook.call(env, action, target)
      end

      def permitted_entry_actions(entry, set)
        entry_set_actions(set).select { |action| action_permitted?(action, action_target(set, entry, action)) }
      end

      # Actions at least one entry in the listing permits.  The server still
      # re-checks every submitted token, so a mixed selection is rejected as a
      # whole rather than partially applied.
      def permitted_actions_for(entries, set)
        entry_set_actions(set).select do |action|
          entries.any? { |entry| action_permitted?(action, action_target(set, entry, action)) }
        end
      end

      def entry_key(entry)
        "#{entry.score}-#{entry.jid}"
      end

      # Token embedded in links, checkboxes and detail forms.
      def job_token(entry, set, actions: nil)
        actions ||= permitted_entry_actions(entry, set)
        Confirmation.issue(
          set: set,
          key: entry_key(entry),
          value: entry.value,
          actions: actions,
          jid: entry.jid
        )
      end

      def perform_entry_actions(set, keys, params)
        action = requested_action(params)
        return {status: :noop} unless action

        keys = Array(keys).compact
        return {status: :noop} if keys.empty?

        prepared = keys.map { |key| prepare_entry_action(set, key, action) }

        # The ledger is consulted before "is this entry still here?": a job
        # which already moved because this action succeeded must report
        # "completed" rather than "the job is gone".
        if prepared.any? { |item| item[:uncertain] }
          return {
            status: :needs_confirmation,
            message: "A previous confirmation of this action did not finish. Reload the list and confirm again; the current job was left untouched."
          }
        end

        pending = prepared.reject { |item| item[:completed] }
        claimed = []

        pending.each do |item|
          next unless item[:nonce]

          case Confirmation.claim(item[:nonce], action)
          when :completed
            item[:completed] = true
          when :uncertain
            claimed.each { |other| Confirmation.release(other[:nonce], action) }
            return {
              status: :needs_confirmation,
              message: "A previous confirmation of this action did not finish. Reload the list and confirm again; the current job was left untouched."
            }
          else
            claimed << item
          end
        end

        performed = 0
        pending.each do |item|
          next if item[:completed]

          begin
            execute_entry_action(item[:entry], set, action)
          rescue => ex
            # The outcome is unknown. Keep the ledger claiming the action so a
            # resubmission reports that re-confirmation is required; reloading
            # the listing issues a new token which can proceed.
            logger.warn("Web UI action #{action} on #{item[:entry].jid} failed: #{ex.class}: #{ex.message}")
            return {
              status: :needs_confirmation,
              message: "The action could not be confirmed as complete. Reload the list to see the current job state; confirm again only if it is still present."
            }
          end
          Confirmation.finish(item[:nonce], action) if item[:nonce]
          performed += 1
        end

        completed = prepared.count { |item| item[:completed] }
        if performed.zero? && completed.positive?
          {status: :completed, message: "This action was already completed. No changes were made."}
        else
          {status: :performed, completed: completed}
        end
      end

      def perform_bulk_action!(set, action)
        # A policy which understands bulk actions answers directly.  Otherwise
        # fall back to checking every entry, so an entry-scoped policy still
        # applies to "retry all"/"delete all" without partially applying.
        target = {set: set.to_s, action: action, bulk: true}
        entries = entry_set_class(set).new.to_a
        if entries.empty?
          halt_notice(403, FORBIDDEN, "You are not permitted to #{action} jobs in this list.") unless action_permitted?(action, target)
          return
        end

        permitted = entries.all? { |entry| action_permitted?(action, action_target(set, entry, action).merge(bulk: true)) }
        unless permitted
          halt_notice(403, FORBIDDEN, "You are not permitted to #{action} jobs in this list.")
        end
      end

      def action_notice(result)
        case result[:status]
        when :completed
          halt_notice(200, COMPLETED, result[:message])
        when :needs_confirmation
          halt_notice(409, NEEDS_CONFIRMATION, result[:message])
        when :forbidden
          halt_notice(403, FORBIDDEN, result[:message])
        end
      end

      def halt_notice(status, state, message)
        body = <<~HTML
          <!doctype html>
          <html lang="en">
          <head><meta charset="utf-8"><title>Sidekiq action</title></head>
          <body class="admin">
            <main id="page"><div class="container">
              <p class="flash" data-action-state="#{h state}">#{h message}</p>
              <p><a href="#{root_path}">Back to Sidekiq</a></p>
            </div></main>
          </body>
          </html>
        HTML
        throw :halt, [status, {"content-type" => "text/html", "x-sidekiq-action-state" => state}, [body]]
      end

      def action_redirect(url, state = PERFORMED)
        location = if (referer = request.referer) && referer.include?("?")
          "#{url}?#{URI(referer).query}"
        else
          url
        end
        location = "#{request.base_url}#{location}" unless location.match?(/:\/\//)
        throw :halt, [302, {"location" => location, "x-sidekiq-action-state" => state}, []]
      end

      private

      def requested_action(params)
        return :retry if params["retry"] || params["add_to_queue"]
        return :cancel if params["delete"]
        return :kill if params["kill"]

        nil
      end

      def prepare_entry_action(set, key, action)
        if (payload = Confirmation.decode(key))
          prepare_token_action(set, action, payload)
        elsif TOKEN_SHAPE.match?(key.to_s)
          # A token-shaped key which fails signature/format validation must not
          # fall through to the legacy score-jid path.
          halt_notice(409, NEEDS_CONFIRMATION, "This confirmation is invalid or has expired. Reload the list and confirm the job again.")
        else
          prepare_legacy_action(set, key)
        end
      end

      def prepare_token_action(set, action, payload)
        unless payload["s"] == set.to_s
          halt_notice(409, NEEDS_CONFIRMATION, "This confirmation belongs to a different list. Reload and confirm again.")
        end

        unless payload["a"].include?(action.to_s)
          halt_notice(403, FORBIDDEN, "You are not permitted to #{action} this job.")
        end

        case Confirmation.state(payload["n"], action)
        when :completed then return {completed: true}
        when :claimed then return {uncertain: true}
        end

        entry = fetch_token_entry(set, payload)
        unless entry
          halt_notice(409, NEEDS_CONFIRMATION, "The job is no longer in this position. Reload the list and confirm the current job.")
        end

        unless entry.jid == payload["j"] &&
            entry_key(entry) == payload["k"] &&
            Confirmation.digest(entry.value) == payload["d"]
          halt_notice(409, NEEDS_CONFIRMATION, "The job changed since this page was read. Reload and confirm again; the current job was left untouched.")
        end

        unless action_permitted?(action, action_target(set, entry, action))
          halt_notice(403, FORBIDDEN, "You are not permitted to #{action} this job.")
        end

        {entry: entry, nonce: payload["n"], completed: false}
      end

      # Without a per-action policy, the historical score-jid keys keep
      # working for compatibility with bookmarks and external tooling.  Once a
      # policy is configured, a token is required so permission and the exact
      # entry can be verified.
      def prepare_legacy_action(set, key)
        if config.authorize_action
          halt_notice(409, NEEDS_CONFIRMATION, "This action requires a fresh confirmation. Reload the list and confirm the job again.")
        end

        entry = entry_set_class(set).new.fetch(*parse_key(key)).first
        {entry: entry, nonce: nil, completed: false}
      end

      def fetch_token_entry(set, payload)
        score, jid = parse_key(payload["k"])
        entry_set_class(set).new.fetch(score, jid).first
      end

      def execute_entry_action(entry, set, action)
        return unless entry

        case action
        when :retry
          set.to_s == "schedule" ? entry.add_to_queue : entry.retry
        when :cancel
          entry.delete
        when :kill
          entry.kill
        else
          raise ArgumentError, "Unknown action #{action.inspect}"
        end
      end
    end
  end
end
