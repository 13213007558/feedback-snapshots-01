# frozen_string_literal: true

# Minimal test helper used only by the standalone runner. The real test/helper
# boots Active Job, Railties and Redis, which are absent from the locked local
# bundle. This provides exactly what current_attributes_test.rb references.
require "minitest/autorun"
require "sidekiq"
require "sidekiq/middleware/current_attributes"

NULL_LOGGER = Logger.new(IO::NULL)

def reset!
  cfg = Sidekiq::Config.new
  cfg.logger = NULL_LOGGER
  cfg.logger.level = Logger::WARN
  Sidekiq.instance_variable_set(:@config, cfg)
  cfg
end

module Rails
  # Mirrors the Rails executor/reloader contract used by the test suite:
  # each unit of work starts and ends with a reset CurrentAttributes context.
  class Reloader
    def wrap
      ActiveSupport::CurrentAttributes.clear_all
      result = yield
      ActiveSupport::CurrentAttributes.clear_all
      result
    end
  end

  def self.application
    self
  end

  def self.reloader
    Reloader.new
  end
end
