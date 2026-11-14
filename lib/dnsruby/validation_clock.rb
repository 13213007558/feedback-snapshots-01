module Dnsruby
  # A single clock for validation so exported evidence can be replayed at the
  # time the conclusion was reached. Outside replay it simply reads Time.now,
  # which keeps existing Time stubs working.
  module ValidationClock # :nodoc: all
    KEY = :dnsruby_validation_time

    def self.now
      fixed = Thread.current[KEY]
      fixed ? Time.at(fixed) : Time.now
    end

    def self.now_i
      now.to_i
    end

    def self.fixed_time
      Thread.current[KEY]
    end

    def self.with_time(time)
      previous = Thread.current[KEY]
      Thread.current[KEY] = time.nil? ? nil : time.to_i
      yield
    ensure
      Thread.current[KEY] = previous
    end
  end
end
