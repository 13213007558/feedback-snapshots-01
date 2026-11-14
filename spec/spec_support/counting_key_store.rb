# frozen_string_literal: true

module SpecSupport
  # In-memory key store standing in for a database. Counts and records every
  # query so tests can prove how often an expensive key finder callback fires
  # and with what arguments. No external service involved.
  class CountingKeyStore
    attr_reader :queries

    def initialize(keys)
      @keys = keys
      @queries = []
    end

    def fetch(kid)
      @queries << kid
      @keys[kid]
    end

    def query_count
      @queries.size
    end
  end
end
