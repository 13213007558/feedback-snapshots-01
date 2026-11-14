# frozen_string_literal: true

require "set"
require_relative "security"

module REXML
  # Per-read resource ledger for general entity expansion.
  #
  # A single XML document is typically read more than once: it may be
  # audited, validated and then consumed by business code, and each of
  # those passes may itself touch several text nodes and attributes.
  # Entity expansion cost must be bounded by what a single read actually
  # expands, not by how many times the document happens to be visited.
  #
  # A ledger is created for one read operation, shared by every nested
  # expansion that read triggers, and discarded when the read finishes. It
  # accumulates:
  #
  # - the number of named general entity expansions, checked against
  #   +entity_expansion_limit+; and
  # - the bytes produced by each expansion scan, checked against
  #   +entity_expansion_text_limit+.
  #
  # Reads that return a previously cached value never reach a ledger, so a
  # cache hit is never charged. A read that exceeds a budget raises before
  # it can publish any partial result, so a failed read cannot leave paid
  # work behind for the next read to reuse for free; the next read simply
  # starts from a fresh ledger and fails again on its own cost.
  #
  # Every Document owns its own limits and mints its own ledgers, so the
  # expansion cost of one document is never charged against another.
  class EntityExpansionLedger
    # One level of value resolution: either the outermost read of a text
    # node or attribute, or the resolution of a single entity's value.
    class Scan
      # @return [Boolean] whether repeats of one entity inside this scan's
      #   value are billed once (true only for the outermost read scan)
      attr_reader :dedup_own

      # @return [Set] entities billed by enclosing dedup scans, inherited
      #   read-only so a nested value still bills their first appearance
      attr_reader :inherited

      # @return [Symbol, nil] the entity whose value this scan resolves; it
      #   is never billed by its own value
      attr_reader :parent_name

      # @return [Set] entities already billed within this scan itself
      attr_reader :billed

      # @return [Integer] bytes produced within this scan
      attr_accessor :bytes

      def initialize(dedup_own, inherited, parent_name)
        @dedup_own = dedup_own
        @inherited = inherited
        @parent_name = parent_name
        @billed = Set.new
        @bytes = 0
      end
    end

    # @return [Integer] number of named general entity expansions charged
    attr_reader :expansion_count

    # @return [Integer] bytes produced by the outermost read scan
    attr_reader :expanded_byte_count

    # @return [Integer] maximum number of expansions allowed for one read
    attr_reader :expansion_limit

    # @return [Integer] maximum expanded bytes allowed for one scan
    attr_reader :text_limit

    # Names of the entities currently being expanded on this read's call
    # stack. A name that reappears denotes a circular entity reference.
    # @return [Set]
    attr_reader :expanding

    def initialize(expansion_limit: Security.entity_expansion_limit,
                   text_limit: Security.entity_expansion_text_limit)
      @expansion_limit = expansion_limit
      @text_limit = text_limit
      @expansion_count = 0
      @expanded_byte_count = 0
      # Active call stack, used solely for cycle detection.
      @expanding = Set.new
      # Stack of value-resolution scans; the outermost read is the base.
      @scans = []
    end

    # Opens the outermost read scan. Repeats of one entity inside the single
    # read value are billed once.
    def begin_read_scan!
      @scans << Scan.new(true, Set.new, nil)
    end

    # Closes the outermost read scan and remembers the bytes it produced.
    def end_read_scan!
      @expanded_byte_count = current_scan.bytes
      @scans.pop
    end

    # Opens the scan that resolves one entity's value. Nested scans count
    # every fresh reference (so exponential fan-out keeps consuming budget)
    # while inheriting the enclosing dedup scan's already-paid entities.
    def begin_entity_scan!(name)
      enclosing = current_scan
      inherited = enclosing.dedup_own ? enclosing.inherited.dup.merge(enclosing.billed) : enclosing.inherited.dup
      @scans << Scan.new(false, inherited, name)
    end

    # Restores the enclosing scan after an entity value resolves.
    def end_entity_scan!
      @scans.pop
    end

    # Runs one read operation under a top-level scan context. The block
    # performs the lazy expansion; whatever it raises still tears the scan
    # down, leaving no partial state for a later read.
    def read
      begin_read_scan!
      begin
        yield
      ensure
        end_read_scan!
      end
    end

    # Charges one named general entity expansion against this read.
    #
    # On the outermost scan the first occurrence of an entity in the value
    # is billed and repeats are free. On a nested scan every fresh
    # reference is billed; an entity inherited from the enclosing dedup
    # scan is still billed once on its first appearance here and only
    # further repeats in this value are free. The entity whose value is
    # being resolved is never billed by its own value.
    #
    # Returns true when a charge was made, false when deduplicated.
    # Raises RuntimeError when the expansion budget is exhausted.
    def charge_expansion!(name)
      scan = current_scan
      return false if scan.parent_name == name

      if scan.dedup_own
        return false if scan.billed.include?(name)
      elsif scan.inherited.include?(name)
        return false if scan.billed.include?(name)
      end

      @expansion_count += 1
      if @expansion_count > @expansion_limit
        raise "number of entity expansions exceeded, processing aborted."
      end
      scan.billed.add(name)
      true
    end

    # Charges the bytes produced within the currently resolving scan.
    #
    # Each scan accumulates its own output against the same text limit, so a
    # deep chain is rejected as soon as one level overshoots. The outermost
    # read's total is exposed through #expanded_byte_count on success.
    #
    # Raises RuntimeError when the expanded text budget is exhausted.
    def charge_text!(bytesize)
      scan = current_scan
      if scan.bytes + bytesize > @text_limit
        raise "entity expansion has grown too large"
      end
      scan.bytes += bytesize
    end

    private

    # Returns the active scan, lazily opening an implicit outermost read
    # scan for callers that drive Text.unnormalize directly without going
    # through a Document-backed Text#value/Attribute#value read.
    def current_scan
      @scans.last || begin
        scan = Scan.new(true, Set.new, nil)
        @scans << scan
        scan
      end
    end
  end
end
