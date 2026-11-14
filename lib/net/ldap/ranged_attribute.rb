# -*- ruby encoding: utf-8 -*-
##
# The outcome of reading one attribute whose values may have been split by
# an Active Directory server into numbered ranges (for example,
# <tt>member;range=0-1499</tt>).
#
# A result is only #complete? when the reader has seen a contiguous set of
# ranges starting at zero and ending with a terminal range (or a single
# un-ranged response). Callers must not use values from an incomplete read
# as an authorization snapshot.
class Net::LDAP::RangedAttributeResult
  ##
  # The distinguished name whose attribute was read.
  attr_reader :dn

  ##
  # The attribute name that was read, such as <tt>"member"</tt>.
  attr_reader :attribute

  ##
  # A Symbol explaining the outcome. +:ok+ means the read completed. Other
  # values mean the read was aborted:
  #
  # :no_response :: the block returned nil before any page
  # :missing_terminal :: the read ended after a numeric range without a
  #                      terminal <tt>*</tt> range, or the attribute
  #                      disappeared before a terminal range
  # :overlap :: a page started before the next expected offset
  # :gap :: a page started after the next expected offset
  # :invalid_range :: the server returned malformed or ambiguous range syntax
  # :short_range :: a page contained fewer values than its numeric range spans
  # :no_progress :: a page's range did not advance the offset
  # :object_changed :: the DN, objectGUID or uSNChanged changed mid-read
  # :unverified_object :: the configured identity/version attribute was
  #                       missing or disappeared mid-read
  # :not_found :: the object did not exist on the first page
  # :search_failed :: the server returned a non-success result code
  # :read_error :: the caller's block raised, for example a transport error
  # :page_limit :: +max_pages+ was reached
  # :missing_value :: the attribute was absent on the only page and
  #                   +treat_missing_as_empty+ was false
  attr_reader :reason

  ##
  # The server responses that were consumed, in order.
  attr_reader :pages

  ##
  # The exception that aborted a +:read_error+ or +:invalid_range+ read,
  # if any.
  attr_reader :error

  ##
  # The first page's object identity value (normally objectGUID). This is
  # the value that later pages were checked against.
  attr_reader :object_guid

  ##
  # The first page's object version value (normally uSNChanged). This is the
  # value that later pages were checked against.
  attr_reader :object_version

  def initialize(dn:, attribute:, reason:, complete:, values:, pages:, error:,
                 object_guid:, object_version:, object_verified:,
                 version_stable:, retryable:, snapshot_safe:)
    @dn              = dn
    @attribute       = attribute
    @reason          = reason
    @complete        = complete
    @values          = values.uniq.freeze
    @pages           = pages.freeze
    @error           = error
    @object_guid     = object_guid
    @object_version  = object_version
    @object_verified = object_verified
    @version_stable  = version_stable
    @retryable       = retryable
    @snapshot_safe   = snapshot_safe
  end

  ##
  # True only when every value was read and the range chain proved contiguous.
  def complete?
    @complete
  end

  ##
  # True when the read was aborted or the range chain could not be proven
  # complete.
  def incomplete?
    !complete?
  end

  ##
  # True only for a completed read with no values. An incomplete read always
  # returns false here, even when no values have been received yet, because
  # "not finished" is not the same as "empty".
  def empty?
    complete? && @values.empty?
  end

  ##
  # The complete, deduplicated set of values. Raises
  # Net::LDAP::IncompleteAttributeError rather than returning a partial set.
  def values
    raise Net::LDAP::IncompleteAttributeError, self unless complete?

    @values
  end
  alias_method :to_a, :values

  ##
  # Values received so far, including values from ranges that were later
  # rejected. Intended for diagnostics and logging only, never as an
  # authorization snapshot.
  def partial_values
    @values
  end

  ##
  # The complete values when it is safe to atomically replace the existing
  # permission snapshot, otherwise nil. A complete empty set returns an
  # empty Array, which is distinguishable from nil ("not safe to replace").
  def snapshot
    replaceable? ? @values : nil
  end

  ##
  # True when the caller may atomically replace the existing permission
  # snapshot with #values. This requires a complete, contiguous read plus
  # either a verified stable object identity or a single un-ranged response.
  def replaceable?
    @snapshot_safe
  end
  alias_method :safe_to_replace_snapshot?, :replaceable?

  ##
  # True when a fresh read from range zero is safe to attempt. This does not
  # promise that the retry will succeed, and it does not permit resuming
  # from the last offset: the object may have changed since the aborted
  # read.
  def retryable?
    @retryable
  end
  alias_method :retry_from_zero?, :retryable?

  ##
  # True when the object identity was present and stayed the same for every
  # page.
  def object_verified?
    @object_verified
  end

  ##
  # True when the object version was present and stayed the same for every
  # page. This is false when the server did not expose a version attribute.
  def version_stable?
    @version_stable
  end

  ##
  # The number of server responses consumed. Useful for logging and for
  # bounding reads with the +max_pages+ option.
  def page_count
    @pages.length
  end

  ##
  # A Hash representation suitable for logging and diagnostics.
  def to_h
    {
      dn:              dn,
      attribute:       attribute,
      complete:        complete?,
      empty:           empty?,
      reason:          reason,
      values:          complete? ? @values : nil,
      partial_values:  @values,
      page_count:      page_count,
      object_verified: object_verified?,
      version_stable:  version_stable?,
      retryable:       retryable?,
      replaceable:     replaceable?,
    }
  end
end

##
# Reads an LDAP attribute that Active Directory may return in numbered
# ranges. This is not RFC 2696 paged results: the ranges describe slices of
# one attribute on one object, and the server ends the sequence with an
# upper bound of <tt>*</tt>, for example <tt>member;range=1500-*</tt>.
#
# The reader asks for <tt>attribute;range=N-*</tt> (or an explicit
# <tt>N-M</tt> when +page_size+ is supplied) and validates each response:
#
# * the first page must start at zero;
# * every later page must start exactly one past the previous numeric end;
# * a page that starts earlier is an overlap and aborts the read;
# * a page that starts later is a gap and aborts the read;
# * a numeric end is never treated as completion; only <tt>*</tt> terminates
#   the sequence;
# * every page must describe the requested DN and, when configured, the
#   same object identity and version as the first page;
# * a completed multi-page read without a stable object identity is
#   reported as complete but is not considered replaceable evidence;
# * the read stops after +max_pages+ responses instead of looping forever.
#
# An aborted read is retryable from range zero, but the partial offsets must
# not be resumed: the object may have changed in the meantime.
#
# The block passed to #read receives the next offset and the number of
# pages already consumed, and must return a Page or nil. This makes the
# state machine easy to drive with an in-memory response sequence:
#
#   pages = [
#     page(range_start: 0, range_end: 1, values: %w(a b)),
#     page(range_start: 2, terminal: true, values: %w(c)),
#   ]
#   result = reader.read { |_offset, _count| pages.shift }
#
# Net::LDAP#read_ranged_attribute builds these pages from real searches
# while always using the same base DN.
class Net::LDAP::RangedAttributeReader
  ##
  # One server response for the requested attribute.
  #
  # +range_start+ and +range_end+ are nil for an un-ranged response, and
  # +range_end+ is nil for a terminal <tt>N-*</tt> response.
  Page = Struct.new(
    :entry_found,
    :dn,
    :attribute_present,
    :plain,
    :range_start,
    :range_end,
    :terminal,
    :values,
    :object_guid,
    :object_version,
    :result_code,
    :error,
    keyword_init: true,
  )

  ##
  # A parsed attribute description such as <tt>member;range=0-1499</tt>.
  AttributeDescription = Struct.new(
    :base,
    :ranged,
    :range_start,
    :range_end,
    :terminal,
    :invalid,
    keyword_init: true,
  )

  DEFAULT_MAX_PAGES = 1000

  attr_reader :dn, :attribute, :identity_attribute, :version_attribute,
              :max_pages

  ##
  # Creates a reader bound to one DN and one attribute. +require_identity+
  # defaults to true so that an authorization read must expose objectGUID
  # (or the configured identity attribute) and keep it stable across pages.
  # +require_version+ likewise requires the configured version attribute
  # (normally uSNChanged) unless explicitly disabled.
  def initialize(dn:, attribute: "member", identity_attribute: "objectGUID",
                 version_attribute: "uSNChanged", require_identity: true,
                 require_version: true, max_pages: DEFAULT_MAX_PAGES,
                 allow_unranged: true, treat_missing_as_empty: true,
                 validate_page_size: true)
    if dn.nil? || dn.to_s.empty?
      raise ArgumentError, "attribute range read requires :dn"
    end
    if attribute.nil? || attribute.to_s.empty? || attribute.to_s.include?(";")
      raise ArgumentError, "attribute must be a plain attribute name"
    end

    @dn                     = dn.to_s
    @attribute              = attribute.to_s
    @identity_attribute     = identity_attribute && identity_attribute.to_s
    @version_attribute      = version_attribute && version_attribute.to_s
    @require_identity       = require_identity
    @require_version        = require_version
    @max_pages              = Integer(max_pages)
    @allow_unranged         = allow_unranged
    @treat_missing_as_empty = treat_missing_as_empty
    @validate_page_size     = validate_page_size

    raise ArgumentError, "max_pages must be positive" unless @max_pages > 0
  end

  ##
  # Runs the read. Yields +offset+ (the expected first value index) and the
  # number of pages already consumed; the block must return a Page or nil.
  # Returns a Net::LDAP::RangedAttributeResult.
  def read
    pages          = []
    values         = []
    offset         = 0
    first_page     = true
    object_guid    = nil
    object_version = nil
    track_identity = false
    track_version  = false
    identity_ok    = false
    version_ok     = false

    loop do
      if pages.length >= max_pages
        return build_result(:page_limit, false, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, false)
      end

      page = begin
        yield(offset, pages.length)
      rescue StandardError => e
        return build_result(:read_error, false, values, pages, e,
                            object_guid, object_version, identity_ok,
                            version_ok, true)
      end

      if page.nil?
        reason = pages.empty? ? :no_response : :missing_terminal
        return build_result(reason, false, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, true)
      end

      pages << page

      if page.error
        reason = page.error.is_a?(Net::LDAP::InvalidAttributeRangeError) ? :invalid_range : :read_error
        return build_result(reason, false, values, pages, page.error,
                            object_guid, object_version, identity_ok,
                            version_ok, true)
      end

      unless page.result_code.nil? || page.result_code == Net::LDAP::ResultCodeSuccess
        if page.result_code == Net::LDAP::ResultCodeNoSuchObject
          reason = first_page ? :not_found : :object_changed
          return build_result(reason, false, values, pages, nil,
                              object_guid, object_version, identity_ok,
                              version_ok, !first_page)
        else
          return build_result(:search_failed, false, values, pages, nil,
                              object_guid, object_version, identity_ok,
                              version_ok, true)
        end
      end

      unless page.entry_found
        reason = first_page ? :not_found : :object_changed
        return build_result(reason, false, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, reason == :object_changed)
      end

      unless same_dn?(page.dn, dn)
        return build_result(:object_changed, false, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, true)
      end

      if first_page
        object_guid    = page.object_guid
        object_version = page.object_version
        track_identity = !blank?(object_guid)
        track_version  = !blank?(object_version)
        identity_ok    = track_identity
        version_ok     = track_version

        if (@require_identity && !track_identity) ||
           (@require_version && !track_version)
          return build_result(:unverified_object, false, values, pages, nil,
                              object_guid, object_version, identity_ok,
                              version_ok, false)
        end
      else
        if blank?(page.object_guid)
          if track_identity
            return build_result(:unverified_object, false, values, pages, nil,
                                object_guid, object_version, false,
                                version_ok, true)
          end
        elsif track_identity
          if page.object_guid != object_guid
            return build_result(:object_changed, false, values, pages, nil,
                                object_guid, object_version, false,
                                version_ok, true)
          end
        else
          # Identity first appeared after a page without it. Use it for the
          # remaining pages, but the read remains unverified as a whole.
          object_guid    = page.object_guid
          track_identity = true
        end

        if blank?(page.object_version)
          if track_version
            return build_result(:unverified_object, false, values, pages, nil,
                                object_guid, object_version, identity_ok,
                                false, true)
          end
        elsif track_version
          if page.object_version != object_version
            return build_result(:object_changed, false, values, pages, nil,
                                object_guid, object_version, identity_ok,
                                false, true)
          end
        else
          object_version = page.object_version
          track_version  = true
        end
      end

      if !page.attribute_present
        if first_page
          if @treat_missing_as_empty
            return build_result(:ok, true, values, pages, nil,
                                object_guid, object_version, identity_ok,
                                version_ok, false)
          else
            return build_result(:missing_value, false, values, pages, nil,
                                object_guid, object_version, identity_ok,
                                version_ok, true)
          end
        else
          return build_result(:missing_terminal, false, values, pages, nil,
                              object_guid, object_version, identity_ok,
                              version_ok, true)
        end
      end

      if page.plain
        unless first_page && @allow_unranged
          return build_result(:invalid_range, false, values, pages, nil,
                              object_guid, object_version, identity_ok,
                              version_ok, true)
        end

        values.concat(Array(page.values))
        return build_result(:ok, true, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, false)
      end

      if page.range_start.nil?
        return build_result(:invalid_range, false, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, true)
      elsif page.range_start < offset
        return build_result(:overlap, false, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, true)
      elsif page.range_start > offset
        return build_result(:gap, false, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, true)
      end

      if page.range_end && page.range_end < page.range_start
        return build_result(:invalid_range, false, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, true)
      end

      # A page cannot legitimately carry duplicate values for one range;
      # duplicates would make the span check pass with too few distinct
      # members.
      if @validate_page_size && page.range_end &&
         (Array(page.values).length != (page.range_end - page.range_start + 1) ||
          Array(page.values).uniq.length != Array(page.values).length)
        return build_result(:short_range, false, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, true)
      end

      values.concat(Array(page.values))

      if page.terminal
        return build_result(:ok, true, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, false)
      end

      if page.range_end.nil?
        return build_result(:invalid_range, false, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, true)
      end

      next_offset = page.range_end + 1
      if next_offset <= page.range_start
        return build_result(:no_progress, false, values, pages, nil,
                            object_guid, object_version, identity_ok,
                            version_ok, true)
      end

      offset     = next_offset
      first_page = false
    end
  end

  class << self
    ##
    # Parses an attribute description into its base name and optional
    # <tt>range=N-M</tt> or <tt>range=N-*</tt> option. Returns nil when the
    # description has no base name. Unknown range syntax is marked invalid.
    def parse_attribute_description(description)
      parts = description.to_s.split(";")
      base  = parts.shift
      return nil if base.nil? || base.empty?

      ranged     = false
      invalid    = false
      range_start = nil
      range_end   = nil
      terminal    = false

      parts.each do |option|
        if option =~ /\Arange=(\d+)-(\d+|\*)\z/i
          if ranged
            invalid = true
          else
            ranged     = true
            range_start = Regexp.last_match(1).to_i
            terminal    = (Regexp.last_match(2) == "*")
            range_end   = terminal ? nil : Regexp.last_match(2).to_i
          end
        elsif option =~ /\Arange=/i
          ranged  = true
          invalid = true
        end
      end

      AttributeDescription.new(
        base:        base,
        ranged:      ranged,
        range_start: range_start,
        range_end:   range_end,
        terminal:    terminal,
        invalid:     invalid,
      )
    end

    ##
    # Builds a Page from a Net::LDAP::Entry returned by a base-scope search.
    # The entry may contain a plain attribute, one ranged attribute, or no
    # attribute at all. More than one matching description is rejected as
    # ambiguous.
    def page_from_entry(entry, attribute:, identity_attribute: nil,
                        version_attribute: nil)
      page = Page.new(
        entry_found:       !entry.nil?,
        values:            [],
        result_code:       Net::LDAP::ResultCodeSuccess,
        attribute_present: false,
        plain:             false,
        terminal:          false,
      )
      return page unless entry

      page.dn             = entry.dn
      page.object_guid    = first_value(entry, identity_attribute)
      page.object_version = first_value(entry, version_attribute)

      matches        = []
      foreign_ranged = false

      entry.attribute_names.each do |name|
        next if name == :dn

        description = parse_attribute_description(name)
        next unless description

        if description.base.casecmp?(attribute.to_s)
          matches << [name, description]
        elsif description.ranged
          foreign_ranged = true
        end
      end

      if foreign_ranged
        page.error = Net::LDAP::InvalidAttributeRangeError.new(
          "server returned a range for an attribute other than #{attribute.inspect}",
        )
        return page
      end

      if matches.empty?
        page.attribute_present = false
        return page
      end

      if matches.length > 1
        page.error = Net::LDAP::InvalidAttributeRangeError.new(
          "server returned multiple descriptions for #{attribute.inspect}",
        )
        return page
      end

      name, description = matches.first

      if description.invalid
        page.error = Net::LDAP::InvalidAttributeRangeError.new(
          "server returned an invalid range for #{name}",
        )
        return page
      end

      page.attribute_present = true
      page.values            = entry[name].dup
      page.plain             = !description.ranged
      page.range_start       = description.range_start
      page.range_end         = description.range_end
      page.terminal          = description.terminal

      page
    end

    private

    def first_value(entry, name)
      return nil if name.nil? || name.empty?

      entry[name].first
    end
  end

  private

  def build_result(reason, complete, values, pages, error, object_guid,
                   object_version, object_verified, version_stable, retryable)
    # A single complete response describes one object at one point in time,
    # so the DN check is sufficient. A multi-page ranged read needs the
    # identity attribute to prove all slices came from the same object.
    identity_sufficient = object_verified || pages.length <= 1

    snapshot_safe = complete && identity_sufficient &&
                    (!@require_version || version_stable)

    Net::LDAP::RangedAttributeResult.new(
      dn:              dn,
      attribute:       attribute,
      reason:          reason,
      complete:        complete,
      values:          values,
      pages:           pages,
      error:           error,
      object_guid:     object_guid,
      object_version:  object_version,
      object_verified: object_verified,
      version_stable:  version_stable,
      retryable:       retryable,
      snapshot_safe:   snapshot_safe,
    )
  end

  def blank?(value)
    value.nil? || value.to_s.empty?
  end

  def same_dn?(actual, expected)
    return false if actual.nil?

    normalize_dn(actual) == normalize_dn(expected)
  end

  def normalize_dn(value)
    value.to_s.split(/(?<!\\),/).map do |rdn|
      type, val = rdn.strip.split(/(?<!\\)=/, 2)
      if val.nil?
        rdn.strip
      else
        "#{type.strip.downcase}=#{val.sub(/\A +/, "")}"
      end
    end.join(",")
  end
end
