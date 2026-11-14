# frozen_string_literal: true

module Net
  class IMAP < Protocol

    # CopyUIDEvidence builds a <em>read-only</em> forensic evidence report
    # describing how message UIDs in a source mailbox correspond to the UIDs
    # that were assigned in a destination mailbox by a +COPY+, +UID COPY+,
    # +MOVE+, or +UID MOVE+ command, based on the server's +COPYUID+ response
    # code (CopyUIDData).
    #
    # The export is a pure function of the investigator-supplied transcript:
    # it performs no I/O, opens no connections, and never mutates its input.
    # All collections inside the returned Report are frozen.
    #
    # === What the report preserves
    #
    # * the source mailbox name (as recorded by the investigator),
    # * the destination mailbox +UIDVALIDITY+ declared by the server,
    # * both uid-sets exactly as declared, in their original interval order,
    # * the basis for the one-to-one mapping (see Mapping#basis).
    #
    # === What the report refuses to do
    #
    # * The two uid-sets are <em>never</em> sorted, deduplicated, and then
    #   paired by rank.  Pairing is strictly positional, in declared order.
    # * A missing, malformed, or mismatched +COPYUID+ code is reported as a
    #   finding.  An +OK+ result alone never causes a mapping to be
    #   fabricated.
    # * Large ranges are kept as ranges.  A +COPYUID+ code covering billions
    #   of UIDs produces a handful of mapping segments, never an expanded
    #   list of integers.
    #
    # === What the report does not prove
    #
    # The mapping is a <em>server-declared</em> correspondence that has only
    # been validated for local structural consistency.  It is not evidence
    # that the message contents on both sides are identical.
    #
    # === Example
    #
    #   report = Net::IMAP::CopyUIDEvidence.export(
    #     source_mailbox: "Archive/2026",
    #     response: "A142 OK [COPYUID 38505 3955:3960,3962 4482:4487,4489] Done"
    #   )
    #   report.clean?                # => true
    #   report.mapping.message_count # => 7
    #   report.to_h                  # => JSON-friendly evidence export
    module CopyUIDEvidence

      # The largest valid uniqueid / UIDVALIDITY value (nz-number, 32 bit).
      UINT32_MAX = 2**32 - 1

      # Human-readable statement of the one-to-one mapping basis, included
      # in every exported mapping.
      MAPPING_BASIS =
        "Positional correspondence of the two server-declared uid-sets, " \
        "taken in their original declared order. Each declared entry " \
        "enumerates its UIDs from the lower to the upper bound (the " \
        "Net::IMAP::SequenceSet#each_ordered_number convention, matching " \
        "CopyUIDData#each_uid_pair). The sets are never sorted, " \
        "deduplicated, or paired by value."

      # Included in every export: the limits of what this evidence shows.
      LIMITATIONS =
        "This report records a server-declared UID correspondence plus " \
        "local structural validation only. Fields under :server_declared " \
        "restate what the server sent; fields under :local_validation and " \
        ":mapping are computed locally from those declarations. This is " \
        "not proof that the source and destination message contents are " \
        "identical."

      # A single declared uid-set entry, preserving its original text and
      # orientation.  +first+ and +last+ are the declared bounds; for a
      # single-number entry they are equal.
      Entry = Data.define(:token, :first, :last) do
        # Lower bound of the entry, regardless of declared orientation.
        def min = first < last ? first : last

        # Upper bound of the entry, regardless of declared orientation.
        def max = first < last ? last : first

        # Number of UIDs covered by this entry.
        def size = max - min + 1

        # Whether the entry was declared with its bounds reversed (9:5).
        def reversed? = first > last
      end

      # One aligned pair of UID intervals in the mapping.  Both ranges
      # ascend and cover the same number of UIDs; the n-th UID of +source+
      # corresponds to the n-th UID of +assigned+.
      Segment = Data.define(:source, :assigned) do
        # Number of messages mapped by this segment.
        def count = source.size

        def to_h = {
          source:   { first: source.first,   last: source.last   },
          assigned: { first: assigned.first, last: assigned.last },
          count:    count,
        }
      end

      # The one-to-one UID mapping, expressed as an ordered list of
      # interval Segments.  Memory use is proportional to the number of
      # segments, not to the number of mapped messages.
      Mapping = Data.define(:segments, :basis) do
        # Total number of mapped messages (computed arithmetically).
        def message_count = segments.sum(&:count)

        # Yields each +(source_uid, assigned_uid)+ pair in mapping order.
        # Returns a lazy-friendly enumerator when no block is given.
        #
        # <em>*Warning:*</em> like CopyUIDData#uid_mapping, fully
        # materializing this enumerator (to_a, to_h) may consume _much_
        # more memory than the segments used to build it.  Check
        # #message_count before expanding a mapping from an untrusted
        # server.
        def each_pair
          return enum_for(__method__) unless block_given?
          segments.each do |segment|
            source_uid   = segment.source.first
            assigned_uid = segment.assigned.first
            segment.count.times do
              yield source_uid, assigned_uid
              source_uid   += 1
              assigned_uid += 1
            end
          end
        end

        def to_h = {
          basis:         basis,
          message_count: message_count,
          segments:      segments.map(&:to_h),
        }
      end

      # A single anomaly or notable observation, reported separately from
      # all other findings.  +category+ is one of :missing_copyuid,
      # :malformed_copyuid, :reversed_range, :overlapping_ranges,
      # :duplicate_uids, or :unequal_counts.  +side+ is :source,
      # :assigned, or nil (when the finding concerns both sides or the
      # response as a whole).
      Finding = Data.define(:category, :side, :detail) do
        def to_h = { category: category, side: side, detail: detail }
      end

      # The read-only evidence report.  See CopyUIDEvidence for an overview
      # and #to_h for the serializable export.
      Report = Data.define(
        :source_mailbox,
        :tagged_status,
        :uidvalidity,
        :source_uid_set,
        :assigned_uid_set,
        :source_entries,
        :assigned_entries,
        :source_count,
        :assigned_count,
        :source_distinct_count,
        :assigned_distinct_count,
        :findings,
        :mapping,
        :copy_uid_data,
      ) do
        # True when no findings were recorded.
        def clean? = findings.empty?

        # True when a one-to-one mapping could be established locally.
        def mapping_established? = !mapping.nil?

        # All findings with the given category.
        def findings_by(category) = findings.select { _1.category == category }

        # JSON-friendly evidence export.  Keys under :server_declared
        # restate what the server sent; keys under :local_validation and
        # :mapping are computed locally.  See LIMITATIONS.
        def to_h = {
          evidence_type: "net-imap/copyuid-correspondence",
          source_mailbox: source_mailbox,
          server_declared: {
            tagged_status:    tagged_status,
            uidvalidity:      uidvalidity,
            source_uid_set:   source_uid_set,
            assigned_uid_set: assigned_uid_set,
          },
          local_validation: {
            source_entries:           source_entries,
            assigned_entries:         assigned_entries,
            source_count:             source_count,
            assigned_count:           assigned_count,
            source_distinct_count:    source_distinct_count,
            assigned_distinct_count:  assigned_distinct_count,
          },
          findings:   findings.map(&:to_h),
          mapping:    mapping&.to_h,
          limitations: LIMITATIONS,
        }
      end

      TAGGED_STATUS_RE = /\A(?:\*|\S+)\s+(OK|NO|BAD)\b/i
      COPYUID_CODE_RE  = /\[COPYUID[ \t]+(\S+)[ \t]+(\S+)[ \t]+(\S+)[ \t]*\]/i
      COPYUID_ANY_RE   = /\[COPYUID([^\]]*)\]/i
      NZ_NUMBER_RE     = /\A[1-9]\d*\z/
      ENTRY_RE         = /\A(\d+)(?::(\d+))?\z/

      module_function

      # :call-seq:
      #   export(source_mailbox:, response:) -> Report
      #   export(source_mailbox:, copyuid:)  -> Report
      #
      # Builds a read-only evidence Report.  Exactly one of +response+ (a
      # raw server response line, tagged or untagged, containing or
      # expected to contain a +COPYUID+ response code) or +copyuid+ (an
      # already parsed CopyUIDData) must be given.
      #
      # +source_mailbox+ is the investigator-recorded name of the mailbox
      # the messages were copied or moved from.
      def export(source_mailbox:, response: nil, copyuid: nil)
        if response.nil? == copyuid.nil?
          raise ArgumentError,
                "exactly one of response: or copyuid: must be given"
        end
        if copyuid
          unless copyuid.is_a?(CopyUIDData)
            raise ArgumentError, "copyuid must be a Net::IMAP::CopyUIDData"
          end
          tagged_status = nil
          code = [copyuid.uidvalidity.to_s,
                  copyuid.source_uids.string,
                  copyuid.assigned_uids.string]
        else
          tagged_status = parse_tagged_status(response)
          code = extract_copyuid_code(response)
        end

        if code == :missing
          findings = [Finding.new(
            category: :missing_copyuid, side: nil,
            detail: { tagged_status: tagged_status }.freeze
          ).freeze]
          return build_report(source_mailbox, tagged_status,
                              nil, nil, nil, nil, nil, findings, nil, nil)
        end

        malformed = []
        if code == :malformed
          malformed << "COPYUID response code is not " \
                       "'COPYUID uidvalidity uid-set uid-set'"
          uidvalidity_text = source_text = assigned_text = nil
        else
          uidvalidity_text, source_text, assigned_text = code
        end

        uidvalidity = uidvalidity_text && parse_nz_number(uidvalidity_text)
        if uidvalidity_text && uidvalidity.nil?
          malformed << "uidvalidity #{uidvalidity_text.inspect} " \
                       "is not a valid nz-number"
        end
        source_entries   = source_text   && parse_uid_set(source_text)
        assigned_entries = assigned_text && parse_uid_set(assigned_text)
        if source_text && source_entries.nil?
          malformed << "source uid-set #{source_text.inspect} is malformed"
        end
        if assigned_text && assigned_entries.nil?
          malformed << "assigned uid-set #{assigned_text.inspect} is malformed"
        end

        unless malformed.empty?
          findings = [Finding.new(
            category: :malformed_copyuid, side: nil,
            detail: { reasons: malformed.freeze }.freeze
          ).freeze]
          return build_report(source_mailbox, tagged_status,
                              uidvalidity, source_text, assigned_text,
                              nil, nil, findings, nil, nil)
        end

        analyze(source_mailbox, tagged_status, uidvalidity,
                source_text, assigned_text, source_entries, assigned_entries)
      end

      # Parses the declared uid-set string into Entries, preserving the
      # declared order and orientation.  Returns nil when malformed.
      def parse_uid_set(string)
        tokens = string.split(",", -1)
        return nil if tokens.empty? || tokens.any?(&:empty?)
        entries = []
        tokens.each do |token|
          match = ENTRY_RE.match(token) or return nil
          first = parse_nz_number(match[1]) or return nil
          last  = match[2] ? (parse_nz_number(match[2]) or return nil) : first
          entries << Entry.new(token: token, first: first, last: last)
        end
        entries
      end

      def parse_nz_number(string)
        return nil unless NZ_NUMBER_RE.match?(string)
        number = Integer(string)
        number <= UINT32_MAX ? number : nil
      end

      def parse_tagged_status(response)
        match = TAGGED_STATUS_RE.match(response)
        match && match[1].upcase
      end

      # Returns [uidvalidity, source, assigned] strings, :missing when no
      # COPYUID code is present, or :malformed when one is present but does
      # not have exactly three arguments.
      def extract_copyuid_code(response)
        if (match = COPYUID_CODE_RE.match(response))
          [match[1], match[2], match[3]]
        elsif COPYUID_ANY_RE.match?(response)
          :malformed
        else
          :missing
        end
      end

      def analyze(source_mailbox, tagged_status, uidvalidity,
                  source_text, assigned_text, source_entries, assigned_entries)
        findings = []
        findings.concat side_findings(:source,   source_entries)
        findings.concat side_findings(:assigned, assigned_entries)

        source_count   = source_entries.sum(&:size)
        assigned_count = assigned_entries.sum(&:size)
        if source_count != assigned_count
          findings << Finding.new(
            category: :unequal_counts, side: nil,
            detail: { source_count:   source_count,
                      assigned_count: assigned_count }.freeze
          )
        end
        findings.freeze

        mapping = copy_uid_data = nil
        if source_count == assigned_count
          segments = build_segments(source_entries, assigned_entries).freeze
          mapping  = Mapping.new(segments: segments, basis: MAPPING_BASIS)
          copy_uid_data = begin
            CopyUIDData.new(uidvalidity:   uidvalidity,
                            source_uids:   source_text,
                            assigned_uids: assigned_text)
          rescue DataFormatError
            nil
          end
        end

        build_report(source_mailbox, tagged_status, uidvalidity,
                     source_text, assigned_text,
                     source_entries, assigned_entries,
                     findings, mapping, copy_uid_data)
      end

      # Reversed-range, overlapping-range, and duplicate-UID findings for
      # one side of the COPYUID code.  Each category is reported separately.
      def side_findings(side, entries)
        findings = []

        reversed = entries.select(&:reversed?).map(&:token)
        unless reversed.empty?
          findings << Finding.new(category: :reversed_range, side: side,
                                  detail: { entries: reversed.freeze }.freeze)
        end

        pairs = overlapping_pairs(entries)
        unless pairs.empty?
          findings << Finding.new(category: :overlapping_ranges, side: side,
                                  detail: { pairs: pairs.freeze }.freeze)
        end

        total    = entries.sum(&:size)
        distinct = distinct_count(entries)
        if total > distinct
          findings << Finding.new(
            category: :duplicate_uids, side: side,
            detail: { duplicate_occurrences: total - distinct,
                      duplicated_uids:       duplicate_set(entries).string }.freeze
          )
        end

        findings
      end

      # Witness pairs for overlapping entries, detected by a sorted sweep
      # in O(n log n) time with output linear in the entry count.  Each
      # pair names an earlier entry (by interval position) and a later
      # entry whose intervals intersect.
      def overlapping_pairs(entries)
        sorted = entries.sort_by(&:min)
        pairs = []
        highest = sorted.first
        sorted.each_with_index do |entry, i|
          next if i.zero?
          if entry.min <= highest.max
            pairs << [highest.token, entry.token].freeze
          end
          highest = entry if entry.max > highest.max
        end
        pairs
      end

      # Distinct UID count, computed by SequenceSet without expansion.
      def distinct_count(entries)
        SequenceSet[entries.map { |entry| entry.min..entry.max }].count
      end

      # The set of UIDs declared more than once, as a SequenceSet (kept in
      # normalized range form, never expanded).
      def duplicate_set(entries)
        seen = SequenceSet.new
        dups = SequenceSet.new
        entries.each do |entry|
          set = SequenceSet[entry.min..entry.max]
          dups.merge(seen & set)
          seen.merge(set)
        end
        dups
      end

      # Walks both sides' entries in declared order (each entry ascending
      # from its lower bound) and splits them into aligned segments.
      # Runs in O(entry count) time and memory; UIDs are never expanded.
      def build_segments(source_entries, assigned_entries)
        source_runs   = source_entries.map   { |entry| [entry.min, entry.max] }
        assigned_runs = assigned_entries.map { |entry| [entry.min, entry.max] }
        segments = []
        i = j = 0
        source_lo,   source_hi   = source_runs.fetch(0)
        assigned_lo, assigned_hi = assigned_runs.fetch(0)
        loop do
          length = [source_hi - source_lo, assigned_hi - assigned_lo].min + 1
          segments << Segment.new(source:   source_lo..(source_lo + length - 1),
                                  assigned: assigned_lo..(assigned_lo + length - 1))
          source_lo   += length
          assigned_lo += length
          if source_lo > source_hi
            i += 1
            break if i == source_runs.size
            source_lo, source_hi = source_runs[i]
          end
          if assigned_lo > assigned_hi
            j += 1
            break if j == assigned_runs.size
            assigned_lo, assigned_hi = assigned_runs[j]
          end
        end
        segments
      end

      def build_report(source_mailbox, tagged_status, uidvalidity,
                       source_text, assigned_text,
                       source_entries, assigned_entries,
                       findings, mapping, copy_uid_data)
        Report.new(
          source_mailbox:          source_mailbox.freeze,
          tagged_status:           tagged_status,
          uidvalidity:             uidvalidity,
          source_uid_set:          source_text&.freeze,
          assigned_uid_set:        assigned_text&.freeze,
          source_entries:          source_entries&.map(&:token)&.freeze,
          assigned_entries:        assigned_entries&.map(&:token)&.freeze,
          source_count:            source_entries&.sum(&:size),
          assigned_count:          assigned_entries&.sum(&:size),
          source_distinct_count:   source_entries   && distinct_count(source_entries),
          assigned_distinct_count: assigned_entries && distinct_count(assigned_entries),
          findings:                findings,
          mapping:                 mapping,
          copy_uid_data:           copy_uid_data,
        ).freeze
      end

    end

  end
end
