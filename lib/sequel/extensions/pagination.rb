# frozen-string-literal: true
#
# The pagination extension adds the Sequel::Dataset#paginate and #each_page methods,
# which return paginated (limited and offset) datasets with the following methods
# added that make creating a paginated display easier:
#
# * +page_size+
# * +page_count+
# * +page_range+
# * +current_page+
# * +next_page+
# * +has_next_page?+ (alias +next_page?+)
# * +prev_page+
# * +first_page?+
# * +last_page?+
# * +at_least_pagination?+
# * +pagination_record_count+
# * +current_page_record_count+
# * +current_page_record_range+
#
# By default, pagination does a count query to determine the total number of
# records and the number of pages.  If the caller should not be able to see
# the total number of records in the dataset, use the :at_least option:
#
#   ds.paginate(1, 20, :at_least=>true)
#
# In at-least mode, no count query is issued.  +has_next_page?+ issues a
# navigation query for a single record after the current page, and uses the
# presence of that record as evidence that a next page exists.  +next_page+
# returns the next page number while there is a next page.
# +pagination_record_count+, +page_count+, +page_range+, and
# +current_page_record_count+ return nil, since the total number of records
# is deliberately not disclosed.  +last_page?+ uses +has_next_page?+ in this
# mode.
#
# The navigation query used by +has_next_page?+ is always derived from the
# same dataset as the page query, so it uses the same filters, joins, and
# authorization conditions.  The only difference is that the page query
# returns the current page's records, while the navigation query checks for
# a record after the current page:
#
#   visible = DB[:tickets].where(authorized: true).order(:id)
#   page = visible.paginate(1, 20, :at_least=>true)
#   page.all              # Uses WHERE authorized = true
#   page.has_next_page?   # Uses WHERE authorized = true, LIMIT 1 OFFSET 20
#   visible.count         # Still uses WHERE authorized = true, if needed
#
# Note that +has_next_page?+ issues a navigation query in at-least mode for
# each paginated dataset.  The result is cached for that dataset, so calling
# the method multiple times for the same page only issues one query.  Fetch a
# new paginated dataset to refresh the result.
#
# This is also supported by each_page:
#
#   visible.each_page(20, :at_least=>true){|page| ...}
#
# each_page with the :at_least option yields the first page even if it is
# empty, so callers can distinguish an empty result set from a failure.
#
# If you need the actual total number of records (for example, for an
# internal report), use the default mode without the :at_least option.
#
# This extension uses Object#extend at runtime, which can hurt performance.
#
# You can load this extension into specific datasets:
#
#   ds = DB[:table]
#   ds = ds.extension(:pagination)
#
# Or you can load it into all of a database's datasets, which
# is probably the desired behavior if you are using this extension:
#
#   DB.extension(:pagination)
#
# Related modules: Sequel::DatasetPagination, Sequel::Dataset::Pagination

#
module Sequel
  module DatasetPagination
    # Returns a paginated dataset. The returned dataset is limited to
    # the page size at the correct offset, and extended with the Pagination
    # module.  If a record count is not provided, does a count of total
    # number of records for this dataset.
    #
    # Options:
    # :at_least :: Do not use a count query or disclose the total number of
    #              records.  The returned dataset only knows the records on
    #              the current page, and whether there is a next page.  The
    #              count is therefore only known to be at least the number of
    #              records through the current page.  Cannot be used with a
    #              provided record count.
    #
    #   ds.paginate(1, 20)                    # Exact record count
    #   ds.paginate(1, 20, :at_least=>true)   # No total count
    def paginate(page_no, page_size, record_count=nil, opts=OPTS)
      raise(Error, "You cannot paginate a dataset that already has a limit") if @opts[:limit]

      if record_count.is_a?(Hash)
        raise(Error, "cannot provide both a record count and options to Dataset#paginate") unless opts.empty?
        opts = record_count
        record_count = nil
      end

      if opts[:at_least]
        raise(Error, "cannot provide a record count when using the :at_least option") unless record_count.nil?

        return limit(page_size, (page_no - 1) * page_size).
          with_extend(Dataset::Pagination).
          clone(:page_size=>page_size, :current_page=>page_no, :pagination_at_least=>true)
      end

      record_count ||= count
      page_count = (record_count / page_size.to_f).ceil
      page_count = 1 if page_count == 0

      limit(page_size, (page_no - 1) * page_size).
        with_extend(Dataset::Pagination).
        clone(:page_size=>page_size, :current_page=>page_no, :pagination_record_count=>record_count, :page_count=>page_count)
    end

    # Yields a paginated dataset for each page and returns the receiver. Does
    # a count to find the total number of records for this dataset. Returns
    # an enumerator if no block is given.
    #
    # If the :at_least option is given, does not do a count query, and instead
    # yields pages until the current page has no next page.  See
    # Dataset#paginate for details on the :at_least option.
    def each_page(page_size, opts=OPTS)
      raise(Error, "You cannot paginate a dataset that already has a limit") if @opts[:limit]
      return to_enum(:each_page, page_size, opts) unless defined?(yield)

      if opts[:at_least]
        page_no = 1
        loop do
          page = paginate(page_no, page_size, opts)
          yield page
          break unless page.has_next_page?
          page_no += 1
        end
        return self
      end

      record_count = count
      total_pages = (record_count / page_size.to_f).ceil
      (1..total_pages).each{|page_no| yield paginate(page_no, page_size, record_count)}
      self
    end
  end

  class Dataset
    # Holds methods that only relate to paginated datasets. Paginated dataset
    # have pages starting at 1 (page 1 is offset 0, page 2 is offset 1 * page_size).
    module Pagination
      # The number of records per page (the final page may have fewer than
      # this number of records).
      def page_size
        @opts[:page_size]
      end

      # The number of pages in the dataset before pagination, of which
      # this paginated dataset is one.  Empty datasets are considered
      # to have a single page.  Returns nil for at-least pagination, since
      # the total number of records is not known.
      def page_count
        return nil if at_least_pagination?
        @opts[:page_count]
      end

      # The current page of the dataset, starting at 1 and not 0.
      def current_page
        @opts[:current_page]
      end

      # Whether this dataset uses at-least pagination, where the total
      # number of records is not disclosed.
      def at_least_pagination?
        @opts[:pagination_at_least] == true
      end

      # The total number of records in the dataset before pagination.
      # Returns nil for at-least pagination, since the total number of
      # records is not disclosed.
      def pagination_record_count
        return nil if at_least_pagination?
        @opts[:pagination_record_count]
      end

      # Returns the record range for the current page.  Returns nil for
      # at-least pagination, since the total number of records is not known.
      def current_page_record_range
        return nil if at_least_pagination?
        return (0..0) if current_page > page_count

        a = 1 + (current_page - 1) * page_size
        b = a + page_size - 1
        b = pagination_record_count if b > pagination_record_count
        a..b
      end

      # Returns the number of records in the current page.  Returns nil for
      # at-least pagination, since the total number of records is not known.
      def current_page_record_count
        return nil if at_least_pagination?
        return 0 if current_page > page_count

        a = 1 + (current_page - 1) * page_size
        b = a + page_size - 1
        b = pagination_record_count if b > pagination_record_count
        b - a + 1
      end

      # Returns true if the current page is the first page
      def first_page?
        current_page == 1
      end

      # Returns true if the current page is the last page
      def last_page?
        if at_least_pagination?
          !has_next_page?
        else
          current_page == page_count
        end
      end

      # Returns the next page number or nil if the current page is the last page
      def next_page
        current_page + 1 if has_next_page?
      end

      # Returns true if there is a next page, false otherwise.  In standard
      # pagination, this is determined using the page count.  In at-least
      # pagination, this issues a query for a single record after the current
      # page.  That query is derived from the same dataset as the current
      # page, so it uses the same filters, joins, and other conditions, and
      # therefore the same authorization conditions.  The result is cached
      # for the dataset, so calling this method multiple times on the same
      # paginated dataset only issues one navigation query.
      def has_next_page?
        if (v = cache_get(:pagination_has_next_page)).nil?
          v = if at_least_pagination?
            !limit(1, current_page * page_size).ungraphed.naked.single_record.nil?
          else
            current_page < page_count
          end
          cache_set(:pagination_has_next_page, v)
        end
        v
      end
      alias_method :next_page?, :has_next_page?

      # Returns the page range.  Returns nil for at-least pagination, since
      # the total number of pages is not known.
      def page_range
        return nil if at_least_pagination?
        1..page_count
      end

      # Returns the previous page number or nil if the current page is the first
      def prev_page
        current_page > 1 ? (current_page - 1) : nil
      end
    end
  end

  Dataset.register_extension(:pagination, DatasetPagination)
end
