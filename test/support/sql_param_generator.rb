# Deterministic generator of small ActiveRecord query expressions used to probe
# the boundary between value placeholders, identifiers and raw SQL fragments in
# Brakeman::CheckSQL.
#
# The generator is deliberately self contained: it does not depend on a checked
# in Rails application. It writes the minimal files Brakeman needs to resolve a
# Rails version and a model, then emits one controller method per anchor.
#
# Every anchor keeps the same tainted source (params[:q]) so that differences in
# Brakeman's verdict come only from the *position* the source is placed in:
#
#   * :safe_bind      - source is genuinely in a value/bind position
#   * :danger         - source is interpolated/concatenated into SQL or used
#                       as an identifier, so an alert is expected
#   * :false_negative - genuinely dangerous but the checker currently stays
#                       silent (documented limitation)
#   * :false_positive - safe code the checker flags because it cannot resolve
#                       the value (reported at medium confidence)
#
# Order/pluck anchors are version sensitive: Rails < 6.1 inspects them,
# Rails >= 6.1 removes them from the checked targets.
module BrakemanTester
  module SqlParamGenerator
    # Fixed seed so generated ordering and any randomized content are stable.
    SEED = 20_261_114

    # The single tainted source reused by every anchor. Reusing one expression
    # is what lets us prove that the verdict is driven by position, not by the
    # shape of the input.
    SOURCE = "params[:q]".freeze

    # Each entry is an independently labelled anchor. :only restricts the
    # anchor to particular Rails major/minor boundaries during scanning.
    ANCHORS = [
      # --- where: value placeholders vs raw fragments ---------------------
      { id: "W01", cat: :safe_bind,
        code: 'Group.where("name = ?", params[:q])',
        note: "positional placeholder, source is a bound value" },
      { id: "W02", cat: :safe_bind,
        code: 'Group.where("name = :name", name: params[:q])',
        note: "named binding, source is a bound value" },
      { id: "W03", cat: :safe_bind,
        code: 'Group.where(["name = ?", params[:q]])',
        note: "bind array, template is static, source in value position" },
      { id: "W04", cat: :danger,
        code: 'Group.where("name = \'#{params[:q]}\'")',
        note: "string interpolation into the SQL template" },
      { id: "W05", cat: :danger,
        code: 'Group.where("name = \'" + params[:q] + "\'")',
        note: "string concatenation into the SQL template" },
      { id: "W06", cat: :danger,
        code: 'Group.where(["name = ? AND #{params[:q]} = 1", 1])',
        note: "bind array whose template itself is interpolated" },
      { id: "W07", cat: :danger,
        code: 'Group.where(params[:q] => 1)',
        note: "dynamic hash key, source controls an identifier" },
      { id: "W08", cat: :danger,
        code: 'Group.where([params[:q] => 1])',
        note: "dynamic identifier key hidden inside an array (regression anchor)" },
      { id: "W09", cat: :danger,
        code: 'Group.where(active: true).where("x = \'#{params[:q]}\'")',
        note: "chained relation, dangerous fragment after a safe hash where" },
      { id: "W10", cat: :safe_bind,
        code: 'Group.where(active: true).where("name = ?", params[:q])',
        note: "chained relation, source stays in value position" },
      { id: "W11", cat: :false_negative,
        code: 'Group.where("name = \'%s\'" % params[:q])',
        note: "String#% formatting is not treated as string building" },

      # --- order / reorder / pluck: identifiers, version sensitive --------
      { id: "O01", cat: :danger,
        code: 'Group.order("name #{params[:q]}")',
        note: "order interpolates an identifier, checked before Rails 6.1",
        only: { max: "6.0.99" } },
      { id: "O02", cat: :safe_bind,
        code: 'Group.order("name ASC")',
        note: "static order fragment, no source at all",
        only: { max: "6.0.99" } },
      { id: "O03", cat: :danger,
        code: 'Group.where(active: true).order(params[:q])',
        note: "chained order on a raw source, checked before Rails 6.1",
        only: { max: "6.0.99" } },
      { id: "O04", cat: :danger,
        code: 'Group.order(Arel.sql("name #{params[:q]}"))',
        note: "Arel.sql wrapped interpolation still reaches order",
        only: { max: "6.0.99" } },
      { id: "O05", cat: :danger,
        code: 'Group.pluck("LOWER(#{params[:q]})")',
        note: "pluck raw fragment interpolation, checked before Rails 6.1",
        only: { max: "6.0.99" } },

      # --- joins: fragments and association identifiers -------------------
      { id: "J01", cat: :danger,
        code: 'Group.joins("LEFT JOIN members ON members.id = #{params[:q]}")',
        note: "joins string fragment is never parameterized" },
      { id: "J02", cat: :safe_bind,
        code: 'Group.joins(:members)',
        note: "association symbol join, no source" },
      { id: "J03", cat: :danger,
        code: 'Group.joins(["JOIN members ON members.id = #{params[:q]}"])',
        note: "joins array does not bind values, fragment stays dangerous" },

      # --- Arel.sql: explicit raw SQL escape hatch ------------------------
      { id: "A01", cat: :danger,
        code: 'Arel.sql("SELECT 1 WHERE x = \'#{params[:q]}\'")',
        note: "Arel.sql interpolated fragment" },
      { id: "A02", cat: :danger,
        code: 'Arel.sql(params[:q])',
        note: "Arel.sql given the raw source directly" },
      { id: "A03", cat: :safe_bind,
        code: 'Group.where(Group.arel_table[:name].eq(params[:q]))',
        note: "Arel predicate binds the source as a value" },
      { id: "A04", cat: :safe_bind,
        code: 'Arel.sql("created_at DESC")',
        note: "Arel.sql static literal, no source" },

      # --- conservative medium-confidence false positive ------------------
      { id: "F01", cat: :false_positive,
        code: 'Group.where("1 = 1 ORDER BY #{sort_column}")',
        note: "whitelist helper result is unresolved and flagged medium",
        helper: "def sort_column; params[:q] == 'age' ? 'age' : 'name'; end" },
    ].freeze

    # Anchors that are actually emitted for a given Rails version string.
    def self.anchors_for(rails_version)
      ANCHORS.select do |anchor|
        constraint = anchor[:only]
        next true if constraint.nil?
        next version_between?("0.0.0", constraint[:max], rails_version) if constraint[:max]
        next version_between?(constraint[:min], "99.99.99", rails_version) if constraint[:min]

        true
      end
    end

    def self.version_between?(low, high, version)
      Gem::Version.new(low) <= Gem::Version.new(version) &&
        Gem::Version.new(version) <= Gem::Version.new(high)
    end

    # A deterministic permutation of anchor ids. The scan must produce the same
    # verdict regardless of presentation order; this proves ordering does not
    # change the result while keeping the run reproducible.
    def self.shuffled_ids(anchors)
      ids = anchors.map { |anchor| anchor[:id] }
      rng = Random.new(SEED)
      ids.shuffle(random: rng)
    end

    def self.controller_source(anchors)
      ordered = order_anchors(anchors)
      lines = ["class GroupsController < ActionController::Base"]

      ordered.each do |anchor|
        lines << "  # anchor:#{anchor[:id]} category:#{anchor[:cat]}"
        lines << "  def #{anchor[:id].downcase}"
        lines << "    #{anchor[:code]}"
        lines << "  end"
      end

      helper_lines(anchors).each { |line| lines << line }
      lines << "end"
      lines.join("\n") + "\n"
    end

    def self.order_anchors(anchors)
      by_id = anchors.to_h { |anchor| [anchor[:id], anchor] }
      shuffled_ids(anchors).map { |id| by_id[id] }
    end

    def self.helper_lines(anchors)
      anchors.select { |anchor| anchor[:helper] }.flat_map do |anchor|
        ["", "  private", "  #{anchor[:helper]}"]
      end
    end

    # Returns a map of anchor id => 1-based line number of the anchor's query
    # expression. Brakeman reports the expression line inside the method, not the
    # def or comment lines, so tests match on the expression line rather than
    # hard coding numbers.
    def self.line_map(anchors)
      map = {}
      current_anchor = nil
      pending_def = false
      controller_source(anchors).each_line.with_index(1) do |line, number|
        comment = line.match(/anchor:([A-Z]\d+)/)
        current_anchor = comment[1] if comment
        pending_def = true if current_anchor && line.include?("def ")
        if pending_def && !line.include?("def ") && !line.strip.start_with?("#")
          map[current_anchor] = number
          current_anchor = nil
          pending_def = false
        end
      end
      map
    end

    def self.gemfile(rails_version)
      "source 'https://rubygems.org'\ngem 'rails', '#{rails_version}'\n"
    end

    def self.application_rb
      <<~RUBY
        module SqlParamApp
          class Application < Rails::Application
            config.load_defaults 6.0
          end
        end
      RUBY
    end

    def self.environment_rb
      "Rails.application.initialize!\n"
    end

    def self.model_source
      "class Group < ActiveRecord::Base\nend\n"
    end

    def self.write_app(root, rails_version, anchors)
      FileUtils.mkdir_p("#{root}/app/controllers")
      FileUtils.mkdir_p("#{root}/app/models")
      FileUtils.mkdir_p("#{root}/config")

      File.write("#{root}/Gemfile", gemfile(rails_version))
      File.write("#{root}/config/application.rb", application_rb)
      File.write("#{root}/config/environment.rb", environment_rb)
      File.write("#{root}/app/models/group.rb", model_source)
      File.write("#{root}/app/controllers/groups_controller.rb", controller_source(anchors))
      root
    end
  end
end
