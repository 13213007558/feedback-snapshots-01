# frozen_string_literal: true

module Liquid
  module SnippetMigration
    # Loads snippet sources from one or more directories without relying on
    # Liquid::LocalFileSystem's underscore naming convention. The analyzer only
    # needs the source and a stable path for evidence.
    class Repository
      attr_reader :roots

      def initialize(roots)
        @roots = Array(roots).compact.map { |root| File.expand_path(root) }
        @cache = {}
      end

      def read(name)
        return @cache[name] if @cache.key?(name)

        @cache[name] = find(name)
      end

      def exist?(name)
        !read(name).nil?
      end

      private

      def find(name)
        return nil unless name.is_a?(String) && !name.empty?

        @roots.each do |root|
          candidate_paths(name, root).each do |path|
            expanded = File.expand_path(path)
            next unless expanded.start_with?(root + File::SEPARATOR)
            next unless File.file?(expanded)

            return Source.new(name: name, path: expanded, body: File.read(expanded))
          end
        end
        nil
      end

      def candidate_paths(name, root)
        relative = name
        variants = if File.extname(relative).empty?
          [relative, File.join(File.dirname(relative), "_#{File.basename(relative)}")]
        else
          [relative]
        end

        variants.flat_map do |variant|
          if File.extname(variant).empty?
            [File.join(root, "#{variant}.liquid"), File.join(root, variant)]
          else
            [File.join(root, variant)]
          end
        end
      end
    end

    Source = Struct.new(:name, :path, :body, keyword_init: true)
  end
end
