# frozen-string-literal: true

require 'uri'

begin
  require 'rack/files'
rescue LoadError
  require 'rack/file'
end

#
class Roda
  module RodaPlugins
    # The public plugin adds a +r.public+ routing method to serve static files
    # from a directory.
    #
    # The public plugin recognizes the application's :root option, and defaults to
    # using the +public+ subfolder of the application's +:root+ option.  If the application's
    # :root option is not set, it defaults to the +public+ folder in the working
    # directory.  Additionally, if a relative path is provided as the +:root+
    # option to the plugin, it will be considered relative to the application's
    # +:root+ option.
    #
    # Examples:
    #
    #   # Use public folder as location of files
    #   plugin :public
    #
    #   # Use /path/to/app/static as location of files
    #   opts[:root] = '/path/to/app'
    #   plugin :public, root: 'static'
    #
    #   # Only serve original files registered in the release manifest.
    #   # Compressed copies and range responses are only available for
    #   # originals registered in the manifest.  The manifest is reloaded
    #   # when it changes on disk.
    #   plugin :public, manifest: 'release-manifest.json'
    #
    #   # Replace the manifest at runtime; subsequent requests use it.
    #   public_manifest = ['images/logo.png', 'css/app.css']
    #
    #   # Assuming public is the location of files
    #   route do
    #     # Make GET /images/foo.png look for public/images/foo.png 
    #     r.public
    #
    #     # Make GET /static/images/foo.png look for public/images/foo.png
    #     r.on(:static) do
    #       r.public
    #     end
    #   end
    module Public
      SPLIT = Regexp.union(*[File::SEPARATOR, File::ALT_SEPARATOR].compact)
      RACK_FILES = defined?(Rack::Files) ? Rack::Files : Rack::File
      ENCODING_MAP = {:zstd=>'zstd', :brotli=>'br', :gzip=>'gzip'}.freeze
      ENCODING_EXTENSIONS = {'br'=>'.br', 'gzip'=>'.gz', 'zstd'=>'.zst'}.freeze

      # simplecov:disable
      PARSER = defined?(::URI::RFC2396_PARSER) ? ::URI::RFC2396_PARSER : ::URI::DEFAULT_PARSER
      MATCH_METHOD = RUBY_VERSION >= '2.4' ? :match? : :match
      # simplecov:enable

      SPLIT_ = SPLIT
      ENCODING_MAP_ = {
        :zstd=>['zstd', '.zst', /\bzstd\b/].freeze,
        :brotli=>['br', '.br', /\bbr\b/].freeze,
        :gzip=>['gzip', '.gz', /\bgzip\b/].freeze
      }.freeze
      PARSER_ = PARSER
      MATCH_METHOD_ = MATCH_METHOD

      RodaPlugins.deprecate_constant(self, :SPLIT)
      RodaPlugins.deprecate_constant(self, :RACK_FILES)
      RodaPlugins.deprecate_constant(self, :ENCODING_MAP)
      RodaPlugins.deprecate_constant(self, :ENCODING_EXTENSIONS)
      RodaPlugins.deprecate_constant(self, :PARSER)
      RodaPlugins.deprecate_constant(self, :MATCH_METHOD)

      private_constant(:SPLIT_,
        :ENCODING_MAP_,
        :PARSER_,
        :MATCH_METHOD_)

      # A snapshot of a public release manifest.  The manifest file contains
      # the relative paths of the original files that are allowed to be
      # served.  The file is checked on each request so that a refreshed
      # manifest takes effect for subsequent requests without a restart.
      #
      # The manifest can be a text file with one path per line, or a JSON
      # file containing an array of paths, a hash with paths as keys, or a
      # hash with a +files+, +public+, +assets+, or +paths+ array.
      #
      # The manifest decision is made for the original file path before
      # selecting a compressed representation or generating any file
      # metadata.  A file that is not registered cannot be served, including
      # its compressed copies, range responses, or conditional responses.
      class Manifest
        FILE_KEYS = %w'files public assets paths'.freeze
        private_constant :FILE_KEYS

        def self.static(entries)
          new(nil, normalize_entries(entries))
        end

        def self.dynamic(callable)
          new(nil, nil, callable)
        end

        # Build the manifest state for the given manifest argument.
        def self.build(manifest, app)
          case manifest
          when nil
            nil
          when String
            new(app.expand_path(manifest))
          when Hash, Array
            static(manifest)
          else
            if manifest.respond_to?(:call)
              dynamic(manifest)
            elsif manifest.respond_to?(:to_path)
              new(app.expand_path(manifest.to_path))
            else
              raise RodaError, "invalid public manifest: #{manifest.inspect}"
            end
          end
        end

        def self.normalize_entries(entries)
          entries = unpack_entries(entries)
          entries.each_with_object({}) do |entry, allowed|
            entry = entry['path'] || entry[:path] if entry.is_a?(Hash)
            if path = normalize_path(entry)
              allowed[path] = true
            end
          end.freeze
        end

        # Unwrap a manifest container, returning the array of entries.  A
        # hash with one of the recognized container keys has the value of
        # that key as its entries.  Other hashes are path-keyed, and the
        # keys are the entries.
        def self.unpack_entries(entries)
          if entries.is_a?(Hash)
            if key = FILE_KEYS.find{|k| entries.key?(k)}
              unpack_entries(entries[key])
            else
              entries.keys
            end
          elsif entries.is_a?(Array)
            entries
          elsif entries.nil?
            []
          else
            [entries]
          end
        end
        private_class_method :unpack_entries

        def self.normalize_path(path)
          return if path.nil?
          path = path.to_s
          return if path.empty? || path.include?("\0")

          segments = []
          path.tr('\\', '/').split('/').each do |segment|
            next if segment.empty? || segment == '.'
            segment == '..' ? segments.pop : segments << segment
          end
          segments.join('/')
        end

        def initialize(path, entries=nil, callable=nil)
          @path = path
          @callable = callable
          @entries = entries || EMPTY_MANIFEST
          @signature = entries ? :static : nil
          @mutex = Mutex.new
        end

        def include?(path)
          if @callable
            return !!@callable.call(path)
          end
          return @entries.key?(path) if @signature == :static

          @mutex.synchronize do
            reload_if_changed
            @entries.key?(path)
          end
        end

        private

        def reload_if_changed
          signature = begin
            stat = ::File.stat(@path)
            mtime = stat.mtime
            ctime = stat.ctime
            [stat.ino, stat.size, mtime.to_i, mtime.nsec, ctime.to_i, ctime.nsec]
          rescue SystemCallError
            # simplecov:disable
            nil
            # simplecov:enable
          end

          return if signature == @signature

          entries = if signature
            parse(::File.read(@path))
          else
            EMPTY_MANIFEST
          end

          # Only cache the result after a successful read and parse, so a
          # partially written or invalid manifest is retried on the next
          # request instead of denying access until the process restarts.
          @entries = entries
          @signature = signature
        rescue StandardError
          # simplecov:disable
          @signature = nil
          @entries = EMPTY_MANIFEST
          # simplecov:enable
        end

        def parse(content)
          if content.lstrip.start_with?('{', '[')
            parse_json(content)
          else
            parse_text(content)
          end
        end

        def parse_text(content)
          content.each_line.each_with_object({}) do |line, allowed|
            line = line.strip
            next if line.empty? || line.start_with?('#')

            line = line.split(/[ \t]/, 2)[0]
            if path = self.class.normalize_path(line)
              allowed[path] = true
            end
          end.freeze
        end

        def parse_json(content)
          require 'json'
          self.class.normalize_entries(::JSON.parse(content))
        end
      end

      EMPTY_MANIFEST = {}.freeze
      private_constant :EMPTY_MANIFEST

      # Use arguments given to setup a Rack::File instance for serving files. Arguments:
      # +brotli+ :: Whether to serve already brotli-compressed files with a .br extension
      #             for clients supporting "br" transfer encoding.
      # +default_mime+ :: The default mime type to use if the mime type is not recognized.
      # +encodings+ :: An enumerable of pairs to handle accepted encodings.  The first
      #                element of the pair is the accepted encoding name (e.g. 'gzip'),
      #                and the second element of the pair is the file extension (e.g.
      #                '.gz'). This allows configuration of the order in which encodings 
      #                are tried, to prefer brotli to zstd for example, or to support
      #                encodings other than zstd, brotli, and gzip. This takes
      #                precedence over the +brotli+, +gzip+, and +zstd+ arguments.
      # :gzip :: Whether to serve already gzipped files with a .gz extension for clients
      #          supporting "gzip" transfer encoding.
      # :headers :: A hash of headers to use for statically served files
      # :manifest :: A path to a public release manifest.  When set, only
      #              files registered in the manifest can be served, and
      #              the compressed representation and range responses are
      #              selected only for registered original files.  The
      #              manifest is reloaded when it changes on disk, so new
      #              requests use the refreshed entries without restarting.
      # :root :: Specifies the root directory in the file system to serve files from
      #          (default: "public")
      # :zstd :: Whether to serve already zstd-compressed files with a .zst extension
      #          for clients supporting "zstd" transfer encoding.
      def self.configure(app, opts=(no_positional_opts = true; OPTS),
          root: opts[:root],
          headers: opts[:headers],
          default_mime: opts[:default_mime],
          encodings: opts[:encodings],
          gzip: opts[:gzip],
          brotli: opts[:brotli],
          zstd: opts[:zstd],
          manifest: opts[:manifest],
          **kw)
        RodaPlugins.check_keywords("the public plugin", no_positional_opts, opts, kw)

        app.opts[:public_root] = app.expand_path(root || app.public_root || "public")
        app.opts[:public_default_mime] =  default_mime || 'text/plain'
        files = defined?(Rack::Files) ? Rack::Files : Rack::File
        app.opts[:public_server] = files.new(app.public_root, headers||OPTS, app.public_default_mime)

        manifest = manifest.nil? ? app.public_manifest : manifest
        app.opts[:public_manifest] = manifest
        app.opts[:public_manifest_state] = Public::Manifest.build(manifest, app)

        app.opts[:public_encodings] = if encodings
          encodings.map{|a| [*a, /\b#{a[0]}\b/].freeze}.freeze
        elsif zstd || brotli || gzip
          encodings = []
          [[:zstd, zstd], [:brotli, brotli], [:gzip, gzip]].each do |sym, value|
            encodings << ENCODING_MAP_[sym] if value
          end
          encodings.freeze
        else
          app.public_encodings || EMPTY_ARRAY
        end
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :public_root)
        RodaPlugins.opt_attr_reader(self, :public_server)
        RodaPlugins.opt_attr_reader(self, :public_encodings)
        RodaPlugins.opt_attr_reader(self, :public_default_mime)
        RodaPlugins.opt_attr_reader(self, :public_manifest)
        RodaPlugins.opt_attr_reader(self, :public_manifest_state)

        # Replace the manifest used to decide which original files are
        # public.  This can be a manifest file path, a hash or array of
        # paths, or a callable that receives the normalized path and
        # returns whether the path is public.  The change applies to
        # subsequent requests.
        def public_manifest=(manifest)
          opts[:public_manifest] = manifest
          opts[:public_manifest_state] = Public::Manifest.build(manifest, self)
          nil
        end
      end

      module RequestMethods
        # Serve files from the public directory if the file exists and this is a GET request.
        def public
          public_serve_with(roda_class.public_server)
        end

        private

        # Return an array of segments for the given path, handling ..
        # and . components
        def public_path_segments(path)
          segments = []
            
          path.split(SPLIT_).each do |seg|
            next if seg.empty? || seg == '.'
            seg == '..' ? segments.pop : segments << seg
          end
            
          segments
        end

        # Return whether the given path is a readable regular file.
        def public_file_readable?(path)
          ::File.file?(path) && ::File.readable?(path)
        rescue SystemCallError
          # simplecov:disable
          false
          # simplecov:enable
        end

        def public_serve_with(server)
          manifest = roda_class.public_manifest_state

          # With a manifest, HEAD is handled as the header-only form of GET,
          # so the registered original, its compressed representation, and
          # its range metadata have the same visibility for both methods.
          # Without a manifest, retain the historical GET-only behavior.
          return unless is_get? || (manifest && head?)

          path = PARSER_.unescape(real_remaining_path)
          return if path.include?("\0")

          segments = public_path_segments(path)

          # The manifest decision is made against the original path, before
          # selecting a compressed representation or generating any file
          # metadata (such as Last-Modified or Range information).
          if manifest && !manifest.include?(segments.join('/'))
            return
          end

          path = ::File.join(server.root, *segments)

          if accept_encoding = env['HTTP_ACCEPT_ENCODING']
            roda_class.public_encodings.each do |enc, ext, regexp|
              if regexp.send(MATCH_METHOD_, accept_encoding)
                public_serve_compressed(server, path, ext, enc)
              end
            end
          end

          if public_file_readable?(path)
            s, h, b = public_serve(server, path)
            headers = response.headers
            headers.replace(h)
            public_add_vary(headers)
            halt [s, headers, b]
          end
        end

        # When encodings are used, the response depends on the Accept-Encoding
        # request header, so add it to the Vary header for caches.
        def public_add_vary(headers)
          unless roda_class.public_encodings.empty?
            headers[RodaResponseHeaders::VARY] = (vary = headers[RodaResponseHeaders::VARY]) ? "#{vary}, Accept-Encoding" : 'Accept-Encoding'
          end
          nil
        end

        # Serve the compressed file if it exists.  This should only
        # be called if the client will accept the related encoding.
        def public_serve_compressed(server, path, suffix, encoding)
          compressed_path = path + suffix

          if public_file_readable?(compressed_path)
            s, h, b = public_serve(server, compressed_path)
            headers = response.headers
            headers.replace(h)

            unless s == 304
              headers[RodaResponseHeaders::CONTENT_TYPE] = ::Rack::Mime.mime_type(::File.extname(path), roda_class.public_default_mime)
              headers[RodaResponseHeaders::CONTENT_ENCODING] = encoding
            end
            public_add_vary(headers)

            halt [s, headers, b]
          end
        end

        if ::Rack.release > '2'
          # Serve the given path using the given Rack::Files server.
          def public_serve(server, path)
            server.serving(self, path)
          end
        else
          def public_serve(server, path)
            server = server.dup
            server.path = path
            server.serving(env)
          end
        end
      end
    end

    register_plugin(:public, Public)
  end
end
