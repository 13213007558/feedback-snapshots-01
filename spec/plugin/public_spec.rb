require_relative "../spec_helper"
require 'tmpdir'
require 'json'

describe "public plugin" do
  it "adds r.public for serving static files from public folder" do
    app(:bare) do
      plugin :public, :root=>'spec/views'

      route do |r|
        r.public

        r.on 'static' do
          r.public
        end
      end
    end

    status("/about/_test.erb\0").must_equal 404
    body('/about/_test.erb').must_equal File.read('spec/views/about/_test.erb')
    body('/static/about/_test.erb').must_equal File.read('spec/views/about/_test.erb')
    body('/foo/.././/about/_test.erb').must_equal File.read('spec/views/about/_test.erb')
  end

  it "respects the application's :root option" do
    app(:bare) do
      opts[:root] = File.expand_path('../../', __FILE__)
      plugin :public, :root=>'views'

      route do |r|
        r.public
      end
    end

    body('/about/_test.erb').must_equal File.read('spec/views/about/_test.erb')
  end

  it "keeps existing :root option if loaded a second time" do
    app(:bare) do
      plugin :public, :root=>'spec/views'
      plugin :public

      route do |r|
        r.public
      end
    end

    body('/about/_test.erb').must_equal File.read('spec/views/about/_test.erb')
    header(RodaResponseHeaders::CONTENT_TYPE, '/about/_test.erb').must_equal 'text/plain'
    header('x-foo', '/about/_test.erb').must_be_nil
  end

  it "support :headers options for custom headers" do
    app(:bare) do
      plugin :public, :root=>'spec/views', :headers=>{'x-foo' => 'bar'}

      route do |r|
        r.public
      end
    end

    body('/about/_test.erb').must_equal File.read('spec/views/about/_test.erb')
    header(RodaResponseHeaders::CONTENT_TYPE, '/about/_test.erb').must_equal 'text/plain'
    header('x-foo', '/about/_test.erb').must_equal 'bar'
  end

  it "support :default_mime options for default mime type" do
    app(:bare) do
      plugin :public, :root=>'spec/views', :default_mime=>'foo/bar'

      route do |r|
        r.public
      end
    end

    body('/about/_test.erb').must_equal File.read('spec/views/about/_test.erb')
    header(RodaResponseHeaders::CONTENT_TYPE, '/about/_test.erb').must_equal 'foo/bar'
    header('x-foo', '/about/_test.erb').must_be_nil
  end

  it "assumes public directory as default :root option" do
    app(:public){|_|}
    app.opts[:public_root].must_equal File.expand_path('public')
  end

  types = [
    [:gzip, 'gzip', '.gz'],
    [:brotli, 'br', '.br'],
    [:zstd, 'zstd', '.zst'],
  ]
  types.each do  |type, accept, ext|
    [true, false].each do |use_encodings|
      opts = {:root=>'spec/views'}
      if use_encodings
        opts[:encodings] = [[accept, ext]]
        opts[:encodings] << ['zstd', '.zst'] if type == :brotli
        opts[:encodings] << ['gzip', '.gz'] unless type == :gzip
      else
        opts[:gzip] = opts[type] = true
      end

      it "handles serving files with #{ext} extension if client supports accepts #{accept} encoding when :encodings is #{'not ' unless use_encodings}given" do
        app(:bare) do
          plugin :public, **opts

          route do |r|
            r.public
          end
        end

        body('/about/_test.erb').must_equal File.read('spec/views/about/_test.erb')
        header(RodaResponseHeaders::CONTENT_ENCODING, '/about/_test.erb').must_be_nil
        header(RodaResponseHeaders::VARY, '/about/_test.erb').must_equal 'Accept-Encoding'

        body('/about.erb').must_equal File.read('spec/views/about.erb')
        header(RodaResponseHeaders::CONTENT_ENCODING, '/about.erb').must_be_nil
        
        accept_encoding = "deflate,#{' gzip,' unless type == :gzip} #{accept}"

        body('/about/_test.erb', 'HTTP_ACCEPT_ENCODING'=>accept_encoding).must_equal File.binread("spec/views/about/_test.erb.gz")
        h = req('/about/_test.erb', 'HTTP_ACCEPT_ENCODING'=>accept_encoding)[1]
        h[RodaResponseHeaders::CONTENT_ENCODING].must_equal 'gzip'
        h[RodaResponseHeaders::CONTENT_TYPE].must_equal 'text/plain'
        h[RodaResponseHeaders::VARY].must_equal 'Accept-Encoding'

        body('/about/_test2.css', 'HTTP_ACCEPT_ENCODING'=>accept_encoding).must_equal File.binread("spec/views/about/_test2.css#{ext}")
        h = req('/about/_test2.css', 'HTTP_ACCEPT_ENCODING'=>accept_encoding)[1]
        h[RodaResponseHeaders::CONTENT_ENCODING].must_equal accept
        h[RodaResponseHeaders::CONTENT_TYPE].must_equal 'text/css'

        s, h, b = req('/about/_test2.css', 'HTTP_IF_MODIFIED_SINCE'=>h[RodaResponseHeaders::LAST_MODIFIED], 'HTTP_ACCEPT_ENCODING'=>accept_encoding)
        s.must_equal 304
        h[RodaResponseHeaders::CONTENT_ENCODING].must_be_nil
        h[RodaResponseHeaders::CONTENT_TYPE].must_be_nil
        h[RodaResponseHeaders::VARY].must_equal 'Accept-Encoding'
        b.must_equal []
      end
    end
  end

  it "does not add Vary when no encodings are used" do
    app(:bare) do
      plugin :public, :root=>'spec/views'

      route do |r|
        r.public
      end
    end

    header(RodaResponseHeaders::VARY, '/about/_test.erb', 'HTTP_ACCEPT_ENCODING'=>'gzip').must_be_nil
  end

  it "appends Accept-Encoding to a Vary header given in the :headers option" do
    app(:bare) do
      plugin :public, :root=>'spec/views', :gzip=>true, :headers=>{RodaResponseHeaders::VARY=>'Cookie'}

      route do |r|
        r.public
      end
    end

    header(RodaResponseHeaders::VARY, '/about/_test.erb', 'HTTP_ACCEPT_ENCODING'=>'gzip').must_equal 'Cookie, Accept-Encoding'
    header(RodaResponseHeaders::VARY, '/about/_test.erb').must_equal 'Cookie, Accept-Encoding'
  end

  it "does not handle non-GET requests" do
    app(:bare) do
      plugin :public, :root=>'spec/views'

      route do |r|
        r.public
      end
    end

    status("/about/_test.erb", "REQUEST_METHOD"=>"POST").must_equal 404
  end

  describe "with a :manifest option" do
    def with_public_dir
      Dir.mktmpdir do |dir|
        File.write(File.join(dir, 'public.txt'), 'PUBLIC')
        File.write(File.join(dir, 'private.txt'), 'PRIVATE')
        File.binwrite(File.join(dir, 'public.txt.gz'), 'PUBLIC_GZ')
        File.binwrite(File.join(dir, 'private.txt.gz'), 'PRIVATE_GZ')
        yield dir
      end
    end

    def public_app(dir, manifest, **opts)
      app(:bare) do
        plugin :public, root: dir, manifest: manifest, gzip: true, **opts

        route do |r|
          r.public
        end
      end
    end

    it "serves only originals registered in a text manifest" do
      with_public_dir do |dir|
        manifest = File.join(dir, 'manifest')
        File.write(manifest, "# released\npublic.txt\n")
        public_app(dir, manifest)

        body('/public.txt').must_equal 'PUBLIC'
        status('/private.txt').must_equal 404
        status('/public.txt.gz').must_equal 404
      end
    end

    it "serves only originals registered in a JSON manifest" do
      with_public_dir do |dir|
        manifest = File.join(dir, 'manifest.json')
        File.write(manifest, JSON.dump('files' => ['public.txt']))
        public_app(dir, manifest)

        body('/public.txt').must_equal 'PUBLIC'
        status('/private.txt').must_equal 404
      end
    end

    it "denies files while the manifest file is missing" do
      with_public_dir do |dir|
        public_app(dir, File.join(dir, 'missing-manifest'))

        status('/public.txt').must_equal 404
        status('/public.txt', 'REQUEST_METHOD' => 'HEAD').must_equal 404
        status('/public.txt', 'HTTP_RANGE' => 'bytes=0-2').must_equal 404
      end
    end

    it "binds compressed selection to the registered original" do
      with_public_dir do |dir|
        manifest = File.join(dir, 'manifest')
        File.write(manifest, "public.txt\n")
        public_app(dir, manifest)

        body('/public.txt', 'HTTP_ACCEPT_ENCODING' => 'gzip').must_equal 'PUBLIC_GZ'
        header(RodaResponseHeaders::CONTENT_ENCODING, '/public.txt', 'HTTP_ACCEPT_ENCODING' => 'gzip').must_equal 'gzip'

        status('/private.txt', 'HTTP_ACCEPT_ENCODING' => 'gzip').must_equal 404
        header(RodaResponseHeaders::CONTENT_ENCODING, '/private.txt', 'HTTP_ACCEPT_ENCODING' => 'gzip').must_be_nil
      end
    end

    it "has the same visibility for HEAD as GET" do
      with_public_dir do |dir|
        manifest = File.join(dir, 'manifest')
        File.write(manifest, "public.txt\n")
        public_app(dir, manifest)

        s, h, b = req('/public.txt', 'REQUEST_METHOD' => 'HEAD')
        s.must_equal 200
        h[RodaResponseHeaders::CONTENT_LENGTH].must_equal '6'
        b.must_equal []

        status('/private.txt', 'REQUEST_METHOD' => 'HEAD').must_equal 404

        s, h, _ = req('/public.txt', 'REQUEST_METHOD' => 'HEAD', 'HTTP_ACCEPT_ENCODING' => 'gzip')
        s.must_equal 200
        h[RodaResponseHeaders::CONTENT_ENCODING].must_equal 'gzip'
      end
    end

    it "does not expose conditional metadata for unregistered originals" do
      with_public_dir do |dir|
        manifest = File.join(dir, 'manifest')
        File.write(manifest, "public.txt\n")
        public_app(dir, manifest)

        last_modified = header(RodaResponseHeaders::LAST_MODIFIED, '/public.txt')
        last_modified.wont_be_nil
        status('/public.txt', 'HTTP_IF_MODIFIED_SINCE' => last_modified).must_equal 304

        status('/private.txt', 'HTTP_IF_MODIFIED_SINCE' => 'Thu, 01 Jan 1970 00:00:00 GMT').must_equal 404
        header(RodaResponseHeaders::LAST_MODIFIED, '/private.txt').must_be_nil
      end
    end

    it "does not serve ranges of unregistered originals" do
      with_public_dir do |dir|
        manifest = File.join(dir, 'manifest')
        File.write(manifest, "public.txt\n")
        public_app(dir, manifest)

        s, h = req('/public.txt', 'HTTP_RANGE' => 'bytes=0-2')
        s.must_equal 206
        h['content-range'].must_equal 'bytes 0-2/6'
        body('/public.txt', 'HTTP_RANGE' => 'bytes=0-2').must_equal 'PUB'

        status('/private.txt', 'HTTP_RANGE' => 'bytes=0-2').must_equal 404
        header('content-range', '/private.txt', 'HTTP_RANGE' => 'bytes=0-2').must_be_nil
      end
    end

    it "uses a refreshed manifest for subsequent requests" do
      with_public_dir do |dir|
        manifest = File.join(dir, 'manifest')
        File.write(manifest, "public.txt\n")
        public_app(dir, manifest)

        body('/public.txt').must_equal 'PUBLIC'
        status('/private.txt').must_equal 404

        File.write(manifest, "private.txt\n")
        # Ensure the signature changes even on file systems with coarse mtimes.
        File.utime(Time.now + 2, Time.now + 2, manifest)

        status('/public.txt').must_equal 404
        body('/private.txt').must_equal 'PRIVATE'
      end
    end

    it "can replace the manifest at runtime" do
      with_public_dir do |dir|
        manifest = File.join(dir, 'manifest')
        File.write(manifest, "public.txt\n")
        public_app(dir, manifest)

        body('/public.txt').must_equal 'PUBLIC'

        app.public_manifest = ['private.txt']
        status('/public.txt').must_equal 404
        body('/private.txt').must_equal 'PRIVATE'

        app.public_manifest = nil
        body('/public.txt').must_equal 'PUBLIC'
      end
    end

    it "keeps working for applications without a manifest" do
      app(:bare) do
        plugin :public, root: 'spec/views', gzip: true

        route do |r|
          r.public
        end
      end

      body('/about/_test.erb').must_equal File.read('spec/views/about/_test.erb')
      body('/about/_test.erb', 'HTTP_ACCEPT_ENCODING' => 'gzip').must_equal File.binread('spec/views/about/_test.erb.gz')
    end
  end
end
