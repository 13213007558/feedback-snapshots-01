require_relative "../spec_helper"

describe "content_security_policy_nonce plugin" do
  it "generates a single request nonce per request" do
    nonce = nil
    app(:content_security_policy_nonce) do |r|
      r.get 'js' do
        %(<script nonce="#{nonce = content_security_policy_nonce}"></script>) +
        %(<script nonce="#{content_security_policy_nonce}"></script>)
      end
    end

    _, h, b = req("/js")

    h[RodaResponseHeaders::CONTENT_SECURITY_POLICY].must_equal "script-src 'nonce-#{nonce}'; style-src 'nonce-#{nonce}'; "
    nonce.size.must_equal 44
    b.must_equal ["<script nonce=\"#{nonce}\"></script>" * 2]
  end

  it "works with existing content_security_policy settings" do
    nonce = nil
    app(:content_security_policy_nonce) do |r|
      r.get 'js' do
        content_security_policy.script_src "foo.example.com"
        %(<script nonce="#{nonce = content_security_policy_nonce}"></script>) +
        %(<script nonce="#{content_security_policy_nonce}"></script>)
      end
    end

    _, h, b = req("/js")

    h[RodaResponseHeaders::CONTENT_SECURITY_POLICY].must_equal "script-src foo.example.com 'nonce-#{nonce}'; style-src 'nonce-#{nonce}'; "
    nonce.size.must_equal 44
    b.must_equal ["<script nonce=\"#{nonce}\"></script>" * 2]
  end

  it "allows overriding the nonce generator" do
    app(:bare) do
      plugin :content_security_policy_nonce do
        "NONCE"
      end

      route do |r|
        r.get 'js' do
          %(<script nonce="#{content_security_policy_nonce}"></script>)
        end
      end
    end

    _, h, b = req("/js")

    h[RodaResponseHeaders::CONTENT_SECURITY_POLICY].must_equal "script-src 'nonce-NONCE'; style-src 'nonce-NONCE'; "
    b.must_equal ["<script nonce=\"NONCE\"></script>"]
  end

  it "supports declaring the nonce before headers for a lazily generated streaming body" do
    declared_nonce = nil
    lazy_body = nil

    app(:content_security_policy_nonce) do |r|
      r.get 'stream' do
        nonce = content_security_policy_nonce!
        declared_nonce = nonce
        lazy_body = Object.new
        lazy_body.define_singleton_method(:each) do |&block|
          block.call(%(<script nonce="#{nonce}"></script>))
        end
        r.halt response.finish_with_body(lazy_body)
      end
    end

    _, h, b = req("/stream")

    unless_lint do
      b.must_be_same_as(lazy_body)
    end
    h[RodaResponseHeaders::CONTENT_SECURITY_POLICY].must_equal "script-src 'nonce-#{declared_nonce}'; style-src 'nonce-#{declared_nonce}'; "

    rendered = []
    b.each { |chunk| rendered << chunk }
    rendered.must_equal [%(<script nonce="#{declared_nonce}"></script>)]
  end

  it "reuses a single declared nonce when requested again from the lazy body" do
    declared_nonce = nil

    app(:content_security_policy_nonce) do |r|
      r.get 'stream' do
        declared_nonce = content_security_policy_nonce!
        scope = self
        body = Object.new
        body.define_singleton_method(:each) do |&block|
          block.call(%(<script nonce="#{scope.content_security_policy_nonce}"></script>))
        end
        r.halt response.finish_with_body(body)
      end
    end

    _, h, b = req("/stream")

    h[RodaResponseHeaders::CONTENT_SECURITY_POLICY].must_equal "script-src 'nonce-#{declared_nonce}'; style-src 'nonce-#{declared_nonce}'; "

    rendered = []
    b.each { |chunk| rendered << chunk }
    rendered.must_equal [%(<script nonce="#{declared_nonce}"></script>)]
  end

  it "does not add a nonce for streaming responses that do not use inline scripts" do
    app(:content_security_policy_nonce) do |r|
      r.get 'plain' do
        body = Object.new
        body.define_singleton_method(:each) do |&block|
          block.call("plain streaming body")
        end
        r.halt response.finish_with_body(body)
      end
    end

    _, h, b = req("/plain")

    h.wont_include(RodaResponseHeaders::CONTENT_SECURITY_POLICY)

    rendered = []
    b.each { |chunk| rendered << chunk }
    rendered.must_equal ["plain streaming body"]
  end

  it "raises when a nonce is first requested from the body after headers are finalized" do
    app(:content_security_policy_nonce) do |r|
      r.get 'stream' do
        scope = self
        body = Object.new
        body.define_singleton_method(:each) do |&block|
          block.call(%(<script nonce="#{scope.content_security_policy_nonce}"></script>))
        end
        r.halt response.finish_with_body(body)
      end
    end

    if ENV['LINT']
      # Rack::Lint iterates the body while processing the request.
      proc do
        req("/stream")
      end.must_raise(Roda::RodaError).message.must_include "content_security_policy_nonce!"
    else
      _, _, b = req("/stream")

      proc do
        b.each { |_| }
      end.must_raise(Roda::RodaError).message.must_include "content_security_policy_nonce!"
    end
  end

  it "raises when a nonce is declared after the response headers have been finalized" do
    app(:content_security_policy_nonce) do |r|
      r.get 'stream' do
        response.finish
        content_security_policy_nonce!
      end
    end

    proc do
      req("/stream")
    end.must_raise(Roda::RodaError).message.must_include "after response headers have been finalized"
  end
end
