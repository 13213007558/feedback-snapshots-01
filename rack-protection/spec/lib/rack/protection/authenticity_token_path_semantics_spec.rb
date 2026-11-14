# frozen_string_literal: true

# Differential, path-semantics tests for the *per-form* CSRF token.
#
# A per-form token is bound to an action identifier of the form
# "<path>#<method>" (see AuthenticityToken#per_form_token). For the token to be
# sound, two things must hold at the same time:
#
#   1. SECURITY  - a token issued for one action is rejected when replayed
#                  against a different action (different path or method).
#   2. SOUNDNESS - every conventional representation of the *same* action that
#                  a form can be issued for and that Rack can deliver must be
#                  accepted; legitimate submissions must never fail randomly.
#
# These specs exercise the real issue/verify round trip end to end: tokens are
# produced with AuthenticityToken.token (real masked HMAC output, never faked)
# and verified by sending them through the actual middleware stack. The four
# dimensions that change the path/method Rack observes are covered:
#
#   * mount prefix      (SCRIPT_NAME + PATH_INFO -> Request#path)
#   * trailing slash    (single trailing "/")
#   * percent-encoding  (Request#path keeps the raw, encoded path)
#   * method override   (Rack::MethodOverride placed before vs after protection)
RSpec.describe Rack::Protection::AuthenticityToken, 'per-form path semantics' do
  # A fixed session so the token issued "by the form" and the token checked
  # "on submission" share one secret, exactly like a real browser session.
  let(:session) { { csrf: described_class.random_token } }
  let(:param)   { 'authenticity_token' }

  # Build a real protection stack. `override_position` controls where
  # Rack::MethodOverride sits relative to the protection middleware:
  #   :before -> it rewrites REQUEST_METHOD before protection sees the request
  #   :after  -> protection sees the original POST and override runs later
  def protection_app(position = nil)
    sess = session
    Rack::Builder.new do
      use Rack::Config do |env|
        env['rack.session'] ||= sess
      end
      use Rack::MethodOverride if position == :before
      use Rack::Protection::AuthenticityToken
      use Rack::MethodOverride if position == :after
      run ->(env) { [200, { 'content-type' => 'text/plain' }, ['ok']] }
    end.to_app
  end

  # Issue a genuine masked per-form token for a form that targets `path`.
  def issue(path, method: :post)
    described_class.token(session, path: path, method: method)
  end

  # Drive one submission through the real middleware and return whether the
  # protection layer accepted (reached the app -> 200) or denied it (-> 403).
  def accepted?(token, request_path, request_method, extra_env: {}, position: nil, params: {})
    app = protection_app(position)
    env = Rack::MockRequest.env_for(
      request_path,
      method: request_method.to_s.upcase,
      params: { param => token }.merge(params),
      **extra_env
    )
    status, = app.call(env)
    status == 200
  end

  # -------------------------------------------------------------------------
  # Finite set of protected actions used throughout the spec. Each pair names
  # one logical action and the surface form it is issued/seen under.
  # -------------------------------------------------------------------------
  describe 'mount prefix (SCRIPT_NAME)' do
    # Rack::Request#path is SCRIPT_NAME + PATH_INFO, so a router that mounts an
    # app under "/app" presents the action "/foo" as the full path "/app/foo".
    it 'accepts when the form is signed with the mount-aware full path' do
      token = issue('/app/foo')
      result = accepted?(
        token, '/app/foo', :post,
        extra_env: { 'SCRIPT_NAME' => '/app', 'PATH_INFO' => '/foo' }
      )
      expect(result).to be(true)
    end

    it 'fails closed when signed with PATH_INFO only but seen under a prefix' do
      # Minimal failing route pair: same underlying "/foo" action, but the
      # signer and the verifier disagree about the mount prefix. Denying is the
      # safe outcome; the contract is that forms must be signed with the same
      # mount-aware path Rack exposes via Request#path.
      token = issue('/foo')
      result = accepted?(
        token, '/app/foo', :post,
        extra_env: { 'SCRIPT_NAME' => '/app', 'PATH_INFO' => '/foo' }
      )
      expect(result).to be(false)
    end

    it 'still rejects a token replayed onto a genuinely different mounted action' do
      token = issue('/app/foo')
      result = accepted?(
        token, '/app/bar', :post,
        extra_env: { 'SCRIPT_NAME' => '/app', 'PATH_INFO' => '/bar' }
      )
      expect(result).to be(false)
    end
  end

  describe 'trailing slash' do
    # A single trailing slash is a conventional spelling of the same action.
    # Issuing and verifying run through the same canonical_form_identifier, so
    # every combination below must succeed.
    [
      '/foo',
      '/foo/'
    ].each do |signed_path|
      ['/foo', '/foo/'].each do |seen_path|
        it "accepts sign #{signed_path.inspect} against seen #{seen_path.inspect}" do
          token = issue(signed_path)
          expect(accepted?(token, seen_path, :post)).to be(true)
        end
      end
    end

    it 'fails closed for an extra segment rather than normalizing it away' do
      # Minimal failing route pair: "/foo//" is a different path, not a trailing
      # slash spelling of "/foo", so it must not be accepted on "/foo"'s token.
      token = issue('/foo')
      expect(accepted?(token, '/foo//', :post)).to be(false)
    end

    it 'round-trips the root action whose only spelling is a single slash' do
      # "/" canonicalizes to "" on both issue and verify, so it must still work.
      token = issue('/')
      expect(accepted?(token, '/', :post)).to be(true)
    end
  end

  describe 'percent-encoding' do
    # Rack::Request#path retains the raw, percent-encoded form. Signing and
    # verifying must therefore use the same (raw) spelling. This is a
    # representation contract, not a canonicalization the middleware invents.
    it 'accepts when the same encoded spelling is used on both sides' do
      token = issue('/foo%20bar')
      expect(accepted?(token, '/foo%20bar', :post)).to be(true)
    end

    it 'accepts an encoded reserved slash (%2F) used consistently' do
      token = issue('/foo%2Fbar')
      expect(accepted?(token, '/foo%2Fbar', :post)).to be(true)
    end

    it 'fails closed when the signer decodes but Rack keeps the raw encoding' do
      # Minimal failing route pair: decoded "/foo bar" at issue time vs raw
      # "/foo%20bar" at verify time. These are different identifiers, so the
      # request is denied rather than silently collapsing two spellings.
      token = issue('/foo bar')
      expect(accepted?(token, '/foo%20bar', :post)).to be(false)
    end

    it 'does not treat an encoded slash as a path separator for another action' do
      # "/foo%2Fbar" must not be accepted by a token bound to the two-segment
      # action "/foo/bar": encoding must not smuggle a segment boundary.
      token = issue('/foo/bar')
      expect(accepted?(token, '/foo%2Fbar', :post)).to be(false)
    end
  end

  describe 'method override ordering' do
    # A browser POST carrying _method=PUT is routed as PUT. Which REQUEST_METHOD
    # the protection layer sees depends entirely on middleware order.
    it 'accepts a PUT-signed token when MethodOverride runs before protection' do
      token = issue('/foo', method: :put)
      result = accepted?(
        token, '/foo', :post, position: :before,
        params: { '_method' => 'put' }
      )
      expect(result).to be(true)
    end

    it 'rejects a POST-signed token when override-before turns the request into PUT' do
      # With override first, protection sees PUT, so a POST-scoped token is a
      # different action and must be rejected.
      token = issue('/foo', method: :post)
      result = accepted?(
        token, '/foo', :post, position: :before,
        params: { '_method' => 'put' }
      )
      expect(result).to be(false)
    end

    it 'accepts a POST-signed token when MethodOverride runs after protection' do
      # Override last: protection still sees the original POST, so the
      # POST-scoped token is valid for the action protection evaluates.
      token = issue('/foo', method: :post)
      result = accepted?(
        token, '/foo', :post, position: :after,
        params: { '_method' => 'put' }
      )
      expect(result).to be(true)
    end

    it 'exposes the order-dependent difference for the same request and token' do
      # One request, one token, two stack layouts. The override-before layout
      # evaluates the PUT action and denies; override-after evaluates POST and
      # accepts. This makes the ordering contract explicit rather than implicit.
      token = issue('/foo', method: :post)
      before = accepted?(token, '/foo', :post, position: :before,
                         params: { '_method' => 'put' })
      after  = accepted?(token, '/foo', :post, position: :after,
                         params: { '_method' => 'put' })
      expect(before).to be(false)
      expect(after).to be(true)
    end
  end

  # -------------------------------------------------------------------------
  # Security criterion: a token must never be usable across distinct actions.
  # These all use real tokens and must be denied.
  # -------------------------------------------------------------------------
  describe 'cross-action isolation' do
    [
      ['different path, same method',  '/foo',   :post, '/bar',   :post],
      ['different method, same path',  '/foo',   :put,  '/foo',   :post],
      ['put token against delete',     '/foo',   :put,  '/foo',   :delete],
      ['post token against put',       '/foo',   :post, '/foo',   :put],
      ['sibling mounted action',       '/app/foo', :post, '/app/baz', :post]
    ].each do |label, signed_path, signed_method, request_path, request_method|
      it "denies: #{label}" do
        token = issue(signed_path, method: signed_method)
        extra = request_path.start_with?('/app/') ? {
          'SCRIPT_NAME' => '/app',
          'PATH_INFO'  => request_path.sub('/app', '')
        } : {}
        expect(accepted?(token, request_path, request_method, extra_env: extra)).to be(false)
      end
    end

    it 'accepts the matching action for every token it denies a neighbor for' do
      # Soundness counterpart of the isolation checks above: the same token
      # that is rejected on a neighbor must succeed on its own action.
      post_token = issue('/foo', method: :post)
      put_token  = issue('/foo', method: :put)
      expect(accepted?(post_token, '/foo', :post)).to be(true)
      expect(accepted?(put_token, '/foo', :put)).to be(true)
    end
  end

  # -------------------------------------------------------------------------
  # Compatibility: the legacy *global* token is a separate code path and must
  # remain path/method agnostic. Per-form scoping must not change it.
  # -------------------------------------------------------------------------
  describe 'legacy global token compatibility' do
    def issue_global
      described_class.token(session) # no path/method -> global token
    end

    [
      ['/foo', :post],
      ['/bar', :put],
      ['/anything/here', :delete],
      ['/app/foo', :post]
    ].each do |request_path, request_method|
      it "global token is accepted on #{request_method.upcase} #{request_path}" do
        token = issue_global
        extra = request_path.start_with?('/app/') ? {
          'SCRIPT_NAME' => '/app', 'PATH_INFO' => request_path.sub('/app', '')
        } : {}
        expect(accepted?(token, request_path, request_method, extra_env: extra)).to be(true)
      end
    end

    it 'keeps global and per-form tokens distinct even for identical actions' do
      global   = issue_global
      per_form = issue('/foo', method: :post)

      # Both work on the action, but only the global token is reusable on a
      # different action; the per-form token is bound to "/foo#post".
      expect(accepted?(global, '/bar', :post)).to be(true)
      expect(accepted?(per_form, '/bar', :post)).to be(false)
    end

    it 'does not accept a per-form token where only the global identifier matches' do
      # A token bound to "/foo#post" must never be validated via the global
      # HMAC branch: per-form scoping and global compatibility are not conflated.
      per_form = issue('/foo', method: :post)
      expect(accepted?(per_form, '/some/other/action', :post)).to be(false)
    end
  end
end
