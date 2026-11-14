#!/usr/bin/env ruby
# frozen_string_literal: true

require 'rack/protection'
require 'rack/session/cookie'
require 'rack/mock'
require 'json'
require 'stringio'
require 'fileutils'
require 'cgi'

module JsonCsrfLab
  SECRET = 'lab-secret-' + ('0123456789abcdef' * 4)
  HOST = 'api.example'
  SELF_ORIGIN = "http://#{HOST}"
  APP_ORIGIN = 'https://app.example'

  class Ledger
    attr_accessor :app_calls, :writes, :auth, :body_each, :body_close, :session_after, :events

    def initialize
      @app_calls = 0
      @writes = []
      @auth = false
      @body_each = 0
      @body_close = 0
      @events = []
    end

    def write(kind)
      @writes << kind
      @events << [:write, kind]
    end
  end

  class RecordingBody
    def initialize(payload, ledger, on_each: nil, on_close: nil)
      @payload = payload
      @ledger = ledger
      @on_each = on_each
      @on_close = on_close
    end

    def each
      @ledger.body_each += 1
      @on_each&.call
      yield @payload
    end

    def close
      @ledger.body_close += 1
      @on_close&.call
    end
  end

  class LedgerApp
    def initialize(ledger)
      @ledger = ledger
    end

    def call(env)
      @ledger.app_calls += 1
      @ledger.events << [:app, env['REQUEST_METHOD'], env['PATH_INFO']]
      @ledger.auth = session_user(env) == 'alice'
      @ledger.session_after = env['rack.session']&.to_hash

      case env['PATH_INFO']
      when '/read'
        json('{"secret":1}')
      when '/read-uppercase'
        respond(200, { 'Content-Type' => 'application/json' }, '{"secret":1}')
      when '/html'
        respond(200, { 'content-type' => 'text/html' }, '<p>secret</p>')
      when '/plain'
        respond(200, { 'content-type' => 'text/plain' }, 'secret')
      when '/not-modified'
        respond(304, {}, '')
      when '/vendor'
        respond(200, { 'content-type' => 'application/vnd.api+json' }, '{"secret":1}')
      when '/cors'
        origin = env['HTTP_ORIGIN'].to_s
        respond(200, {
          'content-type' => 'application/json',
          'access-control-allow-origin' => origin,
          'access-control-allow-credentials' => 'true',
          'vary' => 'Origin'
        }, '{"secret":1}')
      when '/write'
        @ledger.write(:eager)
        json('{"ok":true}')
      when '/write-get'
        @ledger.write(:get)
        json('{"ok":true}')
      when '/stream-write'
        respond(200, { 'content-type' => 'application/json' }, '{"ok":true}',
                on_each: -> { @ledger.write(:stream_each) })
      when '/close-write'
        respond(200, { 'content-type' => 'application/json' }, '{"ok":true}',
                on_close: -> { @ledger.write(:close) })
      when '/write-html'
        @ledger.write(:eager)
        respond(200, { 'content-type' => 'text/html' }, '<p>ok</p>')
      when '/nocontent'
        @ledger.write(:eager)
        respond(204, {}, '')
      when '/transfer'
        unless @ledger.auth
          return respond(401, { 'content-type' => 'application/json' }, '{"error":"auth"}')
        end

        @ledger.write(:eager)
        json('{"ok":true}')
      when '/login'
        env['rack.session'][:user] = 'alice'
        respond(200, { 'content-type' => 'text/plain' }, 'login')
      when '/token'
        respond(200, { 'content-type' => 'text/plain' },
                Rack::Protection::AuthenticityToken.token(env['rack.session']))
      else
        respond(404, { 'content-type' => 'text/plain' }, 'not found')
      end
    end

    private

    def session_user(env)
      session = env['rack.session']
      session && session[:user]
    end

    def json(payload)
      respond(200, { 'content-type' => 'application/json' }, payload)
    end

    def respond(status, headers, payload, on_each: nil, on_close: nil)
      [status, headers, RecordingBody.new(payload, @ledger, on_each: on_each, on_close: on_close)]
    end
  end

  class StrictOrigin
    def initialize(app, allowed_origins)
      @app = app
      @allowed_origins = allowed_origins
    end

    def call(env)
      return @app.call(env) if %w[GET HEAD OPTIONS TRACE].include?(env['REQUEST_METHOD'])

      origin = env['HTTP_ORIGIN']
      return @app.call(env) if origin && @allowed_origins.include?(origin)

      [403, { 'content-type' => 'text/plain' }, ['Forbidden']]
    end
  end

  class Instrumenter
    attr_reader :events

    def initialize
      @events = []
    end

    def instrument(name, env)
      @events << [name, env['rack.protection.attack']]
    end
  end

  Scenario = Struct.new(
    :id, :group, :title, :method, :path, :headers, :input, :cookie,
    :stack, :stack_options, :session, :instrument, :expect,
    keyword_init: true
  )

  class Runner
    def initialize
      @auth_cookie = issue_auth_cookie
      @token = issue_token(@auth_cookie)
    end

    attr_reader :auth_cookie, :token

    def scenarios
      @scenarios ||= build_scenarios
    end

    def run
      results = scenarios.map { |scenario| invoke(scenario) }
      write_outputs(results)
      report(results)
      results.all? { |r| r[:checks].all? { |_k, v| v[:pass] } } ? 0 : 1
    end

    private

    def build_scenarios
      ref_same = { 'HTTP_REFERER' => "#{SELF_ORIGIN}/page" }
      ref_evil = { 'HTTP_REFERER' => 'https://evil.example/page' }
      origin_evil = { 'HTTP_ORIGIN' => 'https://evil.example' }
      origin_self = { 'HTTP_ORIGIN' => SELF_ORIGIN }
      xhr = { 'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest' }
      form = { 'CONTENT_TYPE' => 'application/x-www-form-urlencoded' }
      token_input = "authenticity_token=#{CGI.escape(@token)}"

      list = []
      add = ->(h) { list << Scenario.new(**h) }

      add.call(id: 'R01', group: 'read', title: 'same-host referer', method: 'GET', path: '/read',
               headers: ref_same, stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R02', group: 'read', title: 'cross-host referer', method: 'GET', path: '/read',
               headers: ref_evil, stack: :json_csrf,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 0, body_each: 0, body_close: 1 })
      add.call(id: 'R03', group: 'read', title: 'no Referer', method: 'GET', path: '/read',
               headers: {}, stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R04', group: 'read', title: 'empty Referer', method: 'GET', path: '/read',
               headers: { 'HTTP_REFERER' => '' }, stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R05', group: 'read', title: 'cross-host referer plus X-Requested-With', method: 'GET', path: '/read',
               headers: ref_evil.merge(xhr), stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R06', group: 'read', title: 'cross-host referer plus evil Origin', method: 'GET', path: '/read',
               headers: ref_evil.merge(origin_evil), stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R07', group: 'read', title: 'cross-host referer plus X-Origin', method: 'GET', path: '/read',
               headers: ref_evil.merge('HTTP_X_ORIGIN' => 'https://evil.example'), stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R08', group: 'read', title: 'same host but different scheme and port', method: 'GET', path: '/read',
               headers: { 'HTTP_REFERER' => "https://#{HOST}:8443/page" }, stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R09', group: 'read', title: 'malformed Referer', method: 'GET', path: '/read',
               headers: { 'HTTP_REFERER' => 'http://bad|uri' }, stack: :json_csrf,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 0, body_each: 0, body_close: 1 })
      add.call(id: 'R10', group: 'read', title: 'vendor JSON media type', method: 'GET', path: '/vendor',
               headers: ref_evil, stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R11', group: 'read', title: 'text/html response', method: 'GET', path: '/html',
               headers: ref_evil, stack: :json_csrf,
               expect: { status: 200, body: '<p>secret</p>', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R12', group: 'read', title: 'no Content-Type response', method: 'GET', path: '/not-modified',
               headers: ref_evil, stack: :json_csrf,
               expect: { status: 304, body: '', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R13', group: 'read', title: 'capitalized Content-Type response header', method: 'GET', path: '/read-uppercase',
               headers: ref_evil, stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R14', group: 'read', title: 'CORS reflects evil Origin with credentials', method: 'GET', path: '/cors',
               headers: origin_evil, stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1,
                         headers: { 'access-control-allow-origin' => 'https://evil.example',
                                    'access-control-allow-credentials' => 'true' } })
      add.call(id: 'R15', group: 'read', title: 'cross-host referer plus null Origin', method: 'GET', path: '/read',
               headers: ref_evil.merge('HTTP_ORIGIN' => 'null'), stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R16', group: 'read', title: 'strict Referer option with missing Referer', method: 'GET', path: '/read',
               headers: {}, stack: :json_csrf, stack_options: { allow_empty_referrer: false },
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 0, body_each: 0, body_close: 1 })

      add.call(id: 'R17', group: 'read', title: 'umbrella, evil Origin and evil referer GET', method: 'GET', path: '/read',
               headers: ref_evil.merge(origin_evil), stack: :umbrella,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R18', group: 'read', title: 'umbrella, CORS reflection on evil Origin GET', method: 'GET', path: '/cors',
               headers: origin_evil, stack: :umbrella,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1,
                         headers: { 'access-control-allow-origin' => 'https://evil.example',
                                    'access-control-allow-credentials' => 'true' } })

      add.call(id: 'R19', group: 'read', title: 'empty Origin header with evil Referer', method: 'GET', path: '/read',
               headers: ref_evil.merge('HTTP_ORIGIN' => ''), stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R20', group: 'read', title: 'lowercase xhr marker is not xhr?', method: 'GET', path: '/read',
               headers: ref_evil.merge('HTTP_X_REQUESTED_WITH' => 'xmlhttprequest'), stack: :json_csrf,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 0, body_each: 0, body_close: 1 })

      add.call(id: 'R21', group: 'read', title: 'evil Origin alone, no Referer', method: 'GET', path: '/read',
               headers: origin_evil, stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'R22', group: 'read', title: 'evil X-Origin alone, no Referer', method: 'GET', path: '/read',
               headers: { 'HTTP_X_ORIGIN' => 'https://evil.example' }, stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })

      add.call(id: 'W01', group: 'write', title: 'cross-host referer POST, eager commit', method: 'POST', path: '/write',
               headers: ref_evil.merge(form), input: 'amount=100', stack: :json_csrf,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 1, body_each: 0, body_close: 1 })
      add.call(id: 'W02', group: 'write', title: 'no Referer POST, eager commit', method: 'POST', path: '/write',
               headers: form, input: 'amount=100', stack: :json_csrf,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })
      add.call(id: 'W03', group: 'write', title: 'evil Origin POST, JsonCsrf alone', method: 'POST', path: '/write',
               headers: origin_evil.merge(form), input: 'amount=100', stack: :json_csrf,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })
      add.call(id: 'W04', group: 'write', title: 'authenticated POST with evil referer', method: 'POST', path: '/transfer',
               headers: ref_evil.merge(form), input: 'amount=100', cookie: @auth_cookie, stack: :json_csrf,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 1, auth: true, body_each: 0, body_close: 1 })
      add.call(id: 'W05', group: 'write', title: 'authenticated POST without Referer', method: 'POST', path: '/transfer',
               headers: form, input: 'amount=100', cookie: @auth_cookie, stack: :json_csrf,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: true, body_each: 1, body_close: 1 })
      add.call(id: 'W06', group: 'write', title: 'streaming body, write deferred to each', method: 'POST', path: '/stream-write',
               headers: ref_evil.merge(form), input: 'amount=100', stack: :json_csrf,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 0, body_each: 0, body_close: 1 })
      add.call(id: 'W07', group: 'write', title: 'body close performs the write', method: 'POST', path: '/close-write',
               headers: ref_evil.merge(form), input: 'amount=100', stack: :json_csrf,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 1, body_each: 0, body_close: 1 })
      add.call(id: 'W08', group: 'write', title: 'HTML response, eager commit', method: 'POST', path: '/write-html',
               headers: ref_evil.merge(form), input: 'amount=100', stack: :json_csrf,
               expect: { status: 200, body: '<p>ok</p>', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })
      add.call(id: 'W09', group: 'write', title: '204 response, eager commit', method: 'POST', path: '/nocontent',
               headers: ref_evil.merge(form), input: 'amount=100', stack: :json_csrf,
               expect: { status: 204, body: '', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })
      add.call(id: 'W10', group: 'write', title: 'reaction report on JsonCsrf', method: 'POST', path: '/write',
               headers: ref_evil.merge(form), input: 'amount=100', stack: :json_csrf,
               stack_options: { reaction: :report },
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 1, flag: nil, body_each: 0, body_close: 1 })
      add.call(id: 'W11', group: 'write', title: 'reaction drop_session on JsonCsrf', method: 'POST', path: '/write',
               headers: ref_evil.merge(form), input: 'amount=100', stack: :json_csrf,
               stack_options: { reaction: :drop_session }, session: true,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 1, body_each: 0, body_close: 1 })
      add.call(id: 'W12', group: 'write', title: 'umbrella default, evil Origin', method: 'POST', path: '/write',
               headers: origin_evil.merge(form), input: 'amount=100', cookie: @auth_cookie, stack: :umbrella,
               expect: { status: 403, body: 'Forbidden', app_calls: 0, writes: 0, auth: false, body_each: 0, body_close: 0 })
      add.call(id: 'W13', group: 'write', title: 'umbrella default, evil referer no Origin', method: 'POST', path: '/write',
               headers: ref_evil.merge(form), input: 'amount=100', cookie: @auth_cookie, stack: :umbrella,
               expect: { status: 403, body: 'Forbidden', app_calls: 0, writes: 0, auth: false, body_each: 0, body_close: 0 })
      add.call(id: 'W14', group: 'write', title: 'umbrella default, no Origin no Referer', method: 'POST', path: '/write',
               headers: form, input: 'amount=100', cookie: @auth_cookie, stack: :umbrella,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: true, body_each: 1, body_close: 1 })
      add.call(id: 'W15', group: 'write', title: 'umbrella report mode, evil Origin', method: 'POST', path: '/write',
               headers: origin_evil.merge(form), input: 'amount=100', cookie: @auth_cookie, stack: :umbrella,
               stack_options: { reaction: :report },
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: true, flag: true, body_each: 1, body_close: 1 })
      add.call(id: 'W16', group: 'write', title: 'umbrella report mode, evil referer no Origin', method: 'POST', path: '/write',
               headers: ref_evil.merge(form), input: 'amount=100', cookie: @auth_cookie, stack: :umbrella,
               stack_options: { reaction: :report },
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 1, auth: true, flag: true, body_each: 0, body_close: 1 })
      add.call(id: 'W17', group: 'write', title: 'StrictOrigin pre-app, evil Origin', method: 'POST', path: '/write',
               headers: origin_evil.merge(form), input: 'amount=100', stack: :strict_origin,
               expect: { status: 403, body: 'Forbidden', app_calls: 0, writes: 0, body_each: 0, body_close: 0 })
      add.call(id: 'W18', group: 'write', title: 'StrictOrigin pre-app, missing Origin', method: 'POST', path: '/write',
               headers: form, input: 'amount=100', stack: :strict_origin,
               expect: { status: 403, body: 'Forbidden', app_calls: 0, writes: 0, body_each: 0, body_close: 0 })
      add.call(id: 'W19', group: 'write', title: 'StrictOrigin pre-app, same Origin', method: 'POST', path: '/write',
               headers: origin_self.merge(form), input: 'amount=100', stack: :strict_origin,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })
      add.call(id: 'W20', group: 'write', title: 'AuthenticityToken, no token', method: 'POST', path: '/transfer',
               headers: form, input: 'amount=100', cookie: @auth_cookie, stack: :authenticity_token,
               expect: { status: 403, body: 'Forbidden', app_calls: 0, writes: 0, auth: false, body_each: 0, body_close: 0 })
      add.call(id: 'W21', group: 'write', title: 'AuthenticityToken, valid token', method: 'POST', path: '/transfer',
               headers: form, input: token_input, cookie: @auth_cookie, stack: :authenticity_token,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: true, body_each: 1, body_close: 1 })
      add.call(id: 'W22', group: 'write', title: 'FormToken, XHR header bypasses token', method: 'POST', path: '/transfer',
               headers: form.merge(xhr), input: 'amount=100', cookie: @auth_cookie, stack: :form_token,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: true, body_each: 1, body_close: 1 })
      add.call(id: 'W23', group: 'write', title: 'RemoteToken, missing Referer', method: 'POST', path: '/transfer',
               headers: form, input: 'amount=100', cookie: @auth_cookie, stack: :remote_token,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: true, body_each: 1, body_close: 1 })
      add.call(id: 'W24', group: 'write', title: 'RemoteToken, evil Referer', method: 'POST', path: '/transfer',
               headers: ref_evil.merge(form), input: 'amount=100', cookie: @auth_cookie, stack: :remote_token,
               expect: { status: 403, body: 'Forbidden', app_calls: 0, writes: 0, auth: false, body_each: 0, body_close: 0 })
      add.call(id: 'W25', group: 'write', title: 'RemoteToken, evil Origin but missing Referer', method: 'POST', path: '/transfer',
               headers: origin_evil.merge(form), input: 'amount=100', cookie: @auth_cookie, stack: :remote_token,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: true, body_each: 1, body_close: 1 })
      add.call(id: 'W26', group: 'write', title: 'umbrella without session, same Origin', method: 'POST', path: '/transfer',
               headers: origin_self.merge(form), input: 'amount=100', cookie: nil, stack: :umbrella, session: false,
               expect: { status: 401, body: '{"error":"auth"}', app_calls: 1, writes: 0, auth: false, body_each: 1, body_close: 1 })

      add.call(id: 'W27', group: 'write', title: 'umbrella default, X-Origin evil no Referer', method: 'POST', path: '/write',
               headers: { 'HTTP_X_ORIGIN' => 'https://evil.example' }.merge(form), input: 'amount=100',
               cookie: @auth_cookie, stack: :umbrella,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: true, body_each: 1, body_close: 1 })
      add.call(id: 'W28', group: 'write', title: 'JsonCsrf alone, X-Origin evil no Referer', method: 'POST', path: '/write',
               headers: { 'HTTP_X_ORIGIN' => 'https://evil.example' }.merge(form), input: 'amount=100',
               cookie: @auth_cookie, stack: :json_csrf,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: true, body_each: 1, body_close: 1 })
      add.call(id: 'W29', group: 'write', title: 'umbrella default, null Origin POST', method: 'POST', path: '/write',
               headers: { 'HTTP_ORIGIN' => 'null' }.merge(form), input: 'amount=100',
               cookie: @auth_cookie, stack: :umbrella,
               expect: { status: 403, body: 'Forbidden', app_calls: 0, writes: 0, auth: false, body_each: 0, body_close: 0 })
      add.call(id: 'W30', group: 'write', title: 'umbrella default, evil referer plus same-host Origin', method: 'POST', path: '/write',
               headers: ref_evil.merge(origin_self).merge(form), input: 'amount=100',
               cookie: @auth_cookie, stack: :umbrella,
               expect: { status: 403, body: 'Forbidden', app_calls: 0, writes: 0, auth: false, body_each: 0, body_close: 0 })
      add.call(id: 'W31', group: 'write', title: 'HttpOrigin alone, evil referer plus same-host Origin', method: 'POST', path: '/write',
               headers: ref_evil.merge(origin_self).merge(form), input: 'amount=100',
               cookie: @auth_cookie, stack: :http_origin,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: true, body_each: 1, body_close: 1 })

      add.call(id: 'W32', group: 'write', title: 'umbrella, valid token plus evil referer', method: 'POST', path: '/transfer',
               headers: ref_evil.merge(form), input: token_input, cookie: @auth_cookie, stack: :umbrella,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 1, auth: true, body_each: 0, body_close: 1 })
      add.call(id: 'W33', group: 'write', title: 'umbrella drop_session, evil Origin', method: 'POST', path: '/write',
               headers: origin_evil.merge(form), input: 'amount=100', cookie: @auth_cookie, stack: :umbrella,
               stack_options: { reaction: :drop_session },
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: false, body_each: 1, body_close: 1 })
      add.call(id: 'W34', group: 'write', title: 'JsonCsrf allow_if true, evil referer', method: 'POST', path: '/write',
               headers: ref_evil.merge(form), input: 'amount=100', stack: :json_csrf,
               stack_options: { allow_if: ->(_env) { true } },
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })

      add.call(id: 'W35', group: 'write', title: 'Sinatra-like drop_session, no session, evil Origin', method: 'POST', path: '/write',
               headers: origin_evil.merge(form), input: 'amount=100', stack: :umbrella, session: false,
               stack_options: { reaction: :drop_session, without_session: true },
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: false, body_each: 1, body_close: 1 })
      add.call(id: 'W36', group: 'write', title: 'HttpOrigin alone, missing Origin, evil Referer', method: 'POST', path: '/write',
               headers: ref_evil.merge(form), input: 'amount=100', stack: :http_origin,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })
      add.call(id: 'W37', group: 'write', title: 'JsonCsrf strict Referer, missing Referer POST', method: 'POST', path: '/write',
               headers: form, input: 'amount=100', stack: :json_csrf,
               stack_options: { allow_empty_referrer: false },
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 1, body_each: 0, body_close: 1 })
      add.call(id: 'W38', group: 'write', title: 'state-changing GET with evil Referer', method: 'GET', path: '/write-get',
               headers: ref_evil, stack: :json_csrf,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 1, body_each: 0, body_close: 1 })
      add.call(id: 'W39', group: 'write', title: 'HttpOrigin alone, missing Origin, no Referer', method: 'POST', path: '/write',
               headers: form, input: 'amount=100', stack: :http_origin,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })
      add.call(id: 'W40', group: 'write', title: 'umbrella drop_session, evil Origin, auth-gated endpoint', method: 'POST', path: '/transfer',
               headers: origin_evil.merge(form), input: 'amount=100', cookie: @auth_cookie, stack: :umbrella,
               stack_options: { reaction: :drop_session },
               expect: { status: 401, body: '{"error":"auth"}', app_calls: 1, writes: 0, auth: false, body_each: 1, body_close: 1 })

      add.call(id: 'W41', group: 'write', title: 'JsonCsrf alone, null Origin POST', method: 'POST', path: '/write',
               headers: { 'HTTP_ORIGIN' => 'null' }.merge(form), input: 'amount=100', stack: :json_csrf,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })
      add.call(id: 'W42', group: 'write', title: 'JsonCsrf alone, empty Origin POST', method: 'POST', path: '/write',
               headers: { 'HTTP_ORIGIN' => '' }.merge(form), input: 'amount=100', stack: :json_csrf,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })
      add.call(id: 'W43', group: 'write', title: 'state-changing GET with same-host Referer', method: 'GET', path: '/write-get',
               headers: ref_same, stack: :json_csrf,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })
      add.call(id: 'W44', group: 'write', title: 'state-changing GET without Referer', method: 'GET', path: '/write-get',
               headers: {}, stack: :json_csrf,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })
      add.call(id: 'W45', group: 'write', title: 'state-changing GET with evil Referer plus Origin', method: 'GET', path: '/write-get',
               headers: ref_evil.merge(origin_evil), stack: :json_csrf,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, body_each: 1, body_close: 1 })

      add.call(id: 'N01', group: 'navigation', title: 'top-level cross-site GET', method: 'GET', path: '/read',
               headers: ref_evil.merge('HTTP_ACCEPT' => 'text/html'), stack: :json_csrf,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 0, body_each: 0, body_close: 1 })
      add.call(id: 'N02', group: 'navigation', title: 'top-level GET without Referer', method: 'GET', path: '/read',
               headers: { 'HTTP_ACCEPT' => 'text/html' }, stack: :json_csrf,
               expect: { status: 200, body: '{"secret":1}', app_calls: 1, writes: 0, body_each: 1, body_close: 1 })
      add.call(id: 'N03', group: 'navigation', title: 'top-level cross-site form POST', method: 'POST', path: '/transfer',
               headers: ref_evil.merge(form).merge('HTTP_ACCEPT' => 'text/html'), input: 'amount=100',
               cookie: @auth_cookie, stack: :json_csrf,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 1, auth: true, body_each: 0, body_close: 1 })
      add.call(id: 'N04', group: 'navigation', title: 'top-level form POST without Referer', method: 'POST', path: '/transfer',
               headers: form.merge('HTTP_ACCEPT' => 'text/html'), input: 'amount=100', cookie: @auth_cookie,
               stack: :json_csrf,
               expect: { status: 200, body: '{"ok":true}', app_calls: 1, writes: 1, auth: true, body_each: 1, body_close: 1 })

      add.call(id: 'D01', group: 'diagnostics', title: 'JsonCsrf instrumentation on deny', method: 'GET', path: '/read',
               headers: ref_evil, stack: :json_csrf, instrument: true,
               expect: { status: 403, body: 'Forbidden', app_calls: 1, writes: 0, instrument_events: [], attack_key: nil,
                         body_each: 0, body_close: 1 })
      add.call(id: 'D02', group: 'diagnostics', title: 'HttpOrigin instrumentation on deny', method: 'POST', path: '/read',
               headers: origin_evil, stack: :http_origin, instrument: true,
               expect: { status: 403, body: 'Forbidden', app_calls: 0, writes: 0,
                         instrument_events: [['rack.protection', 'httporigin']], attack_key: 'httporigin',
                         body_each: 0, body_close: 0 })

      list
    end

    def issue_auth_cookie
      ledger = Ledger.new
      app = Rack::Session::Cookie.new(
        Rack::Protection::AuthenticityToken.new(LedgerApp.new(ledger), logging: false),
        secret: SECRET
      )
      env = Rack::MockRequest.env_for("#{SELF_ORIGIN}/login")
      env['rack.errors'] = StringIO.new
      _status, headers, body = app.call(env)
      body.each { |_chunk| }
      body.close if body.respond_to?(:close)
      Array(headers['set-cookie']).join("\n")[/rack\.session=[^;]+/]
    end

    def issue_token(cookie)
      ledger = Ledger.new
      app = Rack::Session::Cookie.new(LedgerApp.new(ledger), secret: SECRET)
      env = Rack::MockRequest.env_for("#{SELF_ORIGIN}/token")
      env['HTTP_COOKIE'] = cookie
      env['rack.errors'] = StringIO.new
      status, _headers, body = app.call(env)
      raise "token endpoint returned #{status}" unless status == 200

      chunks = []
      body.each { |chunk| chunks << chunk }
      body.close if body.respond_to?(:close)
      chunks.join
    end

    def build_stack(inner, scenario)
      options = { logging: false }.merge(scenario.stack_options || {})
      instrumenter = scenario.instrument ? Instrumenter.new : nil
      options[:instrumenter] = instrumenter if instrumenter

      stack = case scenario.stack
              when :none
                inner
              when :json_csrf
                Rack::Protection::JsonCsrf.new(inner, options)
              when :http_origin
                Rack::Protection::HttpOrigin.new(inner, options.merge(permitted_origins: [APP_ORIGIN]))
              when :authenticity_token
                Rack::Protection::AuthenticityToken.new(inner, options)
              when :form_token
                Rack::Protection::FormToken.new(inner, options)
              when :remote_token
                Rack::Protection::RemoteToken.new(inner, options)
              when :umbrella
                Rack::Protection.new(inner, options)
              when :strict_origin
                StrictOrigin.new(inner, [SELF_ORIGIN, APP_ORIGIN])
              else
                raise "unknown stack #{scenario.stack.inspect}"
              end
      [stack, instrumenter]
    end

    def invoke(scenario)
      ledger = Ledger.new
      inner = LedgerApp.new(ledger)
      stack, instrumenter = build_stack(inner, scenario)
      app = scenario.session == false ? stack : Rack::Session::Cookie.new(stack, secret: SECRET)

      env = Rack::MockRequest.env_for(
        "#{SELF_ORIGIN}#{scenario.path}",
        method: scenario.method,
        input: scenario.input.to_s
      )
      scenario.headers.each { |key, value| env[key] = value }
      env['HTTP_COOKIE'] = scenario.cookie if scenario.cookie
      env['rack.errors'] = StringIO.new

      status = nil
      headers = {}
      chunks = []
      error = nil
      begin
        status, headers, body = app.call(env)
        body.each { |chunk| chunks << chunk } if body.respond_to?(:each)
        body.close if body.respond_to?(:close)
      rescue StandardError => e
        error = "#{e.class}: #{e.message}"
      end

      actual = {
        status: status,
        body: chunks.join,
        app_calls: ledger.app_calls,
        writes: ledger.writes.size,
        side_effects: ledger.writes,
        events: ledger.events,
        auth: ledger.auth,
        body_each: ledger.body_each,
        body_close: ledger.body_close,
        flag: env['protection.failed'],
        instrument_events: instrumenter&.events,
        attack_key: env['rack.protection.attack'],
        error: error
      }

      checks = scenario.expect.each_with_object({}) do |(key, expected), memo|
        observed = if key == :headers
                      expected.each_with_object({}) do |(name, _value), h|
                        h[name] = headers[name]
                      end
                    else
                      actual[key]
                    end
        ok = if key == :headers
               expected.all? { |name, value| headers[name] == value }
             else
               observed == expected
             end
        memo[key] = { expected: expected, observed: observed, pass: ok }
      end

      {
        id: scenario.id, group: scenario.group, title: scenario.title,
        method: scenario.method, path: scenario.path, stack: scenario.stack,
        stack_options: scenario.stack_options,
        actual: actual,
        response_headers: headers.to_h,
        checks: checks
      }
    end

    def write_outputs(results)
      FileUtils.mkdir_p(File.join(__dir__, 'results'))
      File.write(File.join(__dir__, 'results', 'latest.json'), JSON.pretty_generate(results))

      lines = []
      lines << '# JsonCsrf offline Rack experiment results'
      lines << ''
      lines << "Generated by `security/json-csrf-lab/harness.rb` against rack-protection #{Rack::Protection::VERSION} and Rack #{Rack::RELEASE}."
      lines << ''
      lines << '| id | group | title | method | path | stack | status | app_calls | writes | body_each | body_close | flag |'
      lines << '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |'
      results.each do |result|
        a = result[:actual]
        lines << format('| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |',
                        result[:id], result[:group], result[:title], result[:method], result[:path],
                        result[:stack], a[:status], a[:app_calls], a[:writes], a[:body_each],
                        a[:body_close], a[:flag].inspect)
      end
      lines << ''
      lines << '`writes` counts committed application-side effects. `body_each` is 1 only if the response body was actually enumerated. `body_close` is 1 if the body was closed, which can itself run application cleanup code.'
      File.write(File.join(__dir__, 'results', 'latest.md'), lines.join("\n") + "\n")
    end

    def report(results)
      failures = 0
      results.each do |result|
        failed = result[:checks].reject { |_key, check| check[:pass] }
        next if failed.empty?

        failures += 1
        puts "FAIL #{result[:id]} #{result[:title]}"
        failed.each do |key, check|
          puts "  #{key}: expected #{check[:expected].inspect}, observed #{check[:observed].inspect}"
        end
      end
      errors = results.select { |result| result[:actual][:error] }
      errors.each { |result| puts "ERROR #{result[:id]}: #{result[:actual][:error]}" }
      puts "#{results.size} scenarios, #{failures} expectation mismatches, #{errors.size} runtime errors"
    end
  end
end

exit JsonCsrfLab::Runner.new.run if $PROGRAM_NAME == __FILE__
