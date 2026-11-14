# frozen_string_literal: true

require "cgi"
require "rack"
require "securerandom"

# Fully in-process demo application. No network listener is required;
# measurements drive it through Rack::MockRequest.
module SidechannelLab
  # Fixed *fake* secret that lives in every sensitive HTML response.
  SECRET_TOKEN = "AKIA-FAKE-9XQZ-TKN-2026-k7v2m9p4".freeze
  TOKEN_LEN = SECRET_TOKEN.length

  # Fixed Last-Modified makes gzip header mtime deterministic, so byte
  # sizes are reproducible run to run.
  FIXED_LAST_MODIFIED = "Wed, 21 Oct 2015 07:28:00 GMT"

  FILLER = <<~HTML.gsub(/\s+/, " ").strip
    <p>Quarterly billing notes: the operations team reviewed recurring
    subscription line items, reconciled vendor invoices against purchase
    orders, and confirmed that regional tax tables were refreshed before the
    reporting window closed. Analysts flagged two legacy discount schedules
    for renewal review and attached the supporting spreadsheets to the
    audit work-package for the compliance team.</p>
  HTML

  ALPHABET = (("A".."Z").to_a + ("0".."9").to_a + %w[- _]).freeze

  module Pages
    module_function

    def h(text)
      CGI.escapeHTML(text.to_s)
    end

    # Secret and attacker-influenced text in the SAME compressible response.
    def co_located(echo, repeats)
      reflected = (h(echo) + " ") * repeats
      <<~HTML
        <!doctype html><html><head><title>Account settings</title></head><body>
        <h1>Account settings</h1>
        <form method="post" action="/change">
          <input type="hidden" name="csrf_token" value="#{SECRET_TOKEN}">
          <input type="hidden" name="session_hint" value="stable-page-fragment-2026">
          #{"<p>#{FILLER}</p>" * 3}
          <section class="reflected" data-echo="#{reflected.strip}">
            <h2>Search preview</h2>
            <p>You searched for: #{reflected.strip}</p>
          </section>
          #{"<p>#{FILLER}</p>" * 3}
        </form></body></html>
      HTML
    end

    # Same response, but secret and reflection are separated by padding.
    # mode=fixed uses identical bytes per response; mode=random regenerates.
    def separated(echo, repeats, mode, padding_bytes)
      reflected = (h(echo) + " ") * repeats
      padding =
        if mode == "random"
          Array.new(padding_bytes) { ALPHABET.sample }.join
        else
          ("Z" * padding_bytes)
        end
      <<~HTML
        <!doctype html><html><body>
        <input type="hidden" name="csrf_token" value="#{SECRET_TOKEN}">
        <pre class="padding">#{padding}</pre>
        #{"<p>#{FILLER}</p>" * 2}
        <section class="reflected"><p>You searched for: #{reflected.strip}</p></section>
        </body></html>
      HTML
    end

    def token_only
      <<~HTML
        <!doctype html><html><body>
        <input type="hidden" name="csrf_token" value="#{SECRET_TOKEN}">
        #{"<p>#{FILLER}</p>" * 4}
        </body></html>
      HTML
    end

    def echo_only(echo, repeats)
      reflected = (h(echo) + " ") * repeats
      <<~HTML
        <!doctype html><html><body>
        #{"<p>#{FILLER}</p>" * 4}
        <section class="reflected"><p>You searched for: #{reflected.strip}</p></section>
        </body></html>
      HTML
    end

    # A compressible public asset (no secret, no reflection).
    def public_js
      lines = [
        "// public bundle v2026.11 - no secrets, cacheable",
        "function formatInvoiceLine(row) {",
        "  const amount = Number(row.amount).toFixed(2);",
        "  const tax = applyRegionalTaxTable(amount, row.region);",
        "  return { label: row.label, amount, tax, total: amount + tax };",
        "}",
        "function applyRegionalTaxTable(amount, region) {",
        "  const table = DEFAULT_TAX_TABLES[region] || DEFAULT_TAX_TABLES.OTHER;",
        "  return roundCurrency(amount * table.rate + table.surcharge);",
        "}",
        "function roundCurrency(value) { return Math.round(value * 100) / 100; }",
      ]
      (lines * 12).join("\n") + "\n"
    end
  end

  # Rack body object that yields the document in +chunk_count+ pieces,
  # simulating a streaming/SSE-style producer.
  class ChunkedBody
    def initialize(document, chunk_count)
      @chunks = split_evenly(document, chunk_count)
    end

    def each(&block)
      @chunks.each(&block)
    end

    def split_evenly(document, chunk_count)
      step = (document.bytesize / chunk_count.to_f).ceil
      document.each_char.each_slice(step).map(&:join).reject(&:empty?)
    end
  end

  class App
    SENSITIVE_PATHS = %w[/reflection /separate /stream /token-only].freeze

    def call(env)
      req = Rack::Request.new(env)
      q = req.GET
      echo = q["echo"].to_s
      repeats = (q["repeats"] || "64").to_i
      chunks = (q["chunks"] || "8").to_i

      case req.path
      when "/"
        ok("text/plain", ["sidechannel lab: see /reflection, /separate, /stream, /token-only, /echo-only, /public/app.js\n"])
      when "/reflection"
        doc = Pages.co_located(echo, repeats)
        ok("text/html; charset=utf-8", doc, sensitive: true)
      when "/separate"
        doc = Pages.separated(echo, repeats, q["mode"] || "random", (q["pad"] || "4096").to_i)
        ok("text/html; charset=utf-8", doc, sensitive: true)
      when "/stream"
        doc = Pages.co_located(echo, repeats)
        ok("text/html; charset=utf-8", ChunkedBody.new(doc, chunks), sensitive: true)
      when "/token-only"
        ok("text/html; charset=utf-8", Pages.token_only, sensitive: true)
      when "/echo-only"
        ok("text/html; charset=utf-8", Pages.echo_only(echo, repeats), sensitive: false)
      when "/public/app.js"
        ok("application/javascript; charset=utf-8", Pages.public_js, sensitive: false, cacheable: true)
      else
        [404, { "content-type" => "text/plain" }, ["not found\n"]]
      end
    end

    private

    def ok(content_type, body, sensitive:, cacheable: false)
      body = [body] if body.is_a?(String)
      headers = {
        "content-type" => content_type,
        "last-modified" => FIXED_LAST_MODIFIED,
      }
      headers["x-sensitive"] = "1" if sensitive
      headers["cache-control"] = cacheable ? "public, max-age=3600" : "private, no-store"
      [200, headers, body]
    end
  end
end
