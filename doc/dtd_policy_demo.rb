# frozen_string_literal: false

# Demonstration of the REXML DOCTYPE declaration admission policy.
#
# Run with:
#   ruby -Ilib doc/dtd_policy_demo.rb
#
# Scenario:
#   * External/partner input must never carry a DTD -> parse it with
#     `disallow_dtd: true`.
#   * Internal/trusted input still relies on internal entities and default
#     attributes -> parse it with the default policy (`false`).
#
# Each entry below is fed through a real pipe one small fragment at a time, so
# the "<!DOCTYPE" token can be split across reads. The output shows exactly
# where each entry refuses the DTD and which callbacks had already run.

require "rexml/document"
require "rexml/parsers/pullparser"
require "rexml/parsers/sax2parser"
require "rexml/sax2listener"
require "rexml/streamlistener"

# A document whose DTD would both define an entity and a default attribute.
EXTERNAL_INPUT = <<~XML.freeze
  <?xml version="1.0"?>
  <!DOCTYPE memo [
    <!ENTITY stamp "TRUSTED-ENTITY-TEXT">
    <!ATTLIST memo priority CDATA "normal">
  ]>
  <memo>&stamp;</memo>
XML

# DTD-looking text hidden in comments/CDATA must never be mistaken for a DTD.
LOOKALIKE_INPUT = <<~XML.freeze
  <memo>
    <!-- <!DOCTYPE not-a-real-declaration [<!ENTITY x "no">]> -->
    <![CDATA[<!DOCTYPE also-not-real SYSTEM "urn:x">]]>
    body
  </memo>
XML

# Delivers `xml` over a pipe in fixed-size fragments, simulating a streaming
# transport whose packet boundaries do not line up with markup tokens.
def fragmented(xml, fragment_size)
  reader, writer = IO.pipe
  Thread.new do
    begin
      xml.chars.each_slice(fragment_size) do |fragment|
        writer.write(fragment.join)
        writer.flush
      end
    rescue Errno::EPIPE
      # The reader may stop as soon as it rejects the declaration.
    ensure
      writer.close rescue nil
    end
  end
  reader
end

def heading(title)
  puts
  puts "=" * 72
  puts title
  puts "=" * 72
end

heading "1) Document (tree) entry -- external input, disallow_dtd: true"
io = fragmented(EXTERNAL_INPUT, 4)
begin
  REXML::Document.new(io, disallow_dtd: true)
  puts "  unexpected: DTD was accepted"
rescue REXML::ParseException => error
  puts "  rejected with: #{error.message.lines.first.chomp}"
  puts "  no tree is returned, so no default attribute or entity expansion"
  puts "  could ever be observed by the caller."
ensure
  io.close
end

heading "2) PullParser entry -- events available before the refusal"
io = fragmented(EXTERNAL_INPUT, 3)
pull_parser = REXML::Parsers::PullParser.new(io, disallow_dtd: true)
seen_events = []
begin
  seen_events << pull_parser.pull.event_type while pull_parser.has_next?
rescue REXML::ParseException => error
  puts "  events already pulled: #{seen_events.inspect}"
  puts "  rejected with: #{error.message.lines.first.chomp}"
  puts "  note: :start_doctype, :entitydecl and :attlistdecl never appear,"
  puts "  so the DTD has not declared anything when the error is raised."
ensure
  io.close
end

heading "3) SAX2Parser entry -- callbacks already fired before the refusal"
class DemoSAX2Listener
  include REXML::SAX2Listener
  attr_reader :callbacks
  def initialize; @callbacks = []; end
  def start_document; @callbacks << :start_document; end
  def xmldecl(*);     @callbacks << :xmldecl; end
  def doctype(*);     @callbacks << :doctype; end
  def entitydecl(*);  @callbacks << :entitydecl; end
  def attlistdecl(*); @callbacks << :attlistdecl; end
  def start_element(*); @callbacks << :start_element; end
  def characters(*);  @callbacks << :characters; end
end
io = fragmented(EXTERNAL_INPUT, 5)
sax_listener = DemoSAX2Listener.new
sax_parser = REXML::Parsers::SAX2Parser.new(io, disallow_dtd: true)
sax_parser.listen(sax_listener)
begin
  sax_parser.parse
rescue REXML::ParseException => error
  puts "  callbacks fired: #{sax_listener.callbacks.inspect}"
  puts "  rejected with: #{error.message.lines.first.chomp}"
  puts "  only prologue/whitespace callbacks ran; no :doctype,"
  puts "  :entitydecl, :attlistdecl or :start_element callback ran."
ensure
  io.close
end

heading "4) StreamParser entry -- StreamListener callbacks before refusal"
class DemoStreamListener
  include REXML::StreamListener
  attr_reader :callbacks
  def initialize; @callbacks = []; end
  def xmldecl(*);    @callbacks << :xmldecl; end
  def doctype(*);    @callbacks << :doctype; end
  def entitydecl(*); @callbacks << :entitydecl; end
  def tag_start(*);  @callbacks << :tag_start; end
  def text(*);       @callbacks << :text; end
end
io = fragmented(EXTERNAL_INPUT, 6)
stream_listener = DemoStreamListener.new
begin
  REXML::Document.parse_stream(io, stream_listener, disallow_dtd: true)
rescue REXML::ParseException => error
  puts "  callbacks fired: #{stream_listener.callbacks.inspect}"
  puts "  rejected with: #{error.message.lines.first.chomp}"
ensure
  io.close
end

heading "5) Lookalike text in comments/CDATA is never rejected"
io = fragmented(LOOKALIKE_INPUT, 5)
begin
  document = REXML::Document.new(io, disallow_dtd: true)
  puts "  parsed cleanly; doctype present? #{!document.doctype.nil?}"
  puts "  CDATA preserved: #{document.root.cdatas.first.value.inspect}"
ensure
  io.close
end

heading "6) Internal/trusted input keeps full DTD capabilities (default)"
trusted = REXML::Document.new(EXTERNAL_INPUT)
puts "  doctype present? #{!trusted.doctype.nil?}"
puts "  internal entity expanded: #{trusted.root.text.inspect}"
puts "  ATTLIST default attribute applied: #{trusted.root.attributes['priority'].inspect}"

heading "7) The two policies never interfere when parsing both sources"
begin
  REXML::Parsers::BaseParser.new(EXTERNAL_INPUT, disallow_dtd: true).pull
rescue REXML::ParseException
  puts "  external parser: DTD rejected"
end
internal_parser = REXML::Parsers::BaseParser.new(EXTERNAL_INPUT)
events = []
events << internal_parser.pull[0] until events.include?(:start_doctype)
puts "  internal parser disallow_dtd? #{internal_parser.disallow_dtd?}; " \
     "reached events: #{events.inspect}"

puts
puts "Safe-use rule"
puts "-" * 72
puts "Treat a result as usable only when the parse completes without raising."
puts "On REXML::ParseException, discard any partially collected events/tree:"
puts "DTD-related callbacks and entity/default-attribute effects have not run,"
puts "while harmless prologue events (e.g. xmldecl) may already have fired."
