# frozen_string_literal: true
#
# Reproduction: internal DTD default attribute turning an absent
# "approved" field into a readable authorization value in REXML.
#
# Run:  ruby security/dtd-default-attributes/reproduce.rb
#
# Environment observed: REXML 3.4.4 (gem), CRuby 4.0.7.
# The behavior is the DOM-level DTD fallback implemented in
# REXML::Attributes#get_attribute (lib/rexml/element.rb), not a parser
# injection: raw parser events only ever carry explicit attributes.

require "rexml/document"
require "rexml/parsers/baseparser"
require "rexml/parsers/sax2parser"
require "rexml/parsers/streamparser"
require "rexml/parsers/pullparser"
require "rexml/streamlistener"
require "rexml/formatters/default"

# The caller submits NO approved attribute on either element. The only place
# "approved" appears is the internal DTD subset, which REXML accepts by
# default (no external network access is needed).
ATTACK_XML = <<~XML.freeze
  <?xml version="1.0"?>
  <!DOCTYPE import [
    <!ELEMENT import (record*)>
    <!ELEMENT record EMPTY>
    <!ATTLIST record
      id       CDATA #REQUIRED
      approved CDATA "true"
      display  CDATA "guest"
      fixedv   CDATA #FIXED "locked">
  ]>
  <import>
    <record id="r1"/>
    <record id="r2" approved="false"/>
  </import>
XML

def heading(title)
  puts "\n" + ("=" * 72)
  puts title
  puts "=" * 72
end

def show(label, value)
  puts format("  %-42s # %s", label, value.inspect)
end

heading "Stage 0 - Raw input"
puts ATTACK_XML
puts "Substring 'approved' occurs only inside the ATTLIST declaration;"
puts "the <record id='r1'/> start tag itself carries no approved attribute."

heading "Stage 1 - Parser events (the explicit-attribute boundary)"
puts "BaseParser / StreamParser / SAX2Parser / PullParser start_element events:"
base = REXML::Parsers::BaseParser.new(REXML::Source.new(+ATTACK_XML))
loop do
  event = base.pull
  if event[0] == :start_element && event[1] == "record"
    show("BaseParser event[2] for #{event[2]['id']}", event[2])
  end
  break if event[0] == :end_document
end

sax = REXML::Parsers::SAX2Parser.new(ATTACK_XML)
sax.listen(:start_element) do |_uri, _local, qname, attrs|
  show("SAX2 start_element #{qname} attrs", attrs) if qname == "record"
end
sax.parse

class DemoListener
  include REXML::StreamListener
  def tag_start(name, attrs)
    puts format("  %-42s # %s", "StreamParser tag_start #{name} attrs", attrs.inspect) \
      if name == "record"
  end
end
REXML::Parsers::StreamParser.new(ATTACK_XML, DemoListener.new).parse

pull = REXML::Parsers::PullParser.new(ATTACK_XML)
while pull.has_next?
  event = pull.pull
  next unless event.event_type == :start_element && event[0] == "record"
  show("PullParser record attr hash", event[1])
end
puts "=> Every event parser reports only explicit attributes; the DTD"
puts "   default is never injected into an event."

heading "Stage 2 - DOM queries on r1 (no explicit approved)"
doc = REXML::Document.new(ATTACK_XML)
r1 = REXML::XPath.first(doc, "//record[@id='r1']")
attrs = r1.attributes

show("r1.attributes['approved']  (Attributes#[])", attrs["approved"])
show("r1['approved']             (Element#[] -> [])", r1["approved"])
show("r1.attribute('approved')   (Element#attribute)", r1.attribute("approved")&.to_s)
show("attrs.get_attribute('approved')", attrs.get_attribute("approved")&.to_s)
puts "  ---- interfaces that keep the explicit/default distinction ----"
show("attrs.include?('approved') (Hash#include?)", attrs.include?("approved"))
show("attrs.key? / has_key?", attrs.key?("approved"))
show("attrs.fetch('approved', nil)", attrs.fetch("approved", nil))
show("attrs.dig('approved')", attrs.dig("approved"))
show("attrs.keys", attrs.keys)
show("attrs.each_attribute names", attrs.each_attribute.map(&:expanded_name))
show("attrs.size", attrs.size)
show("attrs.select { |k,| k == 'approved' }", attrs.select { |k, _| k == "approved" })
show("XPath string(//record[@id='r1']/@approved)",
     REXML::XPath.first(doc, "string(//record[@id='r1']/@approved)"))
show("XPath count(//record[@approved])", REXML::XPath.match(doc, "count(//record[@approved])"))
show("doc.doctype.attribute_of('record','approved') (declared default)",
     doc.doctype.attribute_of("record", "approved"))

r2 = REXML::XPath.first(doc, "//record[@id='r2']")
puts "\n  Control element r2 (explicit approved='false'):"
show("r2.include?('approved')", r2.attributes.include?("approved"))
show("r2['approved']", r2["approved"])
show("r1 FIXED default fixedv via []", r1["fixedv"])
show("r1 fixedv explicit? include?", r1.attributes.include?("fixedv"))

heading "Stage 3 - Copying nodes"
clone = r1.clone
show("r1.clone document link", clone.document)
show("clone.include?('approved')", clone.attributes.include?("approved"))
show("clone['approved'] (no document -> no DTD fallback)", clone["approved"])
show("clone['display']", clone["display"])

deep = r1.deep_clone
show("r1.deep_clone['approved']", deep["approved"])

doc.root.add_element(clone)
show("clone re-attached to original document: include?", clone.attributes.include?("approved"))
show("clone re-attached: [] (fallback restored)", clone["approved"])

other_doc = REXML::Document.new("<other/>")
moved = r1.deep_clone
other_doc.root.add_element(moved)
show("deep copy moved into DTD-less document: []", moved["approved"])
show("moved display []", moved["display"])

heading "Stage 4 - Serialize and re-parse"
serialized = +""
REXML::Formatters::Default.new.write(doc, serialized)
puts "--- serialized document ---"
puts serialized
puts "--- r1 alone (Element#to_s) ---"
puts r1.to_s
reparsed = REXML::Document.new(serialized)
r1_again = REXML::XPath.first(reparsed, "//record[@id='r1']")
show("reparsed r1 include?('approved')", r1_again.attributes.include?("approved"))
show("reparsed r1 ['approved'] (DTD round-trip restores fallback)", r1_again["approved"])
show("reparsed r1 to_s", r1_again.to_s)

heading "The vulnerable import service vs. the explicit-only check"
def vulnerable_authorized?(element)
  # BUG: presence inferred from a read accessor that answers DTD defaults.
  !element["approved"].nil? && element["approved"] == "true"
end

def safe_authorized?(element)
  # Only an attribute physically present on the start tag counts.
  element.attributes.key?("approved") && element["approved"] == "true"
end

show("vulnerable_authorized?(r1) [no field submitted]", vulnerable_authorized?(r1))
show("safe_authorized?(r1)      [no field submitted]", safe_authorized?(r1))
show("safe_authorized?(r2)      [explicit false]", safe_authorized?(r2))

# Legitimate default display value stays available through the display path.
show("r1['display'] default still readable for presentation", r1["display"])
