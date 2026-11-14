# frozen_string_literal: false

# XInclude demo backed entirely by an in-memory resource table.
#
# Run with:
#   ruby -Ilib examples/xinclude_in_memory.rb
#
# Nothing here touches the file system or the network: the resolver is the
# only object that can hand content to the XInclude processor, and it gates
# every read through an explicit authorization check.

require "rexml/document"
require "rexml/xinclude"

XI = REXML::XInclude::XINCLUDE_NAMESPACE

# A fixed, in-memory set of resources.  The shadow entry exists in the table
# but is deliberately kept off the resolver's allow-list.
RESOURCES = {
  "mem:/app/main.xml" => <<~XML,
    <app xmlns:xi="#{XI}" xml:base="mem:/app/main.xml">
      <database>
        <xi:include href="db/connection.xml"/>
      </database>
      <banner>
        <xi:include href="text/banner.txt" parse="text"/>
      </banner>
      <optional>
        <xi:include href="text/missing.txt" parse="text">
          <xi:fallback>no banner configured</xi:fallback>
        </xi:include>
      </optional>
    </app>
  XML
  "mem:/app/db/connection.xml" => <<~XML,
    <connection xmlns:xi="#{XI}">
      <endpoint>
        <xi:include href="../text/endpoint.txt" parse="text"/>
      </endpoint>
    </connection>
  XML
  "mem:/app/text/endpoint.txt" => "db://primary.example:5432/app",
  "mem:/app/text/banner.txt" => "Hello <world> & welcome",
  "mem:/etc/shadow.xml" => "<password>do-not-leak</password>",
}.freeze

class InMemoryResolver
  def initialize(resources, allowed)
    @resources = resources
    @allowed = allowed
    @reads = []
    @denials = []
  end

  attr_reader :reads, :denials

  # Authorization is consulted before any read.  A denied URI never reaches
  # #read, so its bytes cannot leak even though they exist in the table.
  def authorized?(uri)
    allowed = @allowed.include?(uri)
    @denials << uri unless allowed
    allowed
  end

  def read(uri)
    @reads << uri
    unless @resources.key?(uri)
      raise REXML::XInclude::ResourceError.missing!(uri)
    end
    @resources[uri]
  end
end

puts "== 1. Legitimate nested XML and text includes =="
document = REXML::Document.new(RESOURCES["mem:/app/main.xml"])
original = document.to_s

# Every resource referenced by the main document is allowed.
allowed = ["mem:/app/db/connection.xml",
           "mem:/app/text/endpoint.txt",
           "mem:/app/text/banner.txt",
           "mem:/app/text/missing.txt"]
resolver = InMemoryResolver.new(RESOURCES, allowed)
result = REXML::XInclude.include(document, resolver,
                                 base_uri: "mem:/app/main.xml")
puts result.document.to_s

puts "\n== 2. Where each piece of included content came from =="
shown = {}
result.sources.each_value do |source|
  next if shown.key?(source.uri)
  shown[source.uri] = true
  puts "#{source.mode.to_s.ljust(4)} #{source.uri} " \
       "(href #{source.href.inspect} from base #{source.base})"
  puts "      chain: #{source.chain.join(' -> ')}"
end

puts "\n== 3. Resolver audit (only allow-listed reads happened) =="
puts "reads:   #{resolver.reads.inspect}"
puts "denials: #{resolver.denials.inspect}"
puts "original document left intact: #{document.to_s == original ? 'yes' : 'NO'}"

puts "\n== 4. Authorization denial: fatal, fallback never runs, no read =="
locked = REXML::Document.new(<<~XML)
  <root xmlns:xi="#{XI}">
    <xi:include href="mem:/etc/shadow.xml">
      <xi:fallback><restricted>fallback must not run</restricted></xi:fallback>
    </xi:include>
  </root>
XML
strict_resolver = InMemoryResolver.new(RESOURCES, []) # nothing is allowed
begin
  REXML::XInclude.include(locked, strict_resolver)
rescue REXML::XInclude::AuthorizationDenied => error
  puts "raised: #{error.class}: #{error.message}"
  puts "read called on denied resource? " \
       "#{strict_resolver.reads.empty? ? 'no' : 'YES'}"
  puts "document still contains the include? " \
       "#{locked.to_s.include?('xi:include') ? 'yes' : 'no'}"
  puts "fallback content promoted? " \
       "#{locked.root.get_elements('restricted').empty? ? 'no' : 'YES'}"
end
