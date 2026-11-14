# frozen_string_literal: true
#
# End-to-end demo: the same payload processed by the vulnerable pattern
# and by the SafeImportContract read contract.
#
# Run: ruby -Ilib security/dtd-default-attributes/demo_service.rb

require_relative "safe_import_contract"

PAYLOAD = <<~XML
  <?xml version="1.0"?>
  <!DOCTYPE import [
    <!ELEMENT import (user*)>
    <!ELEMENT user EMPTY>
    <!ATTLIST user
      name     CDATA #REQUIRED
      display  CDATA "guest"
      approved CDATA "true">
  ]>
  <import>
    <user name="mallory"/>
    <user name="alice" approved="true"/>
  </import>
XML

module VulnService
  def self.decide(element)
    # Presence inferred from a read accessor -> DTD default authorizes.
    granted = !element["approved"].nil? && element["approved"] == "true"
    [granted, element["approved"]]
  end
end

module HardenedService
  def self.decide(element)
    granted = SafeImportContract.authorized?(element)
    shown = SafeImportContract.display_value(element, "display", "guest")
    [granted, SafeImportContract.explicit_attr(element, "approved"), shown]
  end
end

puts "Payload (note: mallory has NO approved attribute in the document body)"
puts PAYLOAD

puts "\n--- Vulnerable service (parse full document, decide with Element#[]) ---"
vuln_doc = REXML::Document.new(PAYLOAD)
SafeImportContract.records(vuln_doc, "//user").each do |user|
  granted, raw = VulnService.decide(user)
  puts format("  %-8s granted=%-5s read approved=%p", user["name"], granted, raw)
end

puts "\n--- Hardened service (DTD stripped + explicit-only contract) ---"
safe_doc = SafeImportContract.parse(PAYLOAD)
SafeImportContract.records(safe_doc, "//user").each do |user|
  granted, raw, shown = HardenedService.decide(user)
  puts format("  %-8s granted=%-5s explicit approved=%p display=%s",
              user["name"], granted, raw, shown)
end

puts "\n--- Hardened service on a document whose DTD the business keeps ---"
kept = REXML::Document.new(PAYLOAD)
SafeImportContract.records(kept, "//user").each do |user|
  granted = SafeImportContract.authorized?(user)
  shown = SafeImportContract.display_value(user, "display", "guest")
  puts format("  %-8s granted=%-5s display(default preserved)=%s",
              user["name"], granted, shown)
end
