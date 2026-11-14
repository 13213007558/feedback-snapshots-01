# frozen_string_literal: true

# Read contract for import documents that carry an authorization field.
#
# Background: with an internal DTD subset, REXML's DOM read accessors
# (Element#[] / Element#attribute / Attributes#[] / #get_attribute) answer
# ATTLIST default values even when the attribute was never written on the
# start tag. Presence checks therefore must not use those accessors.
#
# This contract separates two questions:
#
#   * authorization  - did the caller explicitly supply the field?
#       Only Hash-level membership on the element's own attribute store
#       counts (key?/include?/fetch), which DTD defaults never enter.
#
#   * presentation    - what value should the UI show?
#       DTD defaults are legitimate here; Element#[] keeps resolving them.
#
# Hardening is layered:
#   1. parse with the internal DTD subset stripped (defense in depth, also
#      shrinks the internal-entity attack surface);
#   2. even if a DTD reaches the tree, every authorization decision goes
#      through explicit_attr? so a default value can never authorize.

require "rexml/document"

module SafeImportContract
  # Matches a DOCTYPE declaration, including an internal subset [...] and
  # an external ID. Nested ']' does not occur in a well-formed subset.
  DOCTYPE_RE = /\s*<!DOCTYPE\s+[^>\[]*(?:\[.*?\])?\s*>/m

  module_function

  # Parse caller-supplied XML without an internal/external DTD declaration.
  # General entities referenced in the body then fail to resolve loudly
  # (undefined entity) instead of being defined attacker-side.
  def parse(xml)
    clean = xml.sub(DOCTYPE_RE, "")
    REXML::Document.new(clean)
  end

  # True only when +name+ is physically present on +element+'s start tag.
  # DTD defaults live in document.doctype, never in this Hash, so they
  # answer false here regardless of what Element#[] would return.
  def explicit_attr?(element, name)
    element.attributes.key?(name)
  end

  # The explicitly submitted raw value, or nil when the field is absent.
  # A submitted empty string ("") is preserved and stays distinguishable
  # from an omitted field. The Attributes Hash stores REXML::Attribute
  # objects, so the value is read off the entry explicitly; this never
  # touches the DTD fallback in Attributes#get_attribute.
  def explicit_attr(element, name)
    entry = element.attributes.fetch(name, nil)
    return nil if entry.nil?
    entry.is_a?(REXML::Attribute) ? entry.value : entry
  end

  # Authorization decision: the field must be explicitly provided AND
  # carry the exact agreed token. Anything else (absent, empty, default,
  # unknown value) is denied.
  def authorized?(element, field: "approved", grant: "true")
    explicit_attr?(element, field) && explicit_attr(element, field) == grant
  end

  # Presentation read: DTD defaults may legitimately fill display-only
  # fields. Never feed this result into an authorization decision.
  def display_value(element, name, fallback = nil)
    element[name] || fallback
  end

  # Records parsed from a typical <import><record/></import> envelope.
  def records(doc, xpath = "//record")
    REXML::XPath.match(doc, xpath)
  end
end
