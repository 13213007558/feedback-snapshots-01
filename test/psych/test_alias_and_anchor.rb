# frozen_string_literal: true
require_relative 'helper'

class ObjectWithInstanceVariables
  attr_accessor :var1, :var2
end

class SubStringWithInstanceVariables < String
  attr_accessor :var1
end

module Psych
 class TestAliasAndAnchor < TestCase
   def test_mri_compatibility
     yaml = <<EOYAML
---
- &id001 !ruby/object {}

- *id001
- *id001
EOYAML
     result = Psych.unsafe_load yaml
     result.each {|el| assert_same(result[0], el) }
   end

   def test_mri_compatibility_object_with_ivars
  yaml = <<EOYAML
---
- &id001 !ruby/object:ObjectWithInstanceVariables
  var1: test1
  var2: test2
- *id001
- *id001
EOYAML

     result = Psych.unsafe_load yaml
     result.each do |el|
      assert_same(result[0], el)
      assert_equal('test1', el.var1)
      assert_equal('test2', el.var2)
    end
   end

   def test_mri_compatibility_substring_with_ivars
    yaml = <<EOYAML
---
- &id001 !str:SubStringWithInstanceVariables
  str: test
  "@var1": test
- *id001
- *id001
EOYAML
     result = Psych.unsafe_load yaml
     result.each do |el|
      assert_same(result[0], el)
      assert_equal('test', el.var1)
    end
   end

   def test_anchor_alias_round_trip
     o = Object.new
     original = [o,o,o]

     yaml = Psych.dump original
     result = Psych.unsafe_load yaml
     result.each {|el| assert_same(result[0], el) }
   end

   def test_anchor_alias_round_trip_object_with_ivars
     o = ObjectWithInstanceVariables.new
     o.var1 = 'test1'
     o.var2 = 'test2'
     original = [o,o,o]

     yaml = Psych.dump original
     result = Psych.unsafe_load yaml
     result.each do |el|
      assert_same(result[0], el)
      assert_equal('test1', el.var1)
      assert_equal('test2', el.var2)
    end
   end

   def test_anchor_alias_round_trip_substring_with_ivars
     o = SubStringWithInstanceVariables.new
     o.var1 = 'test'
     original = [o,o,o]

     yaml = Psych.dump original
     result = Psych.unsafe_load yaml
     result.each do |el|
      assert_same(result[0], el)
      assert_equal('test', el.var1)
    end
   end

   def test_anchor_does_not_leak_between_documents
     yaml = <<~eoyaml
       ---
       secret: &secret "TOP-SECRET"
       ---
       leaked: *secret
     eoyaml

     stream = Psych.parse_stream(yaml)
     error = assert_raise(Psych::AnchorNotDefined) { stream.to_ruby }
     assert_equal 'An alias referenced an unknown anchor: secret', error.message
   end

   def test_documents_do_not_share_anchors_when_converted_individually
     yaml = <<~eoyaml
       ---
       secret: &secret "TOP-SECRET"
       ---
       leaked: *secret
     eoyaml

     secret_document, leaked_document = Psych.parse_stream(yaml).children
     visitor = Psych::Visitors::ToRuby.create

     assert_equal({ 'secret' => 'TOP-SECRET' }, visitor.accept(secret_document))
     assert_raise(Psych::AnchorNotDefined) { visitor.accept(leaked_document) }
   end

   def test_visitor_is_reusable_after_an_undefined_anchor
     yaml = <<~eoyaml
       ---
       secret: &secret "TOP-SECRET"
       ---
       leaked: *secret
       ---
       value: &value "safe"
       ref: *value
     eoyaml

     documents = Psych.parse_stream(yaml).children
     visitor = Psych::Visitors::ToRuby.create

     assert_equal({ 'secret' => 'TOP-SECRET' }, visitor.accept(documents[0]))
     assert_raise(Psych::AnchorNotDefined) { visitor.accept(documents[1]) }
     assert_equal({ 'value' => 'safe', 'ref' => 'safe' }, visitor.accept(documents[2]))
   end

   def test_anchor_names_can_be_redefined_in_separate_documents
     yaml = <<~eoyaml
       ---
       value: &name "first"
       ---
       value: &name "second"
       ref: *name
     eoyaml

     first, second = Psych.parse_stream(yaml).to_ruby
     assert_equal({ 'value' => 'first' }, first)
     assert_equal({ 'value' => 'second', 'ref' => 'second' }, second)
     refute_same first['value'], second['value']
   end

   def test_aliases_still_share_objects_within_a_document
     result = Psych.parse_stream(<<~eoyaml).to_ruby.first
       ---
       - &shared
         key: value
       - *shared
     eoyaml

     assert_same result[0], result[1]
   end

   def test_recursive_alias_within_a_document
     result = Psych.parse_stream(<<~eoyaml).to_ruby.first
       ---
       - &self
         self: *self
     eoyaml

     assert_same result[0], result[0]['self']
   end

   def test_safe_load_stream_does_not_alias_across_documents
     yaml = <<~eoyaml
       ---
       secret: &secret "TOP-SECRET"
       ---
       leaked: *secret
     eoyaml

     assert_raise(Psych::AnchorNotDefined) do
       Psych.safe_load_stream(yaml, aliases: true)
     end

     assert_raise(Psych::AliasesNotEnabled) do
       Psych.safe_load_stream(yaml, aliases: false)
     end
   end
 end
end
