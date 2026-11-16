require File.expand_path(File.join(File.dirname(__FILE__), 'test_helper'))

require 'onelogin/ruby-saml/response'
require 'onelogin/ruby-saml/attribute_records'

class AttributeRecordsTest < Minitest::Test
  BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic'.freeze
  URI_FORMAT = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'.freeze
  PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'.freeze
  ENCRYPTED_NAME = 'urn:oid:1.3.6.1.4.1.5923.1.1.1.6'.freeze
  ISSUE_INSTANT = '2026-11-17T12:00:00Z'.freeze

  describe 'typed attribute records' do
    let(:settings) do
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert = ruby_saml_cert_text
      settings.idp_entity_id = 'https://idp.example.com/metadata'
      settings.sp_entity_id = 'https://sp.example.com/metadata'
      settings.assertion_consumer_service_url = 'https://sp.example.com/acs'
      settings.certificate = ruby_saml_cert_text
      settings.private_key = ruby_saml_key_text
      settings.security[:want_assertions_signed] = true
      settings
    end

    let(:response) do
      Timecop.freeze(Time.parse(ISSUE_INSTANT)) do
        OneLogin::RubySaml::Response.new(fixture('response_typed_attributes'), :settings => settings)
      end
    end

    after do
      OneLogin::RubySaml::Attributes.single_value_compatibility = true
    end

    def with_frozen_time(&block)
      Timecop.freeze(Time.parse(ISSUE_INSTANT), &block)
    end

    it 'validates the signed assertion that carries the typed attributes' do
      with_frozen_time do
        assert response.is_valid?(true), response.errors.inspect
        assert_empty response.errors
      end
    end

    it 'keeps one record per Attribute element and preserves NameFormat' do
      records = response.attribute_records.by_name('eduPersonTargetedID')

      assert_equal [BASIC, URI_FORMAT], records.map(&:name_format)
      assert_equal [BASIC, URI_FORMAT], response.attribute_records.name_formats('eduPersonTargetedID')
      assert records.all?(&:same_name_other_format?)
      refute records.first.duplicate?
      refute response.attribute_record('uid').same_name_other_format?
      assert_equal %w[uid eduPersonTargetedID displayName role urn:oid:1.3.6.1.4.1.5923.1.1.1.6],
                   response.attribute_records.names
    end

    it 'refuses to guess between attributes that share a Name but not a NameFormat' do
      error = assert_raises(OneLogin::RubySaml::AmbiguousAttributeError) do
        response.attribute_record('eduPersonTargetedID')
      end
      assert_includes error.message, 'multiple NameFormat'

      record = response.attribute_record('eduPersonTargetedID', :name_format => URI_FORMAT)
      assert_equal BASIC, response.attribute_record('eduPersonTargetedID', :name_format => BASIC).name_format
      assert_equal 'opaque-target-uri', record.values.first.text
    end

    it 'keeps each qualifier of nested NameID values instead of joining them' do
      record = response.attribute_record('eduPersonTargetedID', :name_format => BASIC)

      assert_equal 2, record.values.size
      first, second = record.values.map(&:name_id)

      assert_equal 'opaque-target-a', first.value
      assert_equal PERSISTENT, first.format
      assert_equal 'https://idp-a.example.com', first.name_qualifier
      assert_equal 'https://sp.example.com/metadata', first.sp_name_qualifier

      assert_equal 'opaque-target-b', second.value
      assert_equal 'https://idp-b.example.com', second.name_qualifier
      assert_equal 'https://sp.example.com/metadata', second.sp_name_qualifier

      # The legacy convenience API still joins qualifier and value to remain compatible.
      assert_equal 'https://idp-a.example.com/opaque-target-a',
                   response.attributes.multi('eduPersonTargetedID').first
    end

    it 'distinguishes xsi:nil, an empty string, a missing value and a missing attribute' do
      record = response.attribute_record('displayName')
      nil_value, empty_value, text_value = record.values

      assert nil_value.nil_value?
      assert_nil nil_value.text
      refute nil_value.empty?

      refute empty_value.nil_value?
      assert_equal '', empty_value.text
      assert empty_value.empty?

      assert_equal 'Alice Example', text_value.text

      assert_raises(OneLogin::RubySaml::MissingAttributeError) do
        response.attribute_record('attribute_not_exists')
      end
      assert_nil response.attributes.multi('attribute_not_exists')
    end

    it 'requires an explicit value index for multi-valued attributes' do
      error = assert_raises(OneLogin::RubySaml::AmbiguousAttributeError) do
        response.attribute_value('displayName')
      end
      assert_includes error.message, '3 values'

      assert response.attribute_value('displayName', :value_index => 1).nil_value?
      assert response.attribute_value('displayName', :value_index => 2).empty?
      assert_equal 'Alice Example', response.attribute_value('displayName', :value_index => 3).text
    end

    it 'keeps duplicate Attribute elements separate and explains the duplication' do
      records = response.attribute_records.by_name('role')

      assert_equal [1, 2], records.map(&:occurrence)
      assert_equal [2, 2], records.map(&:occurrences)
      assert records.all?(&:duplicate?)
      assert_equal [%w[admin auditor], %w[viewer]], records.map { |record| record.values.map(&:text) }

      duplicates = response.attribute_records.duplicates
      assert_equal [[[ 'role', BASIC ], records]], duplicates.to_a

      assert_equal [true, false, 5], [records.first.to_h[:duplicate], records.first.to_h[:same_name_other_format], records.first.to_h[:source][:attribute_index]]

      assert_raises(OneLogin::RubySaml::AmbiguousAttributeError) { response.attribute_record('role') }
      assert_raises(OneLogin::RubySaml::MissingAttributeError) { response.attribute_record('role', :occurrence => 3) }
      assert_equal %w[viewer], response.attribute_record('role', :occurrence => 2).values.map(&:text)
      assert_equal 'auditor', response.attribute_value('role', :occurrence => 1, :value_index => 2).text
    end

    it 'lets the caller choose an account identifier without guessing' do
      # Option 1: the persistent NameID for the SP, addressed by NameFormat.
      targeted_ids = response.attribute_record('eduPersonTargetedID', :name_format => BASIC)
      targeted_id = targeted_ids.values[1].name_id

      assert targeted_id.qualified?
      assert_equal [targeted_id.name_qualifier, targeted_id.sp_name_qualifier, targeted_id.value],
                   ['https://idp-b.example.com', 'https://sp.example.com/metadata', 'opaque-target-b']

      # Option 2: the encrypted attribute, whose source records that it was decrypted.
      principal = response.attribute_record(ENCRYPTED_NAME)
      assert_equal ['alice@example.com', true], [principal.values.first.text, principal.encrypted?]

      # Option 3: the subject NameID keeps its own qualifiers on the Response.
      assert_equal 'alice@example.com', response.name_id
      assert_equal 'https://idp.example.com/metadata', response.name_id_namequalifier
      assert_equal 'https://sp.example.com/metadata', response.name_id_spnamequalifier
    end

    it 'exposes a single nested NameID through AttributeValue#name_id' do
      value = response.attribute_record('eduPersonTargetedID', :name_format => BASIC).values.first

      assert value.name_id?
      assert_equal 'opaque-target-a', value.name_id.value
      assert_equal PERSISTENT, value.name_id.format
    end

    it 'records the XML Schema type of each value' do
      value = response.attribute_value('uid')

      assert_equal 'xs:string', value.type
      assert_equal 'http://www.w3.org/2001/XMLSchema', value.type_namespace
      assert_equal 'string', value.type_name
    end

    it 'exposes the signed assertion and the position of each attribute and value' do
      record = response.attribute_record('role', :occurrence => 2)

      assert_equal 'response-typed-attributes', record.source.response_id
      assert_equal 'assertion-typed-attributes', record.source.assertion_id
      assert_equal 1, record.source.statement_index
      assert_equal 6, record.source.attribute_index
      assert_equal 'Attribute', record.source.element_name
      refute record.encrypted?
      assert_equal "/samlp:Response[@ID='response-typed-attributes']" \
                   "/saml:Assertion[@ID='assertion-typed-attributes']" \
                   '/saml:AttributeStatement[1]/saml:Attribute[6]', record.source.path

      value = record.values.first
      assert_equal 1, value.source.value_index
      assert_equal record.source.path + '/saml:AttributeValue[1]', value.source.path
    end

    it 'includes decrypted EncryptedAttribute values and marks their origin' do
      record = response.attribute_record(ENCRYPTED_NAME)

      assert record.encrypted?
      assert_equal 'EncryptedAttribute', record.source.element_name
      assert_equal URI_FORMAT, record.name_format
      assert_equal 'eduPersonPrincipalName', record.friendly_name
      assert_equal 'alice@example.com', record.values.first.text
      assert_equal ['xs:string', 'http://www.w3.org/2001/XMLSchema', 'string'],
                   [record.values.first.type, record.values.first.type_namespace, record.values.first.type_name]
      assert_equal 7, record.source.attribute_index
      assert_equal 7, response.attribute_records.size
      assert_equal record.source.path + '/saml:AttributeValue[1] (decrypted)',
                   record.values.first.source.path
    end

    it 'returns an empty collection when the assertion has no AttributeStatement' do
      response = OneLogin::RubySaml::Response.new(response_document_without_attributes)

      assert response.attribute_records.empty?
      assert_equal [], response.attribute_records.to_a
      assert_equal [], response.attribute_records.names
    end

    it 'raises when an EncryptedAttribute cannot be decrypted' do
      settings.private_key = nil
      settings.certificate = nil
      response = OneLogin::RubySaml::Response.new(fixture('response_typed_attributes'), :settings => settings)

      error = assert_raises(OneLogin::RubySaml::ValidationError) { response.attribute_records }
      assert_includes error.message, 'no SP private key'
    end

    it 'is not affected by the single_value_compatibility switch' do
      OneLogin::RubySaml::Attributes.single_value_compatibility = false

      assert_equal ['admin', 'auditor'], response.attribute_record('role', :occurrence => 1).values.map(&:text)
      assert_equal 'alice', response.attribute_value('uid').text
      assert_equal ['alice'], response.attributes.multi('uid')

      OneLogin::RubySaml::Attributes.single_value_compatibility = true

      assert_equal ['admin', 'auditor'], response.attribute_record('role', :occurrence => 1).values.map(&:text)
      assert_equal 'alice', response.attribute_value('uid').text
    end

    it 'still returns the legacy convenience view' do
      with_frozen_time do
        assert_equal 'alice', response.attributes[:uid]
        assert_equal 'https://idp-a.example.com/opaque-target-a',
                     response.attributes.multi('eduPersonTargetedID').first
        assert_equal [nil, '', 'Alice Example'], response.attributes.multi('displayName')
      end
    end
  end

  describe 'AttributeValue' do
    it 'refuses to silently pick one of several NameIDs nested in a single value' do
      name_ids = [
        OneLogin::RubySaml::NameIdValue.new(:value => 'a', :name_qualifier => 'https://idp-a'),
        OneLogin::RubySaml::NameIdValue.new(:value => 'b', :name_qualifier => 'https://idp-b')
      ]
      value = OneLogin::RubySaml::AttributeValue.new(:name_ids => name_ids)

      assert_raises(OneLogin::RubySaml::AmbiguousAttributeError) { value.name_id }
      assert_equal name_ids, value.name_ids
    end
  end

  describe 'AttributeCollection#value' do
    def record(values)
      OneLogin::RubySaml::AttributeRecord.new(:name => 'role', :name_format => BASIC, :values => values)
    end

    it 'raises when an Attribute has no AttributeValue' do
      collection = OneLogin::RubySaml::AttributeCollection.new([record([])])

      assert collection.first.empty?
      assert_raises(OneLogin::RubySaml::MissingAttributeError) { collection.value('role') }
      assert_raises(OneLogin::RubySaml::MissingAttributeError) { collection.value('role', :value_index => 1) }
    end

    it 'selects a value by index and reports out-of-range indexes' do
      value = OneLogin::RubySaml::AttributeValue.new(:text => 'admin')
      collection = OneLogin::RubySaml::AttributeCollection.new([record([value])])

      assert_same value, collection.value('role', :value_index => 1)
      assert_raises(OneLogin::RubySaml::MissingAttributeError) { collection.value('role', :value_index => 2) }
    end
  end
end
