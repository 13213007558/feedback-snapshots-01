# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

module YamlMigrationProbes
  # Records every object-lifecycle hook that an attacker could try to trigger
  # through a YAML tag.  The specs below assert this array stays empty, which
  # proves no user object is instantiated (or revived) while reading untrusted
  # data.
  class HookProbe
    def self.allocate
      YamlMigrationProbes.record(:allocate)
      super
    end

    def initialize(*)
      YamlMigrationProbes.record(:initialize)
      super
    end

    def init_with(_coder)
      YamlMigrationProbes.record(:init_with)
    end

    def encode_with(_coder)
      YamlMigrationProbes.record(:encode_with)
    end
  end

  @events = []

  def self.record(name)
    @events << name
  end

  def self.events
    @events
  end

  def self.reset!
    @events.clear
  end

  # A constant the delivery_handler attack would try to resolve.
  module FakeDeliveryHandler
    def self.deliver_mail(_mail)
      YamlMigrationProbes.record(:deliver_mail)
    end
  end
end

RSpec.describe Mail::YAML do
  let(:binary_bytes) { (0..255).map(&:chr).join.force_encoding(Encoding::ASCII_8BIT) }

  around(:each) do |example|
    YamlMigrationProbes.reset!
    example.run
    YamlMigrationProbes.reset!
  end

  describe ".load" do
    it 'loads plain YAML into primitives' do
      expect(described_class.load('{}')).to eq({})
    end

    it 'resolves plain scalars to core types but keeps quoted values as strings' do
      data = described_class.load("i: 42\ns: \"42\"\nflag: true\nnothing: ~\n")
      expect(data['i']).to eq(42)
      expect(data['s']).to eq('42')
      expect(data['flag']).to be(true)
      expect(data['nothing']).to be_nil
    end

    it 'never instantiates a class named by an object tag' do
      yaml = "--- !ruby/object:YamlMigrationProbes::HookProbe\nx: 1\n"
      expect(described_class.load(yaml)).to eq('x' => 1)
      expect(YamlMigrationProbes.events).to be_empty
    end

    it 'reduces tagged Mail collections to plain containers' do
      list = Mail::PartsList.new([1, 2])
      loaded = described_class.load(YAML.dump(list))
      expect(loaded).to eq([1, 2])
      expect(loaded).to be_an(::Array)
      expect(loaded).not_to be_a(Mail::PartsList)
    end
  end

  describe ".migrate" do
    context 'legitimate historical mail (positive cases)' do
      it 'recovers a plain single-part message with no errors' do
        mail = Mail::Message.new(to: 'someone@example.com', subject: 'hello', body: 'the body')
        result = described_class.migrate(mail.to_yaml)

        expect(result).to be_ok
        expect(result.errors).to be_empty
        expect(result.message).to be_a(Mail::Message)
        expect(result.message.to).to eq(['someone@example.com'])
        expect(result.message.header[:subject].value).to eq('hello')
        expect(result.message.decoded).to eq('the body')
      end

      it 'recovers nested multipart structure with all parts' do
        mail = Mail.new(from: 'a@example.com', to: 'b@example.com', subject: 'nested')
        alternative = Mail::Part.new { content_type 'multipart/alternative' }
        alternative.add_part(Mail::Part.new { content_type 'text/plain'; body 'plain' })
        alternative.add_part(Mail::Part.new { content_type 'text/html'; body '<p>html</p>' })
        mail.add_part(alternative)

        result = described_class.migrate(mail.to_yaml)

        expect(result).to be_ok
        rebuilt = result.message
        expect(rebuilt).to be_multipart
        expect(rebuilt.parts.size).to eq(1)
        inner = rebuilt.parts.first
        expect(inner).to be_a(Mail::Part)
        expect(inner.mime_type).to eq('multipart/alternative')
        expect(inner.parts.map { |part| part.body.decoded }).to eq(['plain', '<p>html</p>'])
        expect(rebuilt.all_parts.all? { |part| part.is_a?(Mail::Part) }).to be(true)
      end

      it 'recovers a binary attachment byte-for-byte' do
        mail = Mail.new(from: 'a@example.com', to: 'b@example.com', subject: 'binary')
        mail.add_part(Mail::Part.new { content_type 'text/plain'; body 'cover note' })
        mail.attachments['pixel.bin'] = {
          mime_type: 'application/octet-stream',
          content: binary_bytes,
        }

        result = described_class.migrate(mail.to_yaml)

        expect(result).to be_ok
        attachment = result.message.parts.detect(&:attachment?)
        expect(attachment.filename).to eq('pixel.bin')
        expect(attachment.decoded.bytesize).to eq(256)
        expect(attachment.decoded).to eq(binary_bytes)
        expect(attachment.decoded.encoding).to eq(Encoding::ASCII_8BIT)
      end

      it 'round-trips through Mail::Message.from_yaml' do
        mail = Mail.new(to: 'x@example.com', subject: 'rt', body: 'round trip')
        expect(Mail::Message.from_yaml(mail.to_yaml)).to eq(mail)
      end

      it 'lists skipped internal state as warnings rather than claiming losslessness' do
        mail = Mail::Message.new(to: 'x@example.com', body: 'b')
        result = described_class.migrate(mail.to_yaml)

        expect(result).to be_ok
        expect(result.warnings).not_to be_empty
        expect(result.warnings.map(&:path)).to include('$.@perform_deliveries')
        expect(result.warnings.all?(&:warning?)).to be(true)
      end
    end

    context 'untrusted input (negative cases)' do
      it 'rejects an arbitrary object tag without running any object hook' do
        yaml = <<~YAML
          ---
          headers:
            Subject: attack
          "@body": !ruby/object:YamlMigrationProbes::HookProbe
            evil: true
          "@body_raw": harmless
        YAML

        result = described_class.migrate(yaml)

        expect(result).not_to be_ok
        expect(result.errors.map(&:path)).to include('$.@body')
        expect(YamlMigrationProbes.events).to be_empty
      end

      it 'rejects a non-Mail Ruby tag such as a Regexp object' do
        yaml = <<~YAML
          ---
          headers:
            Subject: attack
          "@body": !ruby/regexp /pattern/
          "@body_raw": harmless
        YAML

        result = described_class.migrate(yaml)

        expect(result).not_to be_ok
        expect(result.errors.map(&:path)).to include('$.@body')
        expect(YamlMigrationProbes.events).to be_empty
      end

      it 'never loads a delivery_handler behaviour configuration' do
        mail = Mail.new(to: 'x@example.com', body: 'b')
        mail.delivery_handler = YamlMigrationProbes::FakeDeliveryHandler
        yaml = mail.to_yaml

        result = described_class.migrate(yaml)

        expect(result).not_to be_ok
        expect(result.errors.map(&:path)).to include('$.delivery_handler')
        expect(result.message.delivery_handler).to be_nil
        expect(YamlMigrationProbes.events).to be_empty
      end

      it 'refuses an injected, non-schema internal instance variable' do
        yaml = <<~YAML
          ---
          headers:
            Subject: attack
          "@evil_internal": pwned
          "@body_raw": harmless
        YAML

        result = described_class.migrate(yaml)

        expect(result).not_to be_ok
        expect(result.errors.map(&:path)).to include('$.@evil_internal')
        expect(result.message.instance_variable_defined?(:@evil_internal)).to be(false)
        expect(result.message.instance_variable_get(:@evil_internal)).to be_nil
      end

      it 'rejects YAML aliases' do
        yaml = <<~YAML
          ---
          headers:
            Subject: aliased
          injected: &anchor
            k: v
          copy: *anchor
          "@body_raw": harmless
        YAML

        result = described_class.migrate(yaml)

        expect(result).not_to be_ok
        expect(result.errors.map(&:reason)).to include(a_string_matching(/alias/))
      end

      it 'rejects unsafe tags buried inside a nested part before building objects' do
        inner = <<~YAML
          ---
          headers:
            Content-Type: text/plain
          "@body": !ruby/object:YamlMigrationProbes::HookProbe
            z: 1
          "@body_raw": nested
        YAML
        outer = {
          'headers'        => { 'Content-Type' => 'multipart/mixed' },
          'transport_encoding' => '7bit',
          'multipart_body' => [inner],
        }
        yaml = Psych.dump(outer)

        result = described_class.migrate(yaml)

        expect(result).not_to be_ok
        expect(result.errors.map(&:path).join).to include('multipart_body[0]')
        expect(YamlMigrationProbes.events).to be_empty
      end

      it 'rejects an unknown top-level field explicitly instead of dropping it silently' do
        yaml = <<~YAML
          ---
          headers:
            Subject: attack
          mystery_field: 123
          "@body_raw": harmless
        YAML

        result = described_class.migrate(yaml)

        expect(result).not_to be_ok
        expect(result.errors.map(&:path)).to include('$.mystery_field')
      end

      it 'raises a clear error when the document is not a mapping' do
        expect { described_class.migrate("- just\n- a list\n") }
          .to raise_error(Mail::YAML::MalformedDocument)
      end

      it 'raises MalformedDocument for an empty document' do
        expect { described_class.migrate('') }
          .to raise_error(Mail::YAML::MalformedDocument)
      end

      it 'raises InvalidYAML for syntactically broken input' do
        expect { described_class.migrate('headers: [unterminated') }
          .to raise_error(Mail::YAML::InvalidYAML)
      end

      it 'keeps quoted values as strings while resolving plain ones' do
        data = described_class.load("plain: 7\nquoted: \"7\"\nflag: true\n")
        expect(data['plain']).to eq(7)
        expect(data['quoted']).to eq('7')
        expect(data['flag']).to be(true)
      end

      it 'records an unparseable nested part instead of crashing' do
        outer = {
          'headers'        => { 'Content-Type' => 'multipart/mixed' },
          'multipart_body' => ['this: is: not: valid: yaml: ['],
        }
        result = described_class.migrate(Psych.dump(outer))
        expect(result).not_to be_ok
        expect(result.errors.map(&:reason).join).to match(/unparseable nested part/)
      end
    end

    describe 'hook ordering guarantee' do
      it 'detects hooks through the historically unsafe loader but never through migration' do
        yaml = "--- !ruby/object:YamlMigrationProbes::HookProbe\nx: 1\n"

        expect { YAML.unsafe_load(yaml) }
          .to change { YamlMigrationProbes.events.dup }
          .to(include(:allocate, :init_with))

        YamlMigrationProbes.reset!
        wrapped = <<~YAML
          ---
          headers: {}
          "@body": !ruby/object:YamlMigrationProbes::HookProbe
            x: 1
          "@body_raw": h
        YAML
        described_class.migrate(wrapped)
        expect(YamlMigrationProbes.events).to be_empty
      end
    end
  end
end
