# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'
require 'mail/security/transfer_decoder'

RSpec.describe Mail::Security::TransferDecoder do
  describe '.decode_base64' do
    it 'decodes a valid stream without issues and preserves raw octets' do
      decoded, issues = described_class.decode('base64', ["a\x00b\xff".b].pack('m0'))
      expect(issues).to be_empty
      expect(decoded).to eq("a\x00b\xff".b)
      expect(decoded.encoding).to eq(Encoding::ASCII_8BIT)
    end

    it 'ignores CRLF folding as permitted by RFC 2045' do
      decoded, issues = described_class.decode('base64', "aGVs\r\nbG8=\r\n")
      expect(issues).to be_empty
      expect(decoded).to eq('hello')
    end

    it 'locates an illegal alphabet character by raw byte offset' do
      decoded, issues = described_class.decode('base64', 'aGV!sbG8=')
      issue = issues.find { |i| i.reason == :illegal_base64_character }
      expect(issue.offset).to eq(3)
      expect(issue.bytes).to eq('!')
      expect(issue.stage).to eq(:transfer_encoding)
      expect(decoded).to be_a(String)
    end

    it 'flags a truncated final quantum instead of silently padding it' do
      tolerant = 'aGVsbG8'.unpack1('m')
      expect(tolerant).to eq('hello')

      _decoded, issues = described_class.decode('base64', 'aGVsbG8')
      expect(issues.map(&:reason)).to include(:truncated_base64_quantum)
    end

    it 'flags padding placed before the end of the quantum' do
      _decoded, issues = described_class.decode('base64', 'aGV=sbG8=')
      expect(issues.map(&:reason)).to include(:illegal_base64_padding)
    end

    it 'rejects incorrect padding widths' do
      _decoded, issues = described_class.decode('base64', 'aGVsb===')
      expect(issues.map(&:reason)).to include(:illegal_base64_padding)
    end
  end

  describe '.decode_quoted_printable' do
    it 'decodes valid escapes and soft line breaks without issues' do
      decoded, issues = described_class.decode('quoted-printable', "caf=E9 =\r\nx\r\n")
      expect(issues).to be_empty
      expect(decoded).to eq("caf\xE9 x\r\n".b)
    end

    it 'locates a dangling soft line break at the end of input' do
      _decoded, issues = described_class.decode('quoted-printable', "body=4\r\n")
      issue = issues.find { |i| i.reason == :malformed_quoted_printable_escape }
      expect(issue.offset).to eq(4)
      expect(issue.bytes).to eq("=4\r".b)
    end

    it 'locates a non-hex escape sequence' do
      _decoded, issues = described_class.decode('quoted-printable', 'a=ZZb')
      issue = issues.find { |i| i.reason == :malformed_quoted_printable_escape }
      expect(issue.offset).to eq(1)
      expect(issue.bytes).to eq('=ZZ')
    end

    it 'reports bare LF and CR line breaks' do
      _decoded, lf_issues = described_class.decode('quoted-printable', "a=\nb")
      expect(lf_issues.map(&:reason)).to include(:bare_line_break)

      _decoded, cr_issues = described_class.decode('quoted-printable', "a=\rb")
      expect(cr_issues.map(&:reason)).to include(:bare_line_break)
    end

    it 'flags raw non-ASCII octets that must be hex escaped' do
      _decoded, issues = described_class.decode('quoted-printable', "caf\xE9".b)
      expect(issues.map(&:reason)).to include(:non_ascii_quoted_printable_byte)
      expect(issues.first.offset).to eq(3)
    end
  end

  describe '.decode with identity encodings' do
    it 'passes 8bit and binary octets through untouched' do
      decoded, issues = described_class.decode('8bit', "\xFF\x00".b)
      expect(issues).to be_empty
      expect(decoded).to eq("\xFF\x00".b)
    end

    it 'flags octets above 0x7F in declared 7bit content' do
      _decoded, issues = described_class.decode('7bit', "ab\xFF".b)
      expect(issues.first.reason).to eq(:non_ascii_seven_bit_byte)
      expect(issues.first.offset).to eq(2)
      expect(issues.first.bytes).to eq("\xFF".b)
    end

    it 'raises for an unregistered transfer encoding' do
      expect { described_class.decode('x-uuencode', 'abc') }
        .to raise_error(Mail::UnknownEncodingType)
    end
  end
end
