require 'spec_helper'

# Consumer-side implementation used by the interoperability tests. It deliberately
# does not call ROTP::OTP::URI or ROTP::Base32: the generator is checked against
# an independent parser and an independent RFC 4226/6238 verifier.
module OTPAuthInterop
  class AmbiguousURI < StandardError; end

  STANDARD_PARAMETERS = %w[secret issuer algorithm digits period counter].freeze
  BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.chars.freeze
  Parsed = Struct.new(:type, :label_issuer, :account, :params)

  module_function

  def decode_component(value)
    URI::DEFAULT_PARSER.unescape(value).force_encoding(Encoding::UTF_8)
  end

  def parse(uri)
    parsed = URI.parse(uri)
    unless parsed.scheme == 'otpauth' && %w[totp hotp].include?(parsed.host)
      raise AmbiguousURI, "not an otpauth URI: #{uri}"
    end

    raw_label = parsed.path.to_s.sub(%r{\A/}, '')
    segments = raw_label.empty? ? [''] : raw_label.split(':', -1)
    if segments.length > 2
      raise AmbiguousURI, 'label contains more than one unescaped colon'
    end

    label_issuer = segments.length == 2 ? decode_component(segments[0]) : nil
    account = decode_component(segments.length == 2 ? segments[1] : segments[0])

    params = {}
    URI.decode_www_form(parsed.query.to_s).each do |raw_key, raw_value|
      key = raw_key.dup.force_encoding(Encoding::UTF_8)
      value = raw_value.dup.force_encoding(Encoding::UTF_8)

      if STANDARD_PARAMETERS.include?(key.downcase)
        raise AmbiguousURI, "standard parameter name is not lowercase: #{key}" if key != key.downcase
        raise AmbiguousURI, "duplicate standard parameter: #{key}" if params.key?(key)

        key = key.downcase
      end
      raise AmbiguousURI, "duplicate parameter: #{key}" if params.key?(key)

      params[key] = value
    end

    if params.key?('issuer') && params['issuer'].empty?
      raise AmbiguousURI, 'empty issuer parameter'
    end
    if label_issuer.nil? && params.key?('issuer')
      raise AmbiguousURI, 'issuer parameter without an issuer label'
    end
    if label_issuer && params.key?('issuer') && label_issuer != params['issuer']
      raise AmbiguousURI, 'label issuer and issuer parameter disagree'
    end

    Parsed.new(parsed.host, label_issuer, account, params)
  end

  def verifier(parsed)
    secret = parsed.params.fetch('secret')
    digest = parsed.params.fetch('algorithm', 'sha1').downcase
    digits = Integer(parsed.params.fetch('digits', '6'))

    if parsed.type == 'totp'
      raise AmbiguousURI, 'TOTP URI must not carry a counter' if parsed.params.key?('counter')

      period = Integer(parsed.params.fetch('period', '30'))
      ->(time) { totp(secret, Integer(time), digits, digest, period) }
    else
      raise AmbiguousURI, 'HOTP URI must not carry a period' if parsed.params.key?('period')

      counter = Integer(parsed.params.fetch('counter'))
      ->(count) { hotp(secret, Integer(count), digits, digest) }
    end
  end

  def hotp(secret, counter, digits, digest)
    message = [counter >> 32, counter & 0xffffffff].pack('N2')
    hmac = OpenSSL::HMAC.digest(digest, base32_decode(secret), message)
    offset = hmac[-1].ord & 0x0f
    code = (hmac[offset].ord & 0x7f) << 24 |
           (hmac[offset + 1].ord & 0xff) << 16 |
           (hmac[offset + 2].ord & 0xff) << 8 |
           (hmac[offset + 3].ord & 0xff)
    format("%0#{digits}d", code % (10**digits))
  end

  def totp(secret, time, digits, digest, period)
    hotp(secret, time / period, digits, digest)
  end

  def base32_decode(value)
    buffer = 0
    bits = 0
    bytes = []

    value.to_s.upcase.delete('=').each_char do |char|
      quint = BASE32_ALPHABET.index(char)
      raise ArgumentError, "invalid Base32 character: #{char.inspect}" if quint.nil?

      buffer = (buffer << 5) | quint
      bits += 5
      while bits >= 8
        bits -= 8
        bytes << ((buffer >> bits) & 0xff)
      end
    end

    bytes.pack('C*')
  end
end

RSpec.describe 'otpauth URI interoperability' do
  INTEROP_SECRET = 'JBSWY3DPEHPK3PXP'.freeze
  RFC_SHA1_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'.freeze
  RFC_SHA256_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA'.freeze
  RFC_SHA512_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA'.freeze

  # RFC 6238 Appendix B timestamps. Codes below were computed independently with
  # Python's hmac/hashlib, not with ROTP.
  RFC_TIMES = [59, 1_111_111_109, 1_111_111_111, 1_234_567_890, 2_000_000_000, 20_000_000_000].freeze

  TOTP_VECTORS = [
    {
      name: 'RFC 6238 SHA1 with omitted defaults',
      secret: RFC_SHA1_SECRET, digest: 'sha1', digits: 6, interval: 30,
      times: RFC_TIMES,
      codes: %w[287082 081804 050471 005924 279037 353130],
    },
    {
      name: 'RFC 6238 SHA256 with 8 digits',
      secret: RFC_SHA256_SECRET, digest: 'sha256', digits: 8, interval: 30,
      times: RFC_TIMES,
      codes: %w[46119246 68084774 67062674 91819424 90698825 77737706],
    },
    {
      name: 'RFC 6238 SHA512 with 8 digits',
      secret: RFC_SHA512_SECRET, digest: 'sha512', digits: 8, interval: 30,
      times: RFC_TIMES,
      codes: %w[90693936 25091201 99943326 93441116 38618901 47863826],
    },
    {
      name: 'SHA256 with 8 digits and a 45 second period',
      secret: INTEROP_SECRET, digest: 'sha256', digits: 8, interval: 45,
      times: [0, 44, 45, 89, 90, 1_234_567_890, 2_000_000_000],
      codes: %w[96023015 96023015 36344551 36344551 52730792 64603424 86128095],
    },
    {
      name: 'SHA512 with 7 digits and a 60 second period',
      secret: INTEROP_SECRET, digest: 'sha512', digits: 7, interval: 60,
      times: [0, 44, 45, 89, 90, 1_234_567_890, 2_000_000_000],
      codes: %w[6582788 6582788 6582788 1439887 1439887 6606127 7198270],
    },
    {
      name: 'SHA256 with the default 6 digits',
      secret: RFC_SHA256_SECRET, digest: 'sha256', digits: 6, interval: 30,
      times: [0, 44, 45, 89, 90, 1_234_567_890, 2_000_000_000],
      codes: %w[920136 119246 119246 882438 975832 819424 698825],
    },
    {
      name: 'SHA512 with a 60 second period',
      secret: RFC_SHA512_SECRET, digest: 'sha512', digits: 8, interval: 60,
      times: [0, 44, 45, 89, 90, 1_234_567_890, 2_000_000_000],
      codes: %w[53550594 53550594 53550594 90693936 90693936 85275929 97791279],
    },
    {
      name: 'SHA1 with 8 digits',
      secret: INTEROP_SECRET, digest: 'sha1', digits: 8, interval: 30,
      times: RFC_TIMES,
      codes: %w[41996554 33071271 28358462 94742275 28890699 94752434],
    },
  ].freeze

  HOTP_VECTORS = [
    {
      name: 'RFC 4226 SHA1',
      secret: RFC_SHA1_SECRET, digest: 'sha1', digits: 6,
      counters: (0..9).to_a,
      codes: %w[755224 287082 359152 969429 338314 254676 287922 162583 399871 520489],
    },
    {
      name: 'SHA256 with 8 digits',
      secret: RFC_SHA256_SECRET, digest: 'sha256', digits: 8,
      counters: (1234..1238).to_a,
      codes: %w[84730349 88946868 78621942 57654268 56982700],
    },
    {
      name: 'SHA512 with 8 digits',
      secret: INTEROP_SECRET, digest: 'sha512', digits: 8,
      counters: (17..21).to_a,
      codes: %w[50327320 40416794 72029791 56771162 90539619],
    },
    {
      name: 'SHA256 with the default 6 digits',
      secret: INTEROP_SECRET, digest: 'sha256', digits: 6,
      counters: (0..4).to_a,
      codes: %w[023015 344551 730792 653637 766270],
    },
  ].freeze

  describe 'identity round trip' do
    it 'preserves colons, slashes, percent signs and Unicode in issuer and account' do
      issuer = 'ACME:Corp/北%京?#&='
      account = 'ali:ce/ops%42@例子.中国?#'
      otp = ROTP::TOTP.new(INTEROP_SECRET, issuer: issuer, name: account)
      uri = otp.provisioning_uri

      expect(URI.parse(uri).path.sub(%r{\A/}, '').count(':')).to eq(1)
      parsed = OTPAuthInterop.parse(uri)
      expect(parsed.label_issuer).to eq(issuer)
      expect(parsed.params['issuer']).to eq(issuer)
      expect(parsed.account).to eq(account)
    end

    it 'distinguishes a literal percent sequence from its decoded character' do
      otp = ROTP::TOTP.new(INTEROP_SECRET, issuer: 'A%3AB')
      parsed = OTPAuthInterop.parse(otp.provisioning_uri('a%40b@example.test'))

      expect(parsed.label_issuer).to eq('A%3AB')
      expect(parsed.params['issuer']).to eq('A%3AB')
      expect(parsed.account).to eq('a%40b@example.test')
    end

    it 'keeps an account colon encoded rather than turning it into a label delimiter' do
      otp = ROTP::TOTP.new(INTEROP_SECRET)
      uri = otp.provisioning_uri('Alice:Smith')

      expect(uri).to include('/Alice%3ASmith?')
      parsed = OTPAuthInterop.parse(uri)
      expect(parsed.label_issuer).to be_nil
      expect(parsed.account).to eq('Alice:Smith')
    end

    it 'does not collapse an issuer underscore with an issuer colon' do
      underscore_issuer = ROTP::TOTP.new(INTEROP_SECRET, issuer: 'ACME_Corp', name: 'alice')
      colon_issuer = ROTP::TOTP.new(INTEROP_SECRET, issuer: 'ACME:Corp', name: 'alice')

      underscore_uri = underscore_issuer.provisioning_uri
      colon_uri = colon_issuer.provisioning_uri

      expect(underscore_uri).not_to eq(colon_uri)
      expect(OTPAuthInterop.parse(underscore_uri).label_issuer).to eq('ACME_Corp')
      expect(OTPAuthInterop.parse(colon_uri).label_issuer).to eq('ACME:Corp')
    end

    it 'omits an issuer that is empty after stripping instead of emitting issuer=' do
      otp = ROTP::TOTP.new(INTEROP_SECRET, issuer: "  \t")
      uri = otp.provisioning_uri('alice@example.test')

      expect(uri).not_to include('issuer=')
      expect(uri).not_to include('/:')
      parsed = OTPAuthInterop.parse(uri)
      expect(parsed.label_issuer).to be_nil
      expect(parsed.params).not_to have_key('issuer')
    end
  end

  describe 'parameter interpretation' do
    TOTP_VECTORS.each do |vector|
      it "produces fixed TOTP codes from parsed URI parameters: #{vector[:name]}" do
        otp = ROTP::TOTP.new(
          vector[:secret],
          digest: vector[:digest],
          digits: vector[:digits],
          interval: vector[:interval]
        )
        parsed = OTPAuthInterop.parse(otp.provisioning_uri('alice@example.test'))
        verify = OTPAuthInterop.verifier(parsed)

        expect(vector[:times].map { |time| otp.at(time) }).to eq(vector[:codes])
        expect(vector[:times].map { |time| verify.call(time) }).to eq(vector[:codes])
      end
    end

    HOTP_VECTORS.each do |vector|
      it "produces fixed HOTP codes from parsed URI parameters: #{vector[:name]}" do
        otp = ROTP::HOTP.new(
          vector[:secret],
          digest: vector[:digest],
          digits: vector[:digits]
        )
        first_counter = vector[:counters].first
        parsed = OTPAuthInterop.parse(otp.provisioning_uri('alice@example.test', first_counter))
        verify = OTPAuthInterop.verifier(parsed)

        expect(vector[:counters].map { |counter| otp.at(counter) }).to eq(vector[:codes])
        expect(vector[:counters].map { |counter| verify.call(counter) }).to eq(vector[:codes])
      end
    end

    it 'omits RFC defaults by default' do
      otp = ROTP::TOTP.new(RFC_SHA1_SECRET)
      parsed = OTPAuthInterop.parse(otp.provisioning_uri('alice@example.test'))

      expect(parsed.params.keys).to contain_exactly('secret')
    end

    it 'treats an uppercase SHA1 digest as the default' do
      otp = ROTP::TOTP.new(RFC_SHA1_SECRET, digest: 'SHA1')
      parsed = OTPAuthInterop.parse(otp.provisioning_uri('alice@example.test'))

      expect(parsed.params).not_to have_key('algorithm')
    end

    it 'requires an explicit counter for HOTP' do
      otp = ROTP::HOTP.new(RFC_SHA1_SECRET)
      uri = ROTP::OTP::URI.new(otp, account_name: 'alice@example.test')

      expect { uri.to_s }.to raise_error(ArgumentError, /counter/)
    end

    it 'can emit RFC defaults explicitly without changing their meaning' do
      otp = ROTP::TOTP.new(
        RFC_SHA1_SECRET,
        issuer: 'ACME',
        skip_default_uri_params: false
      )
      parsed = OTPAuthInterop.parse(otp.provisioning_uri('alice@example.test'))
      verify = OTPAuthInterop.verifier(parsed)

      expect(parsed.params['algorithm']).to eq('SHA1')
      expect(parsed.params['digits']).to eq('6')
      expect(parsed.params['period']).to eq('30')
      expect(RFC_TIMES.map { |time| verify.call(time) }).to eq(TOTP_VECTORS.first[:codes])
    end
  end

  describe 'provisioning_params conflicts and extensions' do
    it 'does not let extension parameters replace TOTP secrets or algorithm settings' do
      otp = ROTP::TOTP.new(
        INTEROP_SECRET,
        issuer: 'Good Corp',
        digest: 'sha256',
        digits: 8,
        interval: 45,
        provisioning_params: {
          secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
          'secret' => 'MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U',
          'Secret' => 'ONSWG4TFOQ======',
          counter: 99,
          'Counter' => 100,
          algorithm: 'SHA1',
          'Algorithm' => 'SHA512',
          digits: 6,
          period: 30,
          issuer: 'Evil Corp',
          image: 'https://example.test/icon.png',
        }
      )
      uri = otp.provisioning_uri('alice@example.test')
      parsed = OTPAuthInterop.parse(uri)
      verify = OTPAuthInterop.verifier(parsed)

      expect(parsed.params['secret']).to eq(INTEROP_SECRET)
      expect(parsed.params['issuer']).to eq('Good Corp')
      expect(parsed.params['algorithm']).to eq('SHA256')
      expect(parsed.params['digits']).to eq('8')
      expect(parsed.params['period']).to eq('45')
      expect(parsed.params).not_to have_key('counter')
      expect(parsed.params.keys).to contain_exactly(
        'secret', 'issuer', 'algorithm', 'digits', 'period', 'image'
      )
      expect(parsed.params['image']).to eq('https://example.test/icon.png')

      vector = TOTP_VECTORS.find { |entry| entry[:name] == 'SHA256 with 8 digits and a 45 second period' }
      expect(vector[:times].map { |time| verify.call(time) }).to eq(vector[:codes])
    end

    it 'does not let extension parameters replace the HOTP counter' do
      otp = ROTP::HOTP.new(
        INTEROP_SECRET,
        issuer: 'Good Corp',
        digest: 'sha512',
        digits: 8,
        provisioning_params: {
          'counter' => 0,
          counter: 1,
          secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
          algorithm: 'SHA1',
        }
      )
      parsed = OTPAuthInterop.parse(otp.provisioning_uri('alice@example.test', 17))
      verify = OTPAuthInterop.verifier(parsed)

      expect(parsed.params['counter']).to eq('17')
      expect(parsed.params['secret']).to eq(INTEROP_SECRET)
      expect(parsed.params['algorithm']).to eq('SHA512')
      expect(parsed.params.keys).to contain_exactly(
        'secret', 'issuer', 'algorithm', 'digits', 'counter'
      )
      expect((17..21).map { |counter| verify.call(counter) }).to eq(
        %w[50327320 40416794 72029791 56771162 90539619]
      )
    end

    it 'percent-encodes extension keys and values' do
      otp = ROTP::TOTP.new(
        INTEROP_SECRET,
        provisioning_params: {
          'icon key' => 'https://example.test/i c o n.png?a=1&b=%2F+c',
          '图标' => '北 京',
        }
      )
      parsed = OTPAuthInterop.parse(otp.provisioning_uri('alice@example.test'))

      expect(parsed.params['icon key']).to eq('https://example.test/i c o n.png?a=1&b=%2F+c')
      expect(parsed.params['图标']).to eq('北 京')
    end

    it 'ignores empty extension keys and case-variant duplicates' do
      otp = ROTP::TOTP.new(
        INTEROP_SECRET,
        provisioning_params: {
          '' => 'ignored',
          image: 'first',
          'IMAGE' => 'second',
        }
      )
      parsed = OTPAuthInterop.parse(otp.provisioning_uri('alice@example.test'))

      expect(parsed.params.keys).to contain_exactly('secret', 'image')
      expect(parsed.params['image']).to eq('first')
    end
  end

  describe 'known ambiguous URI shapes' do
    AMBIGUOUS_URIS = [
      ['duplicate secret', 'otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&secret=GEZDGNBVGY3TQOJQ'],
      ['label issuer and issuer parameter disagree', 'otpauth://totp/Right:alice?secret=JBSWY3DPEHPK3PXP&issuer=Wrong'],
      ['issuer parameter without an issuer label', 'otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME'],
      ['unescaped colon in account', 'otpauth://totp/ACME:ali:ce?secret=JBSWY3DPEHPK3PXP&issuer=ACME'],
      ['empty issuer parameter', 'otpauth://totp/:alice?secret=JBSWY3DPEHPK3PXP&issuer='],
      ['uppercase standard parameter', 'otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&Algorithm=SHA256'],
    ].freeze

    AMBIGUOUS_URIS.each do |label, uri|
      it "rejects #{label}" do
        expect { OTPAuthInterop.parse(uri) }.to raise_error(OTPAuthInterop::AmbiguousURI)
      end
    end

    it 'never emits any of those shapes itself' do
      otp = ROTP::TOTP.new(
        INTEROP_SECRET,
        issuer: 'ACME:Corp',
        provisioning_params: {
          secret: 'GEZDGNBVGY3TQOJQ',
          issuer: 'Evil',
          'SECRET' => 'MFRGGZDFMZTWQ2LK',
        }
      )
      uri = otp.provisioning_uri('ali:ce@example.test')

      expect { OTPAuthInterop.parse(uri) }.not_to raise_error
      expect(uri.scan('secret').length).to eq(1)
    end
  end
end
