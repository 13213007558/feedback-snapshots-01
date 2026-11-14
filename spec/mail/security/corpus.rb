# encoding: utf-8
# frozen_string_literal: true

# Shared, hand-crafted messages used by every security decoding spec. Each
# damaged mail carries the same dangerous payload "EVIL.example" so the specs
# can prove strict decoding never treats the damaged bytes as absent content.
module SecurityCorpus
  DANGEROUS_TOKEN = 'EVIL.example'

  module_function

  def build(headers, body)
    raw = "#{headers.join("\r\n")}\r\n\r\n#{body}"
    Mail.new(raw.dup.force_encoding(Encoding::ASCII_8BIT))
  end

  def base64_headers(charset: 'UTF-8')
    [
      'Content-Transfer-Encoding: base64',
      "Content-Type: text/plain; charset=#{charset}"
    ]
  end

  def qp_headers(charset: 'UTF-8')
    [
      'Content-Transfer-Encoding: quoted-printable',
      "Content-Type: text/plain; charset=#{charset}"
    ]
  end

  # Reference message that every stage decodes without a single replacement.
  def clean_mail
    build(base64_headers, ["all clean text here"].pack('m0') + "\r\n")
  end

  def clean_dangerous_mail
    build(base64_headers, ["browse #{DANGEROUS_TOKEN} now"].pack('m0') + "\r\n")
  end

  # A non-base64 byte ("!") inside the stream plus a dropped final quantum
  # character. The tolerant unpack still rebuilds the dangerous token.
  def bad_base64_mail
    encoded = ["browse #{DANGEROUS_TOKEN} now"].pack('m0')
    damaged = encoded.sub('V', '!').chop
    build(base64_headers, "#{damaged}\r\n")
  end

  # A soft line break ("=") dangling in front of a single hex digit, which a
  # tolerant QP decoder leaves as literal text.
  def truncated_quoted_printable_mail
    build(qp_headers, "browse #{DANGEROUS_TOKEN} now=4\r\n")
  end

  def malformed_quoted_printable_mail
    build(qp_headers, "browse #{DANGEROUS_TOKEN}=ZZ now\r\n")
  end

  # Real UTF-8 multibyte content advertised as US-ASCII.
  def wrong_charset_mail
    payload = "browse #{DANGEROUS_TOKEN} \xE3\x81\x82".b
    build(base64_headers(charset: 'US-ASCII'), [payload].pack('m0') + "\r\n")
  end

  # A three-byte UTF-8 character (E3 81 82) with its final octet missing.
  def multibyte_truncation_mail
    payload = "browse #{DANGEROUS_TOKEN} \xE3\x81".b
    build(base64_headers, [payload].pack('m0') + "\r\n")
  end

  # Charset name Ruby cannot resolve at all.
  def unknown_charset_mail
    payload = "browse #{DANGEROUS_TOKEN}".b
    build(base64_headers(charset: 'X-MADE-UP'), [payload].pack('m0') + "\r\n")
  end

  # Octet above 0x7F sent with a declared 7bit transfer encoding.
  def seven_bit_violation_mail
    build(['Content-Transfer-Encoding: 7bit',
           'Content-Type: text/plain; charset=ISO-8859-1'],
          "browse #{DANGEROUS_TOKEN} \xE9\r\n")
  end

  def damaged_mails
    {
      bad_base64: bad_base64_mail,
      truncated_quoted_printable: truncated_quoted_printable_mail,
      malformed_quoted_printable: malformed_quoted_printable_mail,
      wrong_charset: wrong_charset_mail,
      multibyte_truncation: multibyte_truncation_mail,
      unknown_charset: unknown_charset_mail,
      seven_bit_violation: seven_bit_violation_mail
    }
  end
end
