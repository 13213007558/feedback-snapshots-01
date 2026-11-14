#! /usr/bin/env ruby

# = NAME
#
# dane_verify - offline DANE (TLSA) verification demo for Dnsruby
#
# = SYNOPSIS
#
#   ruby demo/dane_verify.rb
#
# = DESCRIPTION
#
# Generates a private CA and two leaf certificates that share one key pair
# (the same SubjectPublicKeyInfo wrapped in different certificates and for
# different service names), then drives Dnsruby::DANE.verify entirely
# offline.  No DNS traffic is generated: the TLSA associations are built
# locally and handed in only after the caller marks them as DNSSEC SECURE.
#
# The scenarios show how the decision changes with the certificate usage,
# the service name, the trust configuration and the validation state of the
# TLSA data, and print the record that actually authenticated each peer.

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'dnsruby'
require 'openssl'
require 'securerandom'

def make_ca(key, common_name)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = OpenSSL::BN.new(SecureRandom.random_bytes(8).unpack1('H*').hex)
  cert.subject = cert.issuer = OpenSSL::X509::Name.new([['CN', common_name]])
  cert.public_key = key.public_key
  cert.not_before = Time.now - 60
  cert.not_after = Time.now + 3600
  factory = OpenSSL::X509::ExtensionFactory.new
  factory.subject_certificate = cert
  factory.issuer_certificate = cert
  cert.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
  cert.add_extension(factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
  cert.sign(key, OpenSSL::Digest::SHA256.new)
  cert
end

def make_leaf(key, issuer_cert, issuer_key, common_name, not_after: Time.now + 3600)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = OpenSSL::BN.new(SecureRandom.random_bytes(8).unpack1('H*').hex)
  cert.subject = OpenSSL::X509::Name.new([['CN', common_name]])
  cert.issuer = issuer_cert.subject
  cert.public_key = key.public_key
  cert.not_before = Time.now - 60
  cert.not_after = not_after
  factory = OpenSSL::X509::ExtensionFactory.new
  factory.subject_certificate = cert
  factory.issuer_certificate = issuer_cert
  cert.add_extension(factory.create_extension('subjectAltName', "DNS:#{common_name}", false))
  cert.add_extension(factory.create_extension('basicConstraints', 'CA:FALSE', true))
  cert.sign(issuer_key, OpenSSL::Digest::SHA256.new)
  cert
end

def tlsa(usage, selector, matching_type, certificate, name: nil)
  content = selector == Dnsruby::DANE::SELECTOR_CERT ? certificate.to_der : certificate.public_key.to_der
  data = case matching_type
         when Dnsruby::DANE::MATCHING_FULL then content
         when Dnsruby::DANE::MATCHING_SHA2_256 then OpenSSL::Digest::SHA256.digest(content)
         when Dnsruby::DANE::MATCHING_SHA2_512 then OpenSSL::Digest::SHA512.digest(content)
         end
  record = Dnsruby::RR::IN::TLSA.new([usage, selector, matching_type, data])
  record.name = Dnsruby::Name.create(name) if name
  record
end

def heading(title)
  puts
  puts "== #{title} #{'=' * (72 - title.length)}"
end

def attempt(label)
  print "#{label.ljust(58)}"
  result = yield
  puts "TRUSTED  by #{summary(result.matched)}"
  result
rescue Dnsruby::DANE::VerificationError => e
  puts "REJECTED (#{e.result.failure_reason})"
  e.result
rescue Dnsruby::DANE::ArgumentError => e
  puts "REFUSED  (#{e.message})"
end

def summary(record)
  fields = record.rdata_to_string.split
  association = fields[3..].join
  association = "#{association[0, 16]}...#{association.byteslice(-8, 8)} (#{association.length / 2} bytes)" if association.length > 48
  "#{fields[0]} #{fields[1]} #{fields[2]} #{association}"
end

ca_key = OpenSSL::PKey::RSA.new(2048)
ca = make_ca(ca_key, 'Demo Private CA')

# One key pair, two certificates: different serial, subject and service.
shared_key = OpenSSL::PKey::RSA.new(2048)
shop_leaf = make_leaf(shared_key, ca, ca_key, 'shop.example.com')
mail_leaf = make_leaf(shared_key, ca, ca_key, 'mail.example.org')
shop_chain = [shop_leaf, ca]
mail_chain = [mail_leaf, ca]

# An unrelated leaf with its own key.
other_leaf = make_leaf(OpenSSL::PKey::RSA.new(2048), ca, ca_key, 'shop.example.com')

pkix_store = OpenSSL::X509::Store.new
pkix_store.add_cert(ca)
pkix_trust = Dnsruby::DANE::TrustConfig.new(trust_store: pkix_store)
no_trust = Dnsruby::DANE::TrustConfig.new

puts 'Offline DANE verification demo'
puts "shared public key SPKI SHA2-256: #{OpenSSL::Digest::SHA256.hexdigest(shared_key.public_key.to_der)}"
puts "shop cert DER SHA2-256:          #{OpenSSL::Digest::SHA256.hexdigest(shop_leaf.to_der)}"
puts "mail cert DER SHA2-256:          #{OpenSSL::Digest::SHA256.hexdigest(mail_leaf.to_der)}"

heading '1. Same key, different certificates - selector decides the binding'
attempt('DANE-EE SPKI SHA2-256 against the shop certificate') do
  Dnsruby::DANE.verify(service: 'shop.example.com', port: 443,
                       tlsa_records: [tlsa(3, 1, 1, shop_leaf)],
                       chain: shop_chain, verified: true)
end
attempt('Same SPKI record against the mail certificate (same key)') do
  Dnsruby::DANE.verify(service: 'mail.example.org', port: 443,
                       tlsa_records: [tlsa(3, 1, 1, shop_leaf)],
                       chain: mail_chain, verified: true)
end
attempt('Full-certificate record only matches that exact certificate') do
  Dnsruby::DANE.verify(service: 'mail.example.org', port: 443,
                       tlsa_records: [tlsa(3, 0, 0, shop_leaf)],
                       chain: mail_chain, verified: true)
end
attempt('Full-certificate record against the matching certificate') do
  Dnsruby::DANE.verify(service: 'shop.example.com', port: 443,
                       tlsa_records: [tlsa(3, 0, 0, shop_leaf)],
                       chain: shop_chain, verified: true)
end

heading '2. Same record, different service names - DANE-EE skips name checks'
attempt('DANE-EE with a reference identity absent from the certificate') do
  Dnsruby::DANE.verify(service: 'hosted.customer.example.net', port: 443,
                       tlsa_records: [tlsa(3, 1, 1, shop_leaf)],
                       chain: shop_chain, verified: true)
end
attempt('DANE-TA enforces the service name on the leaf certificate') do
  Dnsruby::DANE.verify(service: 'hosted.customer.example.net', port: 443,
                       tlsa_records: [tlsa(2, 0, 1, ca)],
                       chain: shop_chain, verified: true)
end
attempt('DANE-TA with the name present in the certificate') do
  Dnsruby::DANE.verify(service: 'shop.example.com', port: 443,
                       tlsa_records: [tlsa(2, 0, 1, ca)],
                       chain: shop_chain, verified: true)
end

heading '3. Different trust conditions for the same chain'
attempt('PKIX-EE with the private CA configured as an anchor') do
  Dnsruby::DANE.verify(service: 'shop.example.com', port: 443,
                       tlsa_records: [tlsa(1, 1, 1, shop_leaf)],
                       chain: shop_chain, trust_config: pkix_trust, verified: true)
end
attempt('PKIX-EE with no PKIX trust anchors') do
  Dnsruby::DANE.verify(service: 'shop.example.com', port: 443,
                       tlsa_records: [tlsa(1, 1, 1, shop_leaf)],
                       chain: shop_chain, trust_config: no_trust, verified: true)
end
attempt('PKIX-TA pinning the issuing CA, CA trusted locally') do
  Dnsruby::DANE.verify(service: 'shop.example.com', port: 443,
                       tlsa_records: [tlsa(0, 0, 1, ca)],
                       chain: shop_chain, trust_config: pkix_trust, verified: true)
end
attempt('DANE-TA uses the TLSA record itself as the anchor, no local trust') do
  Dnsruby::DANE.verify(service: 'shop.example.com', port: 443,
                       tlsa_records: [tlsa(2, 0, 1, ca)],
                       chain: shop_chain, trust_config: no_trust, verified: true)
end
attempt('DANE-TA fails when the chain does not reach the pinned anchor') do
  other_ca = make_ca(OpenSSL::PKey::RSA.new(2048), 'Other CA')
  Dnsruby::DANE.verify(service: 'shop.example.com', port: 443,
                       tlsa_records: [tlsa(2, 0, 1, other_ca)],
                       chain: shop_chain, trust_config: no_trust, verified: true)
end

heading '4. Fail-closed handling: unknown fields and unverified DNS data'
attempt('Unknown certificate usage (255) cannot authenticate anything') do
  Dnsruby::DANE.verify(service: 'shop.example.com', port: 443,
                       tlsa_records: [tlsa(255, 1, 1, shop_leaf)],
                       chain: shop_chain, verified: true)
end
attempt('Unverified TLSA records are refused before any matching') do
  Dnsruby::DANE.verify(service: 'shop.example.com', port: 443,
                       tlsa_records: [tlsa(3, 1, 1, shop_leaf)],
                       chain: shop_chain, verified: false)
end
attempt('Per-record flags: one unverified record spoils the whole call') do
  Dnsruby::DANE.verify(service: 'shop.example.com', port: 443,
                       tlsa_records: [tlsa(3, 1, 1, other_leaf), tlsa(3, 1, 1, shop_leaf)],
                       chain: shop_chain, verified: [false, true])
end
attempt('A SECURE record that simply does not match the peer') do
  Dnsruby::DANE.verify(service: 'shop.example.com', port: 443,
                       tlsa_records: [tlsa(3, 1, 1, other_leaf)],
                       chain: shop_chain, verified: true)
end
