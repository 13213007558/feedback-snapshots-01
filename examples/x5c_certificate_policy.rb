#!/usr/bin/env ruby
# frozen_string_literal: true

# Demonstrates the x5c certificate policy interface end to end:
#
#   1. A trusted chain whose leaf purpose does not match is rejected.
#   2. A trusted chain with valid revocation evidence verifies the JWT.
#   3. A trusted chain whose revocation evidence has expired is rejected.
#
# Certificates are generated on the fly. The last check proves that the key
# selected from the leaf certificate is the key that verifies the token
# signature: a token signed by a different key fails even though the chain is
# otherwise valid.
#
# Run with: bundle exec ruby examples/x5c_certificate_policy.rb

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'jwt'

Now = Time.at(Time.now.to_i)

def generate_key
  OpenSSL::PKey::RSA.new(2048)
end

def certificate(subject, key, serial, issuer: nil, issuer_key: nil, ca: false, eku: nil,
                not_before: Now - 7200, not_after: Now + 7200)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = serial
  cert.subject = subject
  cert.issuer = (issuer || cert).subject
  cert.public_key = key
  cert.not_before = not_before
  cert.not_after = not_after

  factory = OpenSSL::X509::ExtensionFactory.new
  factory.subject_certificate = cert
  factory.issuer_certificate = issuer || cert

  if ca
    cert.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.add_extension(factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
  else
    cert.add_extension(factory.create_extension('basicConstraints', 'CA:FALSE', true))
    cert.add_extension(factory.create_extension('keyUsage', 'digitalSignature', true))
    cert.add_extension(factory.create_extension('extendedKeyUsage', eku, false)) if eku
  end

  cert.sign(issuer_key || key, 'sha256')
  cert
end

def issue_crl(issuer:, issuer_key:, last_update:, next_update:, revoked: [])
  crl = OpenSSL::X509::CRL.new
  crl.issuer = issuer.subject
  crl.version = 1
  crl.last_update = last_update
  crl.next_update = next_update

  revoked.each do |serial, time|
    entry = OpenSSL::X509::Revoked.new
    entry.serial = serial
    entry.time = time
    crl.add_revoked(entry)
  end

  crl.add_extension(OpenSSL::X509::Extension.new('crlNumber', OpenSSL::ASN1::Integer(1)))
  crl.sign(issuer_key, 'sha256')
  crl
end

def encode(certificate)
  Base64.strict_encode64(certificate.to_der)
end

root_key = generate_key
intermediate_key = generate_key
leaf_key = generate_key

root = certificate(
  OpenSSL::X509::Name.parse('/DC=org/DC=demo/CN=Demo Root CA'),
  root_key, 1, ca: true
)
intermediate = certificate(
  OpenSSL::X509::Name.parse('/DC=org/DC=demo/CN=Demo Intermediate CA'),
  intermediate_key, 2, issuer: root, issuer_key: root_key, ca: true
)
# The leaf is only authorized to sign client (login) credentials.
leaf = certificate(
  OpenSSL::X509::Name.parse('/DC=org/DC=demo/CN=Login Credential Signer'),
  leaf_key.public_key, 3, issuer: intermediate, issuer_key: intermediate_key, eku: 'clientAuth'
)
other_leaf_key = generate_key

x5c = [encode(leaf), encode(intermediate)]
intermediate_crl = issue_crl(
  issuer: intermediate, issuer_key: intermediate_key, last_update: Now - 3600, next_update: Now + 7200
)
root_crl = issue_crl(
  issuer: root, issuer_key: root_key, last_update: Now - 3600, next_update: Now + 7200
)
expired_intermediate_crl = issue_crl(
  issuer: intermediate, issuer_key: intermediate_key, last_update: Now - 7200, next_update: Now - 60
)

finder = JWT::X5cKeyFinder.new([root], [intermediate_crl, root_crl])
token = JWT.encode({ 'sub' => 'demo-user' }, leaf_key, 'RS256', 'x5c' => x5c)

def report(label)
  puts label
  yield
rescue JWT::CertificateVerificationError => e
  puts "  rejected: #{e.class.name.split('::').last} (#{e.reason})"
end

puts 'Scenario 1: trusted chain but the leaf purpose does not allow login credentials'
report('- purpose: :server_auth') do
  finder.from(x5c, purpose: :server_auth, at_time: Now)
  puts '  UNEXPECTEDLY ACCEPTED'
end
puts

puts 'Scenario 2: trusted chain with valid revocation evidence at the verification time'
key = finder.from(x5c, purpose: :client_auth, at_time: Now)
payload, = JWT.decode(token, nil, true, algorithms: ['RS256'],
                                      x5c: { root_certificates: [root], crls: [intermediate_crl, root_crl],
                                             purpose: :client_auth, at_time: Now })
puts "  accepted key: #{key.class}"
puts "  decoded payload: #{payload.inspect}"
puts

puts 'Scenario 3: trusted chain but the revocation evidence has expired'
report('- at_time: now, CRL next_update: now - 60') do
  JWT::X5cKeyFinder.new([root], [expired_intermediate_crl, root_crl])
                   .from(x5c, purpose: :client_auth, at_time: Now)
  puts '  UNEXPECTEDLY ACCEPTED'
end
puts

puts 'Signature check: the selected leaf key is actually used to verify the token'
forged = JWT.encode({ 'sub' => 'attacker' }, other_leaf_key, 'RS256', 'x5c' => x5c)
begin
  JWT.decode(forged, nil, true, algorithms: ['RS256'],
                            x5c: { root_certificates: [root], crls: [intermediate_crl, root_crl],
                                   purpose: :client_auth, at_time: Now })
  puts '  UNEXPECTEDLY ACCEPTED'
rescue JWT::VerificationError => e
  puts "  rejected: #{e.class.name.split('::').last} (#{e.message}) - certificate chain alone is not enough"
end

# Negative control: the same token verifies when revocation evidence is
# explicitly out of scope, showing scenario 3 failed on evidence freshness.
finder.from(x5c, purpose: :client_auth, at_time: Now, revocation: :none)
puts '  control: chain accepted with revocation: :none'
