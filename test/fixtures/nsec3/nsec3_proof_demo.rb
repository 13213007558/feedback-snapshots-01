$LOAD_PATH.unshift(File.expand_path('../../../lib', __dir__))
require 'dnsruby'
require_relative './nsec3_zone_builder'

zone = Nsec3ZoneBuilder.build
verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
verifier.add_trust_anchor(zone.dnskey)

def verdict(verifier, msg, zone)
  structural = begin
    r = verifier.verify_nsecs(msg)
    r.is_a?(Dnsruby::SingleVerifier::Nsec3InsecureDelegation) ? 'INSECURE (opt-out)' : 'proof OK'
  rescue Dnsruby::VerifyError => e
    "REJECT: #{e.message}"
  end
  crypto = begin
    verifier.verify(msg, zone.dnskey) ? 'signature OK' : 'signature FAILED'
  rescue Dnsruby::VerifyError => e
    "REJECT: #{e.message}"
  end
  "structural=#{structural.ljust(60)} | crypto=#{crypto}"
end

puts '=== Baseline: complete, correctly signed proofs ==='
zone.responses.each do |key, msg|
  puts "%-18s %s" % [key, verdict(verifier, msg, zone)]
end

puts
puts '=== NXDOMAIN: remove each proof record in turn ==='
{
  'remove next-closer cover' => zone.nsec3_covering('c.x.w.example.').name,
  'remove encloser match'     => zone.nsec3_matching('x.w.example.').name,
  'remove wildcard cover'     => zone.nsec3_covering('*.x.w.example.').name
}.each do |label, owner|
  msg = Dnsruby::Message.decode(zone.responses[:nxdomain].encode)
  msg.authority.delete_if { |rr| rr.name.canonical == owner.canonical &&
    (rr.type == Dnsruby::Types.NSEC3 || (rr.type == Dnsruby::Types.RRSIG && rr.type_covered == Dnsruby::Types.NSEC3)) }
  puts "%-26s %s" % [label, verdict(verifier, msg, zone)]
end

puts
puts '=== NODATA: replace matching NSEC3 bitmap ==='
target = zone.nsec3_matching('ns1.example.')
[['add MX (qtype present)', %w[A MX RRSIG NSEC3]],
 ['add CNAME', %w[A CNAME RRSIG NSEC3]],
 ['change salt to beefbeef', nil]].each do |label, types|
  msg = Dnsruby::Message.decode(zone.responses[:nodata].encode)
  if types
    rec = zone.make_nsec3(target.name.to_s(true), 0, target.next_hashed, types)
  else
    rec = Dnsruby::RR.create("#{target.name.to_s(true)} 3600 IN NSEC3 1 0 12 beefbeef ( #{target.encode_next_hashed(target.next_hashed)} A RRSIG NSEC3 )")
  end
  msg.authority.delete_if { |rr| rr.name.canonical == target.name.canonical &&
    (rr.type == Dnsruby::Types.NSEC3 || (rr.type == Dnsruby::Types.RRSIG && rr.type_covered == Dnsruby::Types.NSEC3)) }
  msg.add_authority(rec)
  puts "%-26s %s" % [label, verdict(verifier, msg, zone)]
end

puts
puts '=== Opt-Out: unsigned delegation must not become a secure denial ==='
msg = Dnsruby::Message.decode(zone.responses[:ds_nodata_optout].encode)
puts "%-26s %s" % ['opt-out flag set', verdict(verifier, msg, zone)]
plain = zone.make_nsec3(zone.opt_out.name.to_s(true), 0, zone.opt_out.next_hashed,
                        zone.opt_out.types.map(&:string))
msg.authority.delete_if { |rr| rr.name.canonical == zone.opt_out.name.canonical &&
  (rr.type == Dnsruby::Types.NSEC3 || (rr.type == Dnsruby::Types.RRSIG && rr.type_covered == Dnsruby::Types.NSEC3)) }
msg.add_authority(plain)
puts "%-26s %s" % ['opt-out flag cleared', verdict(verifier, msg, zone)]
