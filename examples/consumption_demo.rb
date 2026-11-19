# frozen_string_literal: true

# Reproduces the duplicate-login incident against ROTP::Consumption.
#
# Run with the vendored gems:
#   GEM_HOME="$PWD/.gems" GEM_PATH="$PWD/.gems" ruby -Ilib examples/consumption_demo.rb
#
# Two identical requests are paused right after the code check, then their
# commits are interleaved. The script walks TOTP (with a clock rollback) and
# HOTP (with a skipped counter) and prints one success, one replay rejection,
# and a legitimate following code that can still log in.

require 'rotp/consumption'

def banner(title)
  puts
  puts "== #{title} " + '=' * (68 - title.length)
end

def show(label, result)
  puts format('  %-34<l>s -> %<s>s%<d>s', l: label, s: result.status,
                                          d: result.detail ? " (#{result.detail})" : '')
end

store    = ROTP::Consumption::MemoryStore.new
verifier = ROTP::Consumption::Verifier.new(store)
account  = 'user-42'

# ---------------------------------------------------------------- TOTP
banner 'TOTP: duplicate requests, interleaved commits, clock rollback'
totp       = ROTP::TOTP.new('JBSWY3DPEHPK3PXP')
login_time = Time.utc(2026, 11, 19, 12, 0, 0) # exactly on a 30s boundary
code       = totp.at(login_time)

# Both HTTP requests verify the same code and are paused before committing.
request_one = verifier.verify(account_id: account, authenticator_id: 'phone',
                              otp: totp, code: code, at: login_time)
request_two = verifier.verify(account_id: account, authenticator_id: 'phone',
                              otp: totp, code: code, at: login_time)
puts "  both paused requests pass the code check: " \
     "#{request_one.ok? && request_two.ok?}"

show('first commit wins', verifier.commit(request_one.pending))
show('second commit (replay)', verifier.commit(request_two.pending))

# Clock rolls back to the consumed interval; ROTP alone would accept it.
show('clock rolled back to same interval',
     verifier.verify(account_id: account, authenticator_id: 'phone',
                     otp: totp, code: code, at: login_time, drift_behind: 30))

# A genuine next code still works.
next_time = login_time + 30
next_login = verifier.verify(account_id: account, authenticator_id: 'phone',
                             otp: totp, code: totp.at(next_time), at: next_time)
show('legitimate next code', next_login)
show('commit next code', verifier.commit(next_login.pending))
puts "  stored TOTP watermark: #{store.get(account, 'phone').watermark}"

# ---------------------------------------------------------------- HOTP
banner 'HOTP: duplicate requests, interleaved commits, skipped counter'
hotp = ROTP::HOTP.new('JBSWY3DPEHPK3PXP')

# The device skipped counters 1..6 off-line and presents counter 7.
skipped_code = hotp.at(7)
hotp_one = verifier.verify(account_id: account, authenticator_id: 'keyfob',
                           otp: hotp, code: skipped_code, retries: 10)
hotp_two = verifier.verify(account_id: account, authenticator_id: 'keyfob',
                           otp: hotp, code: skipped_code, retries: 10)
puts "  both paused requests pass the code check: " \
     "#{hotp_one.ok? && hotp_two.ok?}"

show('first commit wins', verifier.commit(hotp_one.pending))
show('second commit (replay)', verifier.commit(hotp_two.pending))
show('re-present skipped-to counter',
     verifier.verify(account_id: account, authenticator_id: 'keyfob',
                     otp: hotp, code: skipped_code, retries: 10))
show('a skipped lower counter (3) is spent too',
     verifier.verify(account_id: account, authenticator_id: 'keyfob',
                     otp: hotp, code: hotp.at(3), retries: 10))

following = verifier.verify(account_id: account, authenticator_id: 'keyfob',
                            otp: hotp, code: hotp.at(8), retries: 10)
show('legitimate following counter (8)', following)
show('commit following counter', verifier.commit(following.pending))
puts "  stored HOTP counter: #{store.get(account, 'keyfob').watermark}"

# ------------------------------------------------- independent positions
banner 'Independent positions per authenticator'
puts "  TOTP watermark and HOTP counter never share state: " \
     "totp=#{store.get(account, 'phone').watermark}, " \
     "hotp=#{store.get(account, 'keyfob').watermark}"

# ------------------------------------------------- business failure
banner 'Business commit failure rolls the OTP position back'
fresh_code = hotp.at(9)
pending = verifier.verify(account_id: account, authenticator_id: 'keyfob',
                          otp: hotp, code: fresh_code, retries: 10)
begin
  store.transaction do
    verifier.commit(pending.pending)
    raise 'downstream order service unavailable'
  end
rescue RuntimeError => e
  puts "  business error: #{e.message}"
end
retry_result = verifier.verify(account_id: account, authenticator_id: 'keyfob',
                               otp: hotp, code: fresh_code, retries: 10)
show('same code reusable after rollback', retry_result)
show('commit retry', verifier.commit(retry_result.pending))
