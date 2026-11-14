# Reference values for the timing-comparison fixture only.
#
# Real applications read credentials from configuration or a credential store.
# Here the expected values are derived at runtime from opaque source tokens via
# a digest, so the application source contains no credential literal that a
# static-analysis tool could copy into a report. These values are not real
# credentials.
module FixtureSecrets
  SOURCE_TOKEN_A = "reference-source-a".freeze
  SOURCE_TOKEN_B = "reference-source-b".freeze

  def self.admin_user
    Digest::SHA256.hexdigest(SOURCE_TOKEN_A)
  end

  def self.admin_password
    Digest::SHA256.hexdigest(SOURCE_TOKEN_B)
  end

  # A fixed-length digest stands in for the stored reference digests.
  def self.expected_user_digest
    Digest::SHA256.hexdigest(admin_user)
  end

  def self.expected_pass_digest
    Digest::SHA256.hexdigest(admin_password)
  end

  # A custom helper whose name contains "secure" but whose implementation is
  # unknown to the analyzer. It must not be trusted on the name alone.
  def self.super_secure_compare(candidate, secret)
    candidate == secret
  end
end
