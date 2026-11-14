# A different initializer file sets the mode from runtime data. The value is not
# a source-level constant, so it resolves to several possible modes. Brakeman
# cannot prove which initializer (and thus which assignment) is effective, and
# must not pick the "safe" one based on file enumeration order.
if Rails.env.production?
  Oj.default_options = { mode: :object }
else
  Oj.default_options = { mode: ENV["OJ_MODE"] }
end
