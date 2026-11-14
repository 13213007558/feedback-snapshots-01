# Timing Attack in Credential Comparison

This is an **optional check** (`CheckCredentialComparisonTiming`, enable with
`-t CheckCredentialComparisonTiming` or `--enable-checks`). It inspects the
hand-written blocks used by methods such as
`authenticate_or_request_with_http_basic`, which the framework-level Basic
Auth checks do not analyze.

## Short-circuiting combinations

`&&` and `||` stop evaluating as soon as the result is determined. When two
credential comparisons are joined this way, the second comparison is skipped
whenever the first one fails, so the response timing reveals whether the first
credential matched:

    authenticate_or_request_with_http_basic do |username, password|
      username == expected_user && password == expected_password
    end

The same problem exists even when each individual comparison is constant time,
because the `&&` sits *between* the two checks:

    ActiveSupport::SecurityUtils.secure_compare(username, expected_user) &&
      Rack::Utils.secure_compare(password, expected_password)

## Safe combinations

Evaluate every comparison unconditionally and combine the resulting booleans
with a non-short-circuit operator (`&` / `|`), or collect them and use `all?`:

    user_ok = secure_compare(username, expected_user)
    pass_ok = secure_compare(password, expected_password)
    user_ok & pass_ok

## Fixed-length comparisons

Comparing fixed-length digests with `==` is safe against prefix leakage because
both sides always have the same digest length. The check recognizes
`Digest::...#hexdigest` / `#digest` style calls. `secure_compare` and
`OpenSSL.fixed_length_secure_compare` are recognized only through their
documented calling conventions; a custom method whose name merely contains
"secure" or "compare" is reported as an unrecognized helper rather than trusted.

The check never reads or reports secret values: warnings carry a file and line
but no comparison code or user input.
