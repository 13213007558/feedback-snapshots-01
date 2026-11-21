# Adding support for parallel requests

!> This is slightly more involved, and this section is not fully formed.

Vague example, excerpted from [the test suite about parallel requests](https://github.com/lostisland/faraday/blob/main/spec/support/shared_examples/request_method.rb#L179)

```ruby
response_1 = nil
response_2 = nil

conn.in_parallel do
  response_1 = conn.get('/about')
  response_2 = conn.get('/products')
end

puts response_1.status
puts response_2.status
```

First, in your class definition, you can tell Faraday that your backend supports parallel operation:

```ruby
class FlorpHttp < ::Faraday::Adapter
  dependency do
    require 'florp_http'
  end

  self.supports_parallel = true
end
```

Then, implement a method which returns a ParallelManager:

```ruby
class FlorpHttp < ::Faraday::Adapter
  dependency do
    require 'florp_http'
  end

  self.supports_parallel = true

  def self.setup_parallel_manager(_options = nil)
    FlorpParallelManager.new # NB: we will need to define this
  end

  def call(env)
    # NB: you can call `in_parallel?` here to check if the current request
    # is part of a parallel batch. Useful if you need to collect all requests
    # into the ParallelManager before running them.
  end
end

class FlorpParallelManager
  # The execute method will be passed the same block as `in_parallel`,
  # so you can either collect the requests or just wrap them into a wrapper,
  # depending on how your adapter works.
  def execute(&block)
    run_async(&block)
  end
end
```

### A note on the old, deprecated interface

Prior to the introduction of the `execute` method, the `ParallelManager` was expected to implement a `run` method
and the execution of the block was done by the Faraday connection BEFORE calling that method.

This approach made the `ParallelManager` implementation harder and forced you to keep state around.
The new `execute` implementation allows to avoid this shortfall and support different flows.

As of Faraday 2.0, `run` is still supported in case `execute` is not implemented by the `ParallelManager`,
but this method should be considered deprecated.

For reference, please see an example using `run` from [em-synchrony](https://github.com/lostisland/faraday-em_synchrony/blob/main/lib/faraday/adapter/em_synchrony.rb)
and its [ParallelManager implementation](https://github.com/lostisland/faraday-em_synchrony/blob/main/lib/faraday/adapter/em_synchrony/parallel_manager.rb).

### Confirming authorization right before execution

Because the adapter only *enqueues* requests while the `in_parallel` block runs,
a parallel manager is the natural place to perform a final, per-request check
immediately before the adapter would send anything. This is useful when an
application's authorization can be revoked after the request was scheduled but
before it actually runs.

The pattern is:

1. The adapter calls `parallel_manager.add(env, perform)` instead of sending the
   request, where `perform` is the work that would execute it.
2. Inside the manager's `execute`/`run`, re-check authorization for each queued
   request. Rejected requests are handed back to the caller (for example via a
   callback and a list) and their deferred work is never invoked.
3. Only confirmed requests reach the adapter. Since `Adapter#save_response`
   leaves a parallel response un-finished, do not call
   `env.response.finish(env)` for a rejected request. Its `on_complete`
   callbacks then never fire, so it is never reported as a successful response.

A fully runnable, in-memory implementation (a parallel-capable adapter plus a
manager that runs three queued requests, confirms them at execution time, and
keeps the revoked one from ever going out) is available in
[`examples/parallel_authorization_spec.rb`](https://github.com/lostisland/faraday/blob/main/examples/parallel_authorization_spec.rb).
