require 'net/ssh/errors'
require 'net/ssh/known_hosts'
require 'net/ssh/verifiers/always'

module Net
  module SSH
    module Verifiers
      # Does a strict host verification, looking the server up in the known
      # host files to see if a key has already been seen for this server. If this
      # server does not appear in any host file, this will register the key in a
      # known hosts file and only accept it once that registration succeeded (or
      # once another connection registered the same key first). It never trusts
      # a key whose registration failed, and two connections racing to register
      # a new host can't both store a key: the second one finds the first one's
      # key and either matches it or raises HostKeyMismatch. If the server does
      # appear at least once, but the key given does not match any known for the
      # server, an exception will be raised (HostKeyMismatch). A key marked
      # @revoked, a certificate failing its constraints, or a key that can't be
      # written raises as well. Otherwise, this returns true.
      class AcceptNew < Always
        def verify(arguments)
          super
        rescue HostKeyUnknown => err
          # Persists the key; if that fails, HostKeyWriteFailed propagates
          # and the connection is refused. No in-memory entry is kept.
          err.remember_host!
          true
        end

        def verify_signature(&block)
          yield
        rescue HostKeyUnknown => err
          err.remember_host!
          true
        end
      end
    end
  end
end
