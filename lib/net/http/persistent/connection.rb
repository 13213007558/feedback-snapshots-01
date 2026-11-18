##
# A Net::HTTP connection wrapper that holds extra information for managing the
# connection's lifetime.

class Net::HTTP::Persistent::Connection # :nodoc:

  attr_accessor :http

  attr_accessor :last_use

  attr_accessor :requests

  attr_accessor :ssl_generation

  ##
  # Whether this connection must use TLS.  It is part of the connection's
  # identity and is used to keep HTTP and HTTPS connections to the same
  # host:port in separate security contexts.

  attr_reader :use_ssl

  def initialize http_class, http_args, ssl_generation, use_ssl = false
    @http           = http_class.new(*http_args)
    @ssl_generation = ssl_generation
    @use_ssl        = use_ssl

    reset
  end

  def finish
    @http.finish
  rescue IOError
  ensure
    reset
  end
  alias_method :close, :finish

  def reset
    @last_use = Net::HTTP::Persistent::EPOCH
    @requests = 0
  end

  def ressl ssl_generation
    @ssl_generation = ssl_generation

    finish
  end

end
