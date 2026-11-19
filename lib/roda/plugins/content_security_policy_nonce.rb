# frozen-string-literal: true

#
class Roda
  module RodaPlugins
    # The content_security_policy_nonce plugin builds on top of the content_security_policy
    # plugin and helps with generating nonces for +script+ and +style+ tags. It is recommended
    # to avoid inline +script+ and +style+ tags, but if you must use them, this allows
    # safe usage via nonces. Enable by loading the plugin:
    #
    #   plugin :content_security_policy_nonce
    #
    # You can then generate nonce values by calling the +content_security_policy_nonce+ method:
    #
    #   r.get 'js' do
    #     "<script nonce=\"#{content_security_policy_nonce}\">alert('inline')</script>"
    #   end
    #
    # This method will return the nonce value to use, as well as allow the nonce for both
    # +script-src+ and +style-src+ in the +Content-Security-Policy+ response header.
    #
    # By default, nonce values are 44-byte random generated URL safe base64 strings. You can
    # override the default nonce generator by passing a block to the plugin:
    #
    #   plugin :content_security_policy_nonce do
    #     # this block must return a string.
    #   end
    #
    # The block is evaluated in route block scope context.
    #
    # When using a streaming response whose body is generated lazily, that is, after the
    # response headers have been sent (such as a body object whose +each+ method renders
    # the content when Rack iterates over it), the nonce must be declared before the headers
    # are finalized, since the +Content-Security-Policy+ header can no longer be modified
    # afterwards. Call +content_security_policy_nonce!+ while still inside the routing tree
    # to force the nonce to be generated and added to the header up front, then use the
    # returned value from inside the lazily generated body:
    #
    #   r.get 'stream' do
    #     nonce = content_security_policy_nonce!
    #     body = Object.new
    #     body.define_singleton_method(:each) do |&block|
    #       block.call %(<script nonce="#{nonce}">alert('inline')</script>)
    #     end
    #     r.halt response.finish_with_body(body)
    #   end
    #
    # Calling either nonce method for the first time after the response headers have been
    # finalized raises a +RodaError+, because a nonce generated at that point would not be
    # present in the +Content-Security-Policy+ header and the inline script would be blocked.
    # Streaming responses that do not use inline scripts simply do not need to call either
    # method, and no nonce is added to the header.
    module ContentSecurityPolicyNonce
      SCOPE_INSTANCE_VARIABLES = [:@content_security_policy_nonce].freeze

      def self.load_dependencies(app, &block)
        app.plugin :content_security_policy
      end

      def self.configure(app, &block)
        if block
          app.class_exec do
            define_method(:content_security_policy_nonce_generator, &block)
            private :content_security_policy_nonce_generator
          end
        end
      end

      module InstanceMethods
        # Return the content security policy nonce value. If one hasn't already
        # been generated, this generates it, and adds to the script-src and style-src
        # in the response's Content-Security-Policy header.
        #
        # Raises RodaError if the response headers have already been finalized,
        # since a nonce generated that late cannot be added to the
        # Content-Security-Policy header. Use content_security_policy_nonce!
        # before returning a lazily generated streaming body to declare the
        # nonce while the headers can still be modified.
        def content_security_policy_nonce
          @content_security_policy_nonce || generate_content_security_policy_nonce
        end

        # Declare that the response needs a content security policy nonce, generating
        # it and adding it to the Content-Security-Policy header before the response
        # headers are finalized. Returns the nonce value, which can be reused from a
        # lazily generated streaming body.
        #
        # Raises RodaError if the response headers have already been finalized.
        def content_security_policy_nonce!
          if @content_security_policy_nonce
            return @content_security_policy_nonce
          end

          if @_response.content_security_policy_headers_finalized?
            raise RodaError, "cannot declare content security policy nonce after " \
                             "response headers have been finalized"
          end

          generate_content_security_policy_nonce
        end

        private

        # Generate a nonce value. This method is overridden if the plugin
        # is passed a block.
        def content_security_policy_nonce_generator
          SecureRandom.urlsafe_base64(33)
        end

        # Generate the request nonce and allow it in the script-src and
        # style-src directives. Raises RodaError if the response headers
        # have already been finalized, as the policy header can no longer
        # be modified in that case.
        def generate_content_security_policy_nonce
          if @_response.content_security_policy_headers_finalized?
            raise RodaError, "content security policy nonce requested after response " \
                             "headers were finalized; call content_security_policy_nonce! " \
                             "before returning the streaming body"
          end

          nonce = @content_security_policy_nonce = content_security_policy_nonce_generator
          a = [:nonce, nonce]
          content_security_policy.add_script_src(a)
          content_security_policy.add_style_src(a)
          nonce
        end
      end

      module ResponseMethods
        # Whether the response headers have been finalized and can no longer
        # be modified by adding a nonce to the policy.
        def content_security_policy_headers_finalized?
          @content_security_policy_headers_finalized == true
        end

        # Finalize the response headers as usual, and remember that they can no
        # longer be modified afterwards.
        def finish
          @content_security_policy_headers_finalized = true
          super
        end

        # Finalize the response headers for a custom body as usual, and remember
        # that they can no longer be modified afterwards.
        def finish_with_body(body)
          @content_security_policy_headers_finalized = true
          super
        end
      end
    end

    register_plugin(:content_security_policy_nonce, ContentSecurityPolicyNonce)
  end
end
