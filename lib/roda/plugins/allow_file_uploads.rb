# frozen-string-literal: true

#
class Roda
  module RodaPlugins
    # The allow_file_uploads plugin adds an +r.allow_file_uploads+ method,
    # which allows file uploads for the current request.  This plugin is
    # designed to be combined with the disallow_file_uploads plugin, which
    # disallows file uploads by default.  Using both plugins allows you to
    # disallow file uploads in general, while allowing them in specific
    # routes.  The plugins should be loaded in this order:
    #
    #   plugin :disallow_file_uploads
    #   plugin :allow_file_uploads
    #
    # Then, in the specific routes where you want to allow file uploads,
    # call +r.allow_file_uploads+ before parsing the request body:
    #
    #   route do |r|
    #     r.post "tickets", Integer, "attachment" do |ticket_id|
    #       r.allow_file_uploads
    #
    #       # File uploads are allowed for this request, so r.params
    #       # will return uploaded files, and other form fields remain
    #       # available as usual.
    #     end
    #
    #     # All other routes still disallow file uploads.  If a request
    #     # to another route contains a multipart file upload, parsing
    #     # the request body raises
    #     # Roda::RodaPlugins::DisallowFileUploads::Error, and no
    #     # temporary file is created.
    #   end
    #
    # Note that +r.allow_file_uploads+ only affects the parsing of the
    # request body, so it must be called before the request body is parsed
    # (e.g. before +r.params+ or +r.POST+ is called).  Calling it after
    # the request body has been parsed has no effect.
    module AllowFileUploads
      module RequestMethods
        # Allow file uploads for the current request, by removing the
        # tempfile factory restriction that the disallow_file_uploads
        # plugin installs.
        def allow_file_uploads
          env.delete('rack.multipart.tempfile_factory')
        end
      end
    end

    register_plugin(:allow_file_uploads, AllowFileUploads)
  end
end
