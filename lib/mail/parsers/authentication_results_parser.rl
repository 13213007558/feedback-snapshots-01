# frozen_string_literal: true
require 'mail/utilities'
require 'mail/parser_tools'

begin
  original_verbose, $VERBOSE = $VERBOSE, nil

%%{
  machine authentication_results;
  alphtype int;

  # NOTE: every action commits its token directly and independently.
  # Ragel runs leaving actions of enclosing machines before enclosed
  # ones on the same transition, so nested "commit" actions would see
  # incomplete state. Token-level actions are safe: each token ends on
  # its own transition (or at EOF, which Ragel also handles).

  # authserv-id
  action authserv_id_s { authserv_id_s = p }
  action authserv_id_e { authres.authserv_id = chars(data, authserv_id_s, p-1) }
  action authserv_id_quoted { authres.authserv_id = qstr; qstr = nil }

  # authres-version
  action version_s { version_s = p }
  action version_e { authres.version = chars(data, version_s, p-1) }

  # "none" payload
  action none_e { authres.none = true }

  # methodspec: a new method token starts a new result entry
  action method_s { method_s = p }
  action method_e {
    current_entry = ResultStruct.new
    current_entry.method = chars(data, method_s, p-1)
    current_entry.properties = []
    current_entry.comments = []
    authres.results << current_entry
  }
  action method_version_s { method_version_s = p }
  action method_version_e { current_entry.method_version = chars(data, method_version_s, p-1) }
  action result_s { result_s = p }
  action result_e { current_entry.result = chars(data, result_s, p-1) }

  # reasonspec
  action reason_s { reason_s = p }
  action reason_e { current_entry.reason = chars(data, reason_s, p-1) }
  action reason_quoted { current_entry.reason = qstr; qstr = nil }

  # propspec
  action prop_type_s { prop_type_s = p }
  action prop_type_e {
    current_property = PropertyStruct.new
    current_property.type = chars(data, prop_type_s, p-1)
    current_entry.properties << current_property
  }
  action prop_name_s { prop_name_s = p }
  action prop_name_e { current_property.property = chars(data, prop_name_s, p-1) }
  action prop_value_s { prop_value_s = p }
  action prop_value_e { current_property.value = chars(data, prop_value_s, p-1) }
  action prop_value_quoted { current_property.value = qstr; qstr = nil }

  # Comments: captured with nesting depth so a "pass" (or anything else)
  # inside a comment is kept as comment text, never as a result token.
  action comment_begin {
    comment_depth += 1
    comment_s = p if comment_depth == 1
    fcall comment_tail;
  }
  action comment_exit {
    comment_depth -= 1
    if comment_depth == 0
      comment_text = chars(data, comment_s + 1, p - 1)
      if current_entry
        current_entry.comments << comment_text
      else
        authres.comments << comment_text
      end
    end
    fret;
  }

  # Quoted String
  action qstr_s { qstr_s = p }
  action qstr_e { qstr = chars(data, qstr_s, p-1) }

  include rfc8601_authentication_results "rfc8601_authentication_results.rl";
  main := authentication_results;
}%%

module Mail::Parsers
  module AuthenticationResultsParser
    extend Mail::ParserTools

    PropertyStruct = Struct.new(:type, :property, :value)
    ResultStruct = Struct.new(:method, :method_version, :result, :reason, :properties, :comments)
    AuthenticationResultsStruct = Struct.new(:authserv_id, :version, :none, :results, :comments, :error)

    %%write data noprefix;

    def self.parse(data)
      data = data.dup.force_encoding(Encoding::ASCII_8BIT) if data.respond_to?(:force_encoding)

      raise Mail::Field::NilParseError.new(Mail::AuthenticationResultsElement) if data.nil?

      authres = AuthenticationResultsStruct.new
      authres.none = false
      authres.results = []
      authres.comments = []

      # Parser state
      authserv_id_s = version_s = method_s = method_version_s = result_s = nil
      reason_s = prop_type_s = prop_name_s = prop_value_s = comment_s = qstr_s = nil
      qstr = nil
      current_entry = nil
      current_property = nil
      comment_depth = 0

      # 5.1 Variables Used by Ragel
      p = 0
      eof = pe = data.length
      stack = []

      %%write init;
      %%write exec;

      if p != eof || cs < %%{ write first_final; }%%
        raise Mail::Field::IncompleteParseError.new(Mail::AuthenticationResultsElement, data, p)
      end

      authres
    end
  end
end

ensure
  $VERBOSE = original_verbose
end
