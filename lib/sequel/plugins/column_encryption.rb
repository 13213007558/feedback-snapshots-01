# frozen-string-literal: true

# simplecov:disable
raise(Sequel::Error, "Sequel column_encryption plugin requires ruby 2.3 or greater") unless RUBY_VERSION >= '2.3'
# simplecov:enable

require 'openssl'

begin
  # Test cipher actually works
  cipher = OpenSSL::Cipher.new("aes-256-gcm")
  cipher.encrypt
  cipher.key = '1'*32
  cipher_iv = cipher.random_iv
  cipher.auth_data = ''
  cipher_text = cipher.update('2') << cipher.final
  auth_tag = cipher.auth_tag

  cipher = OpenSSL::Cipher.new("aes-256-gcm")
  cipher.decrypt
  cipher.iv = cipher_iv
  cipher.key = '1'*32
  cipher.auth_data = ''
  cipher.auth_tag = auth_tag
  # simplecov:disable
  unless (cipher.update(cipher_text) << cipher.final) == '2'
    raise OpenSSL::Cipher::CipherError
  end
rescue RuntimeError, OpenSSL::Cipher::CipherError
  raise LoadError, "Sequel column_encryption plugin requires a working aes-256-gcm cipher"
  # simplecov:enable
end

require 'securerandom'
require 'monitor'

module Sequel
  module Plugins
    # The column_encryption plugin adds support for encrypting the content of individual
    # columns in a table.
    #
    # Column values are encrypted with AES-256-GCM using a per-value cipher key derived from
    # a key provided in the configuration using HMAC-SHA256.
    #
    # = Usage
    #
    # If you would like to support encryption of columns in more than one model, you should
    # probably load the plugin into the parent class of your models and specify the keys:
    #
    #   Sequel::Model.plugin :column_encryption do |enc|
    #     enc.key 0, ENV["SEQUEL_COLUMN_ENCRYPTION_KEY"]
    #   end
    #
    # This specifies a single master encryption key.  Unless you are actively rotating keys,
    # it is best to use a single master key.  Rotation of encryption keys will be discussed
    # in a later section.
    #
    # In the above call, <tt>0</tt> is the id of the key, and the
    # <tt>ENV["SEQUEL_COLUMN_ENCRYPTION_KEY"]</tt> is the content of the key, which must be
    # a string with exactly 32 bytes. As indicated, this key should not be hardcoded or
    # otherwise committed to the source control repository.
    #
    # For models that need encrypted columns, you load the plugin again, but specify the
    # columns to encrypt:
    #
    #   ConfidentialModel.plugin :column_encryption do |enc|
    #     enc.column :encrypted_column_name
    #     enc.column :searchable_column_name, searchable: true
    #     enc.column :ci_searchable_column_name, searchable: :case_insensitive
    #   end
    #
    # With this, all three specified columns (+encrypted_column_name+, +searchable_column_name+,
    # and +ci_searchable_column_name+) will be marked as encrypted columns.  When you run the
    # following code:
    #
    #   ConfidentialModel.create(
    #     encrypted_column_name: 'These',
    #     searchable_column_name: 'will be',
    #     ci_searchable_column_name: 'Encrypted'
    #   )
    #
    # It will save encrypted versions to the database.  +encrypted_column_name+ will not be
    # searchable, +searchable_column_name+ will be searchable with an exact match, and
    # +ci_searchable_column_name+ will be searchable with a case insensitive match. See section
    # below for details on searching.
    #
    # It is possible to have model-specific keys by specifying both the +key+ and +column+ methods
    # in the model:
    #
    #   ConfidentialModel.plugin :column_encryption do |enc|
    #     enc.key 0, ENV["SEQUEL_MODEL_SPECIFIC_ENCRYPTION_KEY"]
    #
    #     enc.column :encrypted_column_name
    #     enc.column :searchable_column_name, searchable: true
    #     enc.column :ci_searchable_column_name, searchable: :case_insensitive
    #   end
    #
    # When the +key+ method is called inside the plugin block, previous keys are ignored,
    # and only the new keys specified will be used.  This approach would allow the
    # +ConfidentialModel+ to use the model specific encryption keys, and other models
    # to use the default keys specified in the parent class.
    #
    # The +key+ and +column+ methods inside the plugin block support additional options.
    # The +key+ method supports the following options:
    #
    # :auth_data :: The authentication data to use for the AES-256-GCM cipher. Defaults
    #               to the empty string.
    # :padding :: The number of padding bytes to use. For security, data is padded so that
    #             a database administrator cannot determine the exact size of the
    #             unencrypted data.  By default, this value is 8, which means that
    #             unencrypted data will be padded to a multiple of 8 bytes. Up to twice as
    #             much padding as specified will be used, as the number of padding bytes
    #             is partially randomized.
    #
    # The +column+ method supports the following options:
    #
    # :searchable :: Whether the column is searchable.  This should not be used unless
    #                searchability is needed, as it can allow the database administrator
    #                to determine whether two distinct rows have the same unencrypted
    #                data (but not what that data is).  This can be set to +true+ to allow
    #                searching with an exact match, or +:case_insensitive+ for a case
    #                insensitive match.
    # :search_both :: This should only be used if you have previously switched the
    #                 +:searchable+ option from +true+ to +:case_insensitive+ or vice-versa,
    #                 and would like the search to return values that have not yet been
    #                 reencrypted.  Note that switching from +true+ to +:case_insensitive+
    #                 isn't a problem, but switching from +:case_insensitive+ to +true+ and
    #                 using this option can cause the search to return values that are
    #                 not an exact match.  You should manually filter those objects
    #                 after decrypting if you want to ensure an exact match.
    # :format :: The format of the column, if you want to perform serialization before
    #            encryption and deserialization after decryption.  Can be either a
    #            symbol registered with the serialization plugin or an array of two
    #            callables, the first for serialization and the second for deserialization.
    #
    # The +column+ method also supports a block for column-specific keys:
    #
    #   ConfidentialModel.plugin :column_encryption do |enc|
    #     enc.column :encrypted_column_name do |cenc|
    #       cenc.key 0, ENV["SEQUEL_COLUMN_SPECIFIC_ENCRYPTION_KEY"]
    #     end
    #
    #     enc.column :searchable_column_name, searchable: true
    #     enc.column :ci_searchable_column_name, searchable: :case_insensitive
    #   end
    #
    # In this case, the <tt>ENV["SEQUEL_COLUMN_SPECIFIC_ENCRYPTION_KEY"]</tt> key will
    # only be used for the +:encrypted_column_name+ column, and not the other columns.
    #
    # Note that there isn't a security reason to prefer either model-specific or
    # column-specific keys, as the actual cipher key used is unique per column value.
    #
    # Note that changing the key_id, key string, or auth_data for an existing key will
    # break decryption of values encrypted with that key.  If you would like to change
    # any aspect of the key, add a new key, rotate to the new encryption key, and then
    # remove the previous key, as described in the section below on key rotation.
    #
    # = Searching Encrypted Values
    #
    # To search searchable encrypted columns, use +with_encrypted_value+.  This example
    # code will return the model instance created in the code example in the previous
    # section:
    #
    #   ConfidentialModel.
    #     with_encrypted_value(:searchable_column_name, "will be")
    #     with_encrypted_value(:ci_searchable_column_name, "encrypted").
    #     first
    #
    # = Encryption Key Rotation
    #
    # To rotate encryption keys, add a new key above the existing key, with a new key ID:
    #
    #   Sequel::Model.plugin :column_encryption do |enc|
    #     enc.key 1, ENV["SEQUEL_COLUMN_ENCRYPTION_KEY"]
    #     enc.key 0, ENV["SEQUEL_OLD_COLUMN_ENCRYPTION_KEY"]
    #   end
    #
    # Newly encrypted data will then use the new key.  Records encrypted with the older key
    # will still be decrypted correctly.
    #
    # To force reencryption for existing records that are using the older key, you can use
    # the +needing_reencryption+ dataset method and the +reencrypt+ instance method. For a
    # small number of records, you can probably do:
    #
    #   ConfidentialModel.needing_reencryption.all(&:reencrypt)
    #
    # With more than a small number of records, you'll want to do this in batches.  It's
    # possible you could use an approach such as:
    #
    #   ds = ConfidentialModel.needing_reencryption.limit(100)
    #   true until ds.all(&:reencrypt).empty?
    #
    # However, that approach is not safe if the application is still updating the same
    # records, as +reencrypt+ saves the entire row and can overwrite columns changed by
    # the application after the row was retrieved.  It also has no way to record the
    # rows it has completed, so restarting it starts from the beginning.
    #
    # For an online rotation where the application can update records concurrently, use
    # +rotate_encryption+ instead:
    #
    #   result = ConfidentialModel.rotate_encryption(batch_size: 100)
    #   result.last_pk  # => primary key of the last row processed
    #   result.errors   # => rows that could not be rotated, with their exceptions
    #
    # +rotate_encryption+ only updates the encrypted columns that need rotating, and
    # only if their values are still the same as when they were read.  If the
    # application changes a row between the read and the update, the update does not
    # affect the row.  If the application already stored the value with the current
    # key, the row is counted as skipped, otherwise it is recorded in
    # <tt>result.conflicts</tt> for a later pass.  Values encrypted with the old key
    # remain readable during the transition, as long as the old key is still in the
    # configuration.
    #
    # The following options are supported by +rotate_encryption+:
    #
    # :batch_size :: The maximum number of rows to process in each batch. Defaults
    #                to 100.
    # :after :: Only process rows with a primary key greater than this value.  Use
    #           <tt>result.last_pk</tt> from a previous run to resume where the
    #           previous run stopped.  Rows at or before this value are not
    #           examined, so pass a lower value or omit this option if you need
    #           to retry rows reported in <tt>result.errors</tt> or
    #           <tt>result.conflicts</tt> from the previous run.
    # :max_batches :: The maximum number of batches to process in this call.  This
    #                 allows deliberately stopping a rotation, and then resuming it
    #                 later with <tt>after: result.last_pk</tt>.
    # :checkpoint :: A callable called with the primary key after each batch has
    #                been processed.  Use this to durably store the resume position.
    #                If the process exits in the middle of a batch, the rows at the
    #                start of the batch that were already rotated are not returned by
    #                +needing_reencryption+, so the next run skips them.  Rows at or
    #                before the checkpoint are not reexamined when resuming, so rows
    #                reported in <tt>result.errors</tt> or <tt>result.conflicts</tt>
    #                before the checkpoint need to be retried separately (the
    #                +:on_error+ and +:on_conflict+ callbacks can record them).
    # :raise_on_error :: If true, raise an error for a row that cannot be rotated
    #                    instead of recording it in <tt>result.errors</tt>.
    # :on_error :: A callable called with a RowError for each row that cannot be
    #              rotated, as soon as the error occurs.  Use this to durably
    #              record the row for later handling.  The row is also added to
    #              <tt>result.errors</tt>.
    # :on_conflict :: A callable called with a RowConflict for each row changed
    #                 concurrently that still needs rotation, as soon as the
    #                 conflict is detected.  The conflict is also added to
    #                 <tt>result.conflicts</tt>.
    # :server :: The database server/shard to use.
    #
    # +rotate_encryption+ requires the model to have a single column primary key.  It
    # returns a Sequel::Plugins::ColumnEncryption::Rotation object with the following
    # methods:
    #
    # processed :: The number of rows examined.
    # rotated :: The number of rows rotated to the current key.
    # skipped :: The number of rows that did not need rotation when processed.
    # conflicts :: An array of RowConflict objects for rows changed concurrently that
    #              still need rotation.  Each object has +primary_key+ and +columns+
    #              methods.
    # errors :: An array of RowError objects for rows that could not be rotated.
    #           Each object has +primary_key+, +columns+, and +exception+ methods.
    # batches :: The number of batches processed.
    # last_pk :: The primary key of the last row examined.  Pass this as the +:after+
    #            option to resume from this position.
    #
    # A row that is already using the current key is not returned by
    # +needing_reencryption+, and rows that are rotated concurrently by the application
    # are skipped.  This makes it safe to run the rotation more than once, and to run
    # it concurrently from multiple processes, though using a single process with
    # checkpointing is recommended.
    #
    # A row that raised an error is included in <tt>result.errors</tt> so it can be
    # investigated separately.  Errors affecting the database connection (such as
    # a disconnect) are not treated as row errors, and stop the rotation.
    #
    # After all values have been reencrypted for all models, and no models use the older
    # encryption key, you can remove it from the configuration:
    #
    #   Sequel::Model.plugin :column_encryption do |enc|
    #     enc.key 1, ENV["SEQUEL_COLUMN_ENCRYPTION_KEY"]
    #   end
    #
    # Once an encryption key has been removed, after no data uses it, it is safe to reuse
    # the same key id for a new key.  This approach allows for up to 256 concurrent keys
    # in the same configuration.
    #
    # = Encrypting Additional Formats
    #
    # By default, the column_encryption plugin assumes that the decrypted data should be
    # returned as a string, and a string will be passed to encrypt.  However, using the
    # +:format+ option, you can specify an alternate format.  For example, if you want to
    # encrypt a JSON representation of the object, so that you can deal with an array/hash
    # and automatically have it serialized with JSON and then encrypted when saving, and
    # then deserialized with JSON after decryption when it is retrieved:
    #
    #   require 'json'
    #   ConfidentialModel.plugin :column_encryption do |enc|
    #     enc.key 0, ENV["SEQUEL_MODEL_SPECIFIC_ENCRYPTION_KEY"]
    #
    #     enc.column :encrypted_column_name
    #     enc.column :searchable_column_name, searchable: true
    #     enc.column :ci_searchable_column_name, searchable: :case_insensitive
    #     enc.column :encrypted_json_column_name, format: :json
    #   end
    #
    # The values of the +:format+ are the same values you can pass as the first argument
    # to +serialize_attributes+ (in the serialization plugin).  You can pass an array
    # with the serializer and deserializer for custom support.
    #
    # You can use both +:searchable+ and +:format+ together for searchable encrypted
    # serialized columns.  However, note that this allows only exact searches of the
    # serialized version of the data.  So for JSON, a search for <tt>{'a'=>1, 'b'=>2}</tt>
    # would not match <tt>{'b'=>2, 'a'=>1}</tt> even though the objects are considered
    # equal.  If this is an issue, make sure you use a serialization format where all
    # equal objects are serialized to the same string.
    #
    # = Enforcing Uniqueness
    #
    # You cannot enforce uniqueness of unencrypted data at the database level
    # if you also want to support key rotation.  However, absent key rotation, a
    # unique index on the first 48 characters of the encrypted column can enforce uniqueness,
    # as long as the column is searchable.  If the encrypted column is case-insensitive
    # searchable, the uniqueness is case insensitive as well.
    #
    # = Column Value Cryptography/Format
    #
    # Column values used by this plugin use the following format (+key+ is specified
    # in the plugin configuration and must be exactly 32 bytes):
    #
    # column_value :: urlsafe_base64(flags + NUL + key_id + NUL + search_data + key_data +
    #                 cipher_iv + cipher_auth_tag + encrypted_data)
    # flags :: 1 byte, the type of record (0: not searchable, 1: searchable, 2: lowercase searchable)
    # NUL :: 1 byte, ASCII NUL
    # key_id :: 1 byte, the key id, supporting 256 concurrently active keys (0 - 255)
    # search_data :: 0 bytes if flags is 0, 32 bytes if flags is 1 or 2.
    #                Format is HMAC-SHA256(key, unencrypted_data).
    #                Ignored on decryption, only used for searching.
    # key_data :: 32 bytes random data used to construct cipher key
    # cipher_iv :: 12 bytes, AES-256-GCM cipher random initialization vector
    # cipher_auth_tag :: 16 bytes, AES-256-GCM cipher authentication tag
    # encrypted_data :: AES-256-GCM(HMAC-SHA256(key, key_data),
    #                   padding_size + padding + unencrypted_data)
    # padding_size :: 1 byte, with the amount of padding (0-255 bytes of padding allowed)
    # padding :: number of bytes specified by padding size, ignored on decryption
    # unencrypted_data :: actual column value
    #
    # The reason for <tt>flags + NUL + key_id + NUL</tt> (4 bytes) as the header is to allow for
    # an easy way to search for values needing reencryption using a database index.  It takes
    # the first three bytes and converts them to base64, and looks for values less than that value
    # or greater than that value with 'B' appended. The NUL byte in the fourth byte of the header
    # ensures that after base64 encoding, the fifth byte in the column will be 'A'.
    #
    # The reason for <tt>search_data</tt> (32 bytes) directly after is that for searchable values,
    # after base64 encoding of the header and search data, it is 48 bytes and can be used directly
    # as a prefix search on the column, which can be supported by the same database index.  This is
    # more efficient than a full column value search for large values, and allows for case-insensitive
    # searching without a separate column, by having the search_data be based on the lowercase value
    # while the unencrypted data is original case.
    #
    # The reason for the padding is so that a database administrator cannot be sure exactly how
    # many bytes are in the column.  It is stored encrypted because otherwise the database
    # administrator could calculate it by decoding the base64 data.
    #
    # = Unsupported Features
    #
    # The following features are deliberately not supported:
    #
    # == Compression
    #
    # Allowing compression with encryption is inviting security issues later.
    # While padding can reduce the risk of compression with encryption, it does not
    # eliminate it entirely.  Users that must have compression with encryption can use
    # the +:format+ option with a serializer that compresses and a deserializer that
    # decompresses.
    #
    # == Mixing Encrypted/Unencrypted Data
    #
    # Mixing encrypted and unencrypted data increases the complexity and security risk, since there
    # is a chance unencrypted data could look like encrypted data in the pathologic case.
    # If you have existing unencrypted data that would like to encrypt, create a new column for
    # the encrypted data, and then migrate the data from the unencrypted column to the encrypted
    # column.  After all unencrypted values have been migrated, drop the unencrypted column.
    #
    # == Arbitrary Encryption Schemes
    #
    # Supporting arbitrary encryption schemes increases the complexity risk.
    # If in the future AES-256-GCM is not considered a secure enough cipher, it is possible to
    # extend the current format using the reserved values in the first two bytes of the header.
    #
    # = Caveats
    #
    # As column_encryption is a model plugin, it only works with using model instance methods.
    # If you directly modify the database using a dataset or an external program that modifies
    # the contents of the encrypted columns, you will probably corrupt the data. To make data
    # corruption less likely, it is best to have a CHECK constraints on the encrypted column
    # with a basic format and length check:
    #
    #   DB.alter_table(:table_name) do
    #     c = Sequel[:encrypted_column_name]
    #     add_constraint(:encrypted_column_name_format,
    #                    c.like('AA__A%') | c.like('Ag__A%') | c.like('AQ__A%'))
    #     add_constraint(:encrypted_column_name_length, Sequel.char_length(c) >= 88)
    #   end
    #
    # If possible, it's also best to check that the column is valid urlsafe base64 data of
    # sufficient length. This can be done on PostgreSQL using a combination of octet_length,
    # decode, and regexp_replace:
    #
    #   DB.alter_table(:ce_test) do
    #     c = Sequel[:encrypted_column_name]
    #     add_constraint(:enc_base64) do
    #       octet_length(decode(regexp_replace(regexp_replace(c, '_', '/', 'g'), '-', '+', 'g'), 'base64')) >= 65
    #     end
    #   end
    #
    # Such constraints will probably be sufficient to protect against most unintentional corruption of
    # encrypted columns.
    #
    # If the database supports transparent data encryption and you trust the database administrator,
    # using the database support is probably a better approach.
    #
    # The column_encryption plugin is only supported on Ruby 2.3+ and when the Ruby openssl standard
    # library supports the AES-256-GCM cipher.
    module ColumnEncryption
      # Cryptor handles the encryption and decryption of rows for a key set.
      # It also provides methods that return search prefixes, which datasets
      # use in queries.
      #
      # The same cryptor can support non-searchable, searchable, and case-insensitive
      # searchable columns.
      class Cryptor # :nodoc:
        # Flags
        NOT_SEARCHABLE = 0
        SEARCHABLE = 1
        LOWERCASE_SEARCHABLE = 2

        # This is the default padding, but up to 2x the padding can be used for a record.
        DEFAULT_PADDING = 8

        # Keys should be an array of arrays containing key_id, key string, auth_data, and padding.
        def initialize(keys)
          if !keys || keys.empty?
            raise Error, "Cannot initialize encryptor without encryption key"
          end

          # First key is used for encryption
          @key_id, @key, @auth_data, @padding = keys[0]

          # All keys are candidates for decryption
          @key_map = {}
          keys.each do |key_id, key, auth_data, padding|
            @key_map[key_id] = [key, auth_data, padding].freeze
          end

          freeze
        end

        # Decrypt using any supported format and any available key.
        def decrypt(data)
          begin
            data = urlsafe_decode64(data)
          rescue ArgumentError
            raise Error, "Unable to decode encrypted column: invalid base64"
          end

          unless data.getbyte(1) == 0 && data.getbyte(3) == 0
            raise Error, "Unable to decode encrypted column: invalid format"
          end

          flags = data.getbyte(0)

          key, auth_data = @key_map[data.getbyte(2)]
          unless key
            raise Error, "Unable to decode encrypted column: invalid key id"
          end

          case flags
          when NOT_SEARCHABLE
            if data.bytesize < 65
              raise Error, "Decoded encrypted column smaller than minimum size"
            end

            data.slice!(0, 4)
          when SEARCHABLE, LOWERCASE_SEARCHABLE
            if data.bytesize < 97
              raise Error, "Decoded encrypted column smaller than minimum size"
            end

            data.slice!(0, 36)
          else
            raise Error, "Unable to decode encrypted column: invalid flags"
          end

          key_part = data.slice!(0, 32)
          cipher_iv = data.slice!(0, 12)
          auth_tag = data.slice!(0, 16)

          cipher = OpenSSL::Cipher.new("aes-256-gcm")
          cipher.decrypt
          cipher.iv = cipher_iv
          cipher.key = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, key, key_part)
          cipher.auth_data = auth_data
          cipher.auth_tag = auth_tag
          begin
            decrypted_data = cipher.update(data) << cipher.final
          rescue OpenSSL::Cipher::CipherError => e
            raise Error, "Unable to decrypt encrypted column: #{e.class} (probably due to encryption key or auth data mismatch or corrupt data)"
          end

          # Remove padding
          decrypted_data.slice!(0, decrypted_data.getbyte(0) + 1)

          decrypted_data
        end

        # Encrypt in not searchable format with the first configured encryption key.
        def encrypt(data)
          _encrypt(data, "#{NOT_SEARCHABLE.chr}\0#{@key_id.chr}\0")
        end

        # Encrypt in searchable format with the first configured encryption key.
        def searchable_encrypt(data)
          _encrypt(data, _search_prefix(data, SEARCHABLE, @key_id, @key))
        end

        # Encrypt in case insensitive searchable format with the first configured encryption key.
        def case_insensitive_searchable_encrypt(data)
          _encrypt(data, _search_prefix(data.downcase, LOWERCASE_SEARCHABLE, @key_id, @key))
        end

        # The prefix string of columns for the given search type and the first configured encryption key.
        # Used to find values that do not use this prefix in order to perform reencryption.
        def current_key_prefix(search_type)
          urlsafe_encode64("#{search_type.chr}\0#{@key_id.chr}")
        end

        # The prefix values to search for the given data (an array of strings), assuming the column uses
        # the searchable format.
        def search_prefixes(data)
          _search_prefixes(data, SEARCHABLE)
        end

        # The prefix values to search for the given data (an array of strings), assuming the column uses
        # the case insensitive searchable format.
        def lowercase_search_prefixes(data)
          _search_prefixes(data.downcase, LOWERCASE_SEARCHABLE)
        end

        # The prefix values to search for the given data (an array of strings), assuming the column uses
        # either the searchable or the case insensitive searchable format.  Should be used only when
        # transitioning between formats (used by the :search_both option when encrypting columns).
        def regular_and_lowercase_search_prefixes(data)
          search_prefixes(data) + lowercase_search_prefixes(data)
        end

        private

        if RUBY_VERSION >= '2.4'
          def decode64(str)
            str.unpack1("m0")
          end
        # simplecov:disable
        else
          def decode64(str)
            str.unpack("m0")[0]
          end
        # simplecov:enable
        end

        def urlsafe_encode64(bin)
          str = [bin].pack("m0")
          str.tr!("+/", "-_")
          str
        end

        def urlsafe_decode64(str)
          decode64(str.tr("-_", "+/"))
        end

        # An array of strings, one for each configured encryption key, to find encrypted values matching
        # the given data and search format.
        def _search_prefixes(data, search_type)
          @key_map.map do |key_id, (key, _)|
            urlsafe_encode64(_search_prefix(data, search_type, key_id, key))
          end
        end

        # The prefix to use for searchable data, including the HMAC-SHA256(key, data).
        def _search_prefix(data, search_type, key_id, key)
          "#{search_type.chr}\0#{key_id.chr}\0#{OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, key, data)}"
        end

        # Encrypt the data using AES-256-GCM, with the given prefix.
        def _encrypt(data, prefix)
          padding = @padding
          random_data = SecureRandom.random_bytes(32)
          cipher = OpenSSL::Cipher.new("aes-256-gcm")
          cipher.encrypt
          cipher.key = OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, @key, random_data)
          cipher_iv = cipher.random_iv
          cipher.auth_data = @auth_data

          cipher_text = String.new
          data_size = data.bytesize

          padding_size = if padding
            (padding * rand(1)) + padding - (data.bytesize % padding)
          else
            0
          end

          cipher_text << cipher.update(padding_size.chr)
          cipher_text << cipher.update(SecureRandom.random_bytes(padding_size)) if padding_size > 0
          cipher_text << cipher.update(data) if data_size > 0
          cipher_text << cipher.final

          urlsafe_encode64("#{prefix}#{random_data}#{cipher_iv}#{cipher.auth_tag}#{cipher_text}")
        end
      end

      # The object type yielded to blocks passed to the +column+ method inside
      # <tt>plugin :column_encryption</tt> blocks.  This is used to configure custom
      # per-column keys.
      class ColumnDSL # :nodoc:
        # An array of arrays for the data for the keys configured inside the block.
        attr_reader :keys

        def initialize
          @keys = []
        end

        # Verify that the key_id, key, and options are value.
        def key(key_id, key, opts=OPTS)
          unless key_id.is_a?(Integer) && key_id >= 0 && key_id <= 255
            raise Error, "invalid key_id argument, must be integer between 0 and 255"
          end

          unless key.is_a?(String) && key.bytesize == 32
            raise Error, "invalid key argument, must be string with exactly 32 bytes"
          end

          if opts.has_key?(:padding)
            if padding = opts[:padding]
              unless padding.is_a?(Integer) && padding >= 1 && padding <= 120
                raise Error, "invalid :padding option, must be between 1 and 120"
              end
            end
          else
            padding = Cryptor::DEFAULT_PADDING
          end

          @keys << [key_id, key, opts[:auth_data].to_s, padding].freeze
        end
      end

      # The object type yielded to <tt>plugin :column_encryption</tt> blocks,
      # used to configure encryption keys and encrypted columns.
      class DSL < ColumnDSL # :nodoc:
        # An array of arrays of data for the columns configured inside the block.
        attr_reader :columns

        def initialize
          super
          @columns = []
        end

        # Store the column information.
        def column(column, opts=OPTS, &block)
          @columns << [column, opts, block].freeze
        end
      end

      # Lock used to serialize rotation calls in the current process.  The
      # conditional updates used by rotation make it safe to run multiple
      # processes at the same time, but serializing rotation calls in the
      # same process avoids wasted work.
      ROTATION_LOCK = Monitor.new

      # A row that was modified concurrently while the rotation was running, and
      # that still contains values encrypted with an older key.  The +columns+
      # are the encrypted columns that the rotation was unable to update.
      RowConflict = Struct.new(:primary_key, :columns)

      # A row that could not be rotated because an exception was raised while
      # processing it.  The +columns+ are the encrypted columns being processed
      # when the exception was raised, and +exception+ is the exception raised.
      RowError = Struct.new(:primary_key, :columns, :exception)

      # The result of a call to +rotate_encryption+.  See the documentation for
      # +rotate_encryption+ for details on the methods.
      class Rotation
        # The number of rows examined.
        attr_reader :processed

        # The number of rows rotated to the current encryption key.
        attr_reader :rotated

        # The number of rows that did not need rotation when they were examined.
        attr_reader :skipped

        # An array of RowConflict instances for rows changed concurrently that
        # still need rotation.
        attr_reader :conflicts

        # An array of RowError instances for rows that could not be rotated.
        attr_reader :errors

        # The number of batches processed.
        attr_reader :batches

        # The primary key of the last row examined.  Pass this as the +:after+
        # option to +rotate_encryption+ to resume from this position.  Rows
        # that raised an error or conflicted with a concurrent update are
        # examined again only if they are not after this position.
        attr_reader :last_pk

        def initialize(last_pk=nil)
          @processed = 0
          @rotated = 0
          @skipped = 0
          @conflicts = []
          @errors = []
          @batches = 0
          @last_pk = last_pk
        end

        # Record a row that did not need rotation.
        def skip
          @processed += 1
          @skipped += 1
          nil
        end

        # Record a row that was rotated.
        def rotate
          @processed += 1
          @rotated += 1
          nil
        end

        # Record a row that was modified concurrently and still needs rotation.
        def conflict(primary_key, columns)
          @processed += 1
          @conflicts << RowConflict.new(primary_key, columns).freeze
          nil
        end

        # Record a row that could not be rotated.
        def error(primary_key, columns, exception)
          @processed += 1
          @errors << RowError.new(primary_key, columns, exception).freeze
          nil
        end

        # Record that a batch was processed, and the primary key of the last
        # row examined in the batch.
        def finish_batch(last_pk)
          @batches += 1
          @last_pk = last_pk
          nil
        end
      end

      def self.apply(model, opts=OPTS, &_)
        model.plugin :serialization
      end

      def self.configure(model)
        dsl = DSL.new
        yield dsl

        model.instance_exec do
          unless dsl.keys.empty?
            @column_encryption_keys = dsl.keys.freeze
            @column_encryption_cryptor = nil
          end

          @column_encryption_metadata = Hash[@column_encryption_metadata || {}]

          dsl.columns.each do |column, opts, block|
            _encrypt_column(column, opts, &block)
          end

          @column_encryption_metadata.freeze
        end
      end

      # This stores four callables for handling encryption, decryption, data searching,
      # and key searching.  One of these is created for each encrypted column.
      ColumnEncryptionMetadata = Struct.new(:encryptor, :decryptor, :data_searcher, :key_searcher) # :nodoc:

      module ClassMethods
        private

        # A hash with column symbol keys and ColumnEncryptionMetadata values for each
        # encrypted column.
        attr_reader :column_encryption_metadata

        # The default Cryptor to use for encrypted columns.  This is only overridden if
        # per-column keys are used.
        def column_encryption_cryptor
          @column_encryption_cryptor ||= Cryptor.new(@column_encryption_keys)
        end

        # Setup encryption for the given column.
        def _encrypt_column(column, opts)
          cryptor ||= if defined?(yield)
            dsl = ColumnDSL.new
            yield dsl
            Cryptor.new(dsl.keys)
          else
            column_encryption_cryptor
          end

          encrypt_method, search_prefixes_method, search_type = case searchable = opts[:searchable]
          when nil, false
            [:encrypt, nil, Cryptor::NOT_SEARCHABLE] 
          when true
            [:searchable_encrypt, :search_prefixes, Cryptor::SEARCHABLE] 
          when :case_insensitive
            [:case_insensitive_searchable_encrypt, :lowercase_search_prefixes, Cryptor::LOWERCASE_SEARCHABLE] 
          else
            raise Error, "invalid :searchable option for encrypted column: #{searchable.inspect}"
          end

          if searchable && opts[:search_both]
            search_prefixes_method = :regular_and_lowercase_search_prefixes
          end

          # Setup the callables used in the metadata.
          encryptor = cryptor.method(encrypt_method)
          decryptor = cryptor.method(:decrypt)
          data_searcher = cryptor.method(search_prefixes_method) if search_prefixes_method
          key_searcher = lambda{cryptor.current_key_prefix(search_type)}

          if format = opts[:format]
            if format.is_a?(Symbol)
              unless format = Sequel.synchronize{Serialization::REGISTERED_FORMATS[format]}
                raise(Error, "Unsupported serialization format: #{format} (valid formats: #{Sequel.synchronize{Serialization::REGISTERED_FORMATS.keys}.inspect})")
              end
            end

            # If a custom serialization format is used, override the
            # callables to handle serialization and deserialization.
            serializer, deserializer = format
            enc, dec, data_s = encryptor, decryptor, data_searcher
            encryptor = lambda do |data|
              enc.call(serializer.call(data))
            end
            decryptor = lambda do |data|
              deserializer.call(dec.call(data))
            end
            data_searcher = lambda do |data|
              data_s.call(serializer.call(data))
            end
          end

          # Setup the setter and getter methods to do encryption and decryption using
          # the serialization plugin.
          serialize_attributes([encryptor, decryptor], column)

          column_encryption_metadata[column] = ColumnEncryptionMetadata.new(encryptor, decryptor, data_searcher, key_searcher).freeze

          nil
        end
      end

      module ClassMethods
        Plugins.def_dataset_methods(self, [:with_encrypted_value, :needing_reencryption])

        # Rotate encrypted columns to the current encryption key in batches.
        # See the documentation for the column_encryption plugin for details
        # on the supported options and the object returned.
        def rotate_encryption(opts=OPTS)
          lock = ROTATION_LOCK.synchronize do
            @column_encryption_rotate_lock ||= Monitor.new
          end

          lock.synchronize do
            _rotate_encryption(opts)
          end
        end

        Plugins.inherited_instance_variables(self,
          :@column_encryption_cryptor=>nil,
          :@column_encryption_keys=>nil,
          :@column_encryption_metadata=>nil,
          :@column_encryption_rotate_lock=>nil,
        )

        private

        # The primary key column to use as a cursor for rotation, and the
        # metadata for all encrypted columns.
        def _rotation_pk_and_metadata
          case pk = primary_key
          when Symbol
            nil
          when Array
            raise Error, "cannot rotate encryption for a model with a composite primary key"
          else
            raise Error, "cannot rotate encryption for a model without a primary key"
          end

          [pk, column_encryption_metadata]
        end

        # Return the encrypted columns in the given row that need rotation, with
        # their current and rotated values.  The row should be a hash of column
        # values from the database.
        def _rotation_changes(row, metadata)
          changes = {}

          metadata.each do |column, column_metadata|
            value = row[column]
            next if value.nil?
            next if value.start_with?(column_metadata.key_searcher.call)

            changes[column] = [value, column_metadata.encryptor.call(column_metadata.decryptor.call(value))]
          end

          changes
        end

        # Return the columns in the row that still need rotation, using the
        # values for the given columns only.
        def _rotation_remaining_columns(row, metadata, columns)
          columns.select do |column|
            value = row[column]
            value && !value.start_with?(metadata[column].key_searcher.call)
          end
        end

        # Rotate a single row.  Uses a conditional update so that if the row
        # changed after it was fetched, the old values are not written over the
        # new values.  Returns :rotated, :skipped, or an array of the columns
        # that still need rotation (for conflicts).
        def _rotate_encryption_row(ds, pk, row, metadata)
          pk_value = row[pk]
          changes = _rotation_changes(row, metadata)

          if changes.empty?
            return :skipped
          end

          condition = {pk=>pk_value}
          changes.each do |column, (old_value, _)|
            condition[column] = old_value
          end
          new_values = Hash[changes.map{|column, (_, new_value)| [column, new_value]}]

          if ds.where(condition).update(new_values) == 1
            return :rotated
          end

          # The row changed between the fetch and the update.  Re-fetch the
          # encrypted columns to see if another process already rotated them
          # or rotated a different encrypted column in the same row.
          current = ds.
            where(pk=>pk_value).
            select(pk, *metadata.keys).
            naked.
            first

          return :skipped unless current

          remaining = _rotation_remaining_columns(current, metadata, metadata.keys)
          return :skipped if remaining.empty?

          remaining
        end

        # Rotate encrypted columns to the current encryption key in batches.
        # Calling this method concurrently on the same model is serialized in
        # the current process.  Concurrent changes by other processes are
        # handled by the conditional update in _rotate_encryption_row.
        def _rotate_encryption(opts)
          batch_size = opts.fetch(:batch_size, 100)
          unless batch_size.is_a?(Integer) && batch_size >= 1
            raise Error, "invalid :batch_size option, must be a positive integer"
          end

          if opts.has_key?(:max_batches)
            max_batches = opts[:max_batches]
            unless max_batches.is_a?(Integer) && max_batches >= 0
              raise Error, "invalid :max_batches option, must be a nonnegative integer"
            end
          end

          checkpoint = opts[:checkpoint]
          if checkpoint && !checkpoint.respond_to?(:call)
            raise Error, "invalid :checkpoint option, must respond to call"
          end

          on_error = opts[:on_error]
          if on_error && !on_error.respond_to?(:call)
            raise Error, "invalid :on_error option, must respond to call"
          end

          on_conflict = opts[:on_conflict]
          if on_conflict && !on_conflict.respond_to?(:call)
            raise Error, "invalid :on_conflict option, must respond to call"
          end

          raise_on_error = opts[:raise_on_error]
          server = opts[:server]
          pk, metadata = _rotation_pk_and_metadata
          after = opts[:after]
          result = Rotation.new(after)
          row_ds = server ? dataset.server(server) : dataset

          while max_batches.nil? || result.batches < max_batches
            rows_ds = dataset.
              needing_reencryption.
              select(pk, *metadata.keys).
              order(pk).
              limit(batch_size)
            rows_ds = rows_ds.where(Sequel[pk] > after) if after
            rows_ds = rows_ds.server(server) if server
            rows = rows_ds.naked.all
            break if rows.empty?

            # Advance the cursor for every row examined, including rows with
            # errors or conflicts.  Those rows are recorded separately in the
            # result, so they do not cause the rotation to get stuck on them.
            # If the process exits in the middle of a batch, no checkpoint is
            # recorded for the batch, and the next run resumes from the
            # previous checkpoint.  Rows already rotated in the partial batch
            # are skipped by the next run.
            after = rows.last[pk]

            rows.each do |row|
              begin
                case remaining = _rotate_encryption_row(row_ds, pk, row, metadata)
                when :rotated
                  result.rotate
                when :skipped
                  result.skip
                else
                  result.conflict(row[pk], remaining)
                  on_conflict.call(result.conflicts.last) if on_conflict
                end
              rescue Sequel::DatabaseDisconnectError, Sequel::DatabaseConnectionError
                # Errors affecting the database connection should stop the
                # rotation, and not be recorded as an error for a single row.
                raise
              rescue StandardError => e
                raise if raise_on_error
                result.error(row[pk], _rotation_changes_columns(row, metadata), e)
                on_error.call(result.errors.last) if on_error
              end
            end

            result.finish_batch(after)
            checkpoint.call(after) if checkpoint
            break if rows.length < batch_size
          end

          result
        end

        # The encrypted columns in the row that have not been rotated, for
        # error reporting if an exception is raised while processing the row.
        def _rotation_changes_columns(row, metadata)
          metadata.keys.select do |column|
            value = row[column]
            value && !value.start_with?(metadata[column].key_searcher.call)
          end
        end
      end

      module InstanceMethods
        # Reencrypt the model if needed.  Looks at all of the models encrypted columns
        # and if any were encrypted with older keys or a different format, reencrypt
        # with the current key and format and save the object.  Returns the object
        # if reencryption was needed, or nil if reencryption was not needed.
        def reencrypt
          do_save = false

          model.send(:column_encryption_metadata).each do |column, metadata|
            if (value = values[column]) && !value.start_with?(metadata.key_searcher.call)
              do_save = true
              values[column] = metadata.encryptor.call(metadata.decryptor.call(value))
            end
          end

          save if do_save
        end
      end

      module DatasetMethods
        # Filter the dataset to only match rows where the column contains an encrypted version
        # of value.  Only works on searchable encrypted columns.
        def with_encrypted_value(column, value)
          metadata = model.send(:column_encryption_metadata)[column]
          
          unless metadata && metadata.data_searcher
            raise Error, "lookup for encrypted column #{column.inspect} is not supported"
          end

          prefixes = metadata.data_searcher.call(value)
          where(Sequel.|(*prefixes.map{|v| Sequel.like(column, "#{escape_like(v)}%")}))
        end

        # Filter the dataset to exclude rows where all encrypted columns are already encrypted
        # with the current key and format.
        def needing_reencryption
          incorrect_column_prefixes = model.send(:column_encryption_metadata).map do |column, metadata|
            prefix = metadata.key_searcher.call
            (Sequel[column] < prefix) | (Sequel[column] > prefix + 'B')
          end

          where(Sequel.|(*incorrect_column_prefixes))
        end
      end
    end
  end
end
