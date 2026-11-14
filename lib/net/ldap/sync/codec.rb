# -*- ruby encoding: utf-8 -*-
class Net::LDAP::Sync
  ##
  # BER encode/decode helpers for the protocol elements defined in RFC 4533.
  #
  # Every public +decode_*+ method tolerates being handed either a raw BER
  # OCTET STRING (the value carried in a control or intermediate response)
  # or an already parsed BER array. Encoding methods return the complete
  # LDAP Control sequence (for request/state/done) or the intermediate
  # response payload expected by the test harness.
  module Codec
    module_function

    # BER syntax covering every tag that can appear inside an RFC 4533
    # control or Sync Info value: universal BOOLEAN/ENUMERATED/OCTET
    # STRING/SEQUENCE/SET plus the context-specific CHOICE tags [0]-[3].
    SYNC_SYNTAX = Net::BER.compile_syntax(
      universal: {
        primitive: {
          1 => :boolean,  # BOOLEAN
          2 => :integer,  # INTEGER
          4 => :string,   # OCTET STRING / syncUUID / syncCookie
          10 => :integer, # ENUMERATED
        },
        constructed: {
          16 => :array, # SEQUENCE
          17 => :array, # SET
        },
      },
      context_specific: {
        primitive: {
          0 => :string, # newcookie [0], responseName/value [0]/[1]
          1 => :string,
        },
        constructed: {
          0 => :array,
          1 => :array, # refreshDelete [1]
          2 => :array, # refreshPresent [2]
          3 => :array, # syncIdSet [3]
        },
      },
    )

    # Encode a complete Sync Request Control value.
    #
    #   syncRequestValue ::= SEQUENCE {
    #       mode ENUMERATED { refreshOnly (1), refreshAndPersist (3) },
    #       cookie     syncCookie OPTIONAL,
    #       reloadHint BOOLEAN DEFAULT FALSE
    #   }
    def encode_request_control(mode: MODE_REFRESH_ONLY, cookie: nil, reload_hint: false)
      value = [mode.to_ber_enumerated]
      value << cookie.to_ber if cookie && !cookie.empty?
      value << reload_hint.to_ber if reload_hint

      [
        OID::REQUEST.to_ber,
        false.to_ber,
        value.to_ber_sequence.to_s.to_ber,
      ].to_ber_sequence
    end

    # Parse a syncStateValue (section 2.3).
    #
    #   syncStateValue ::= SEQUENCE {
    #       state ENUMERATED { present(0), add(1), modify(2), delete(3) },
    #       entryUUID syncUUID,
    #       cookie    syncCookie OPTIONAL
    #   }
    #
    # Returns a hash with +:state+, +:uuid+ and an optional +:cookie+.
    def decode_state_value(ber)
      seq = as_array(ber)
      raise ProtocolError, "malformed syncStateValue" unless seq && seq.length.between?(2, 3)

      state = seq[0]
      uuid = seq[1]
      cookie = seq[2]
      unless STATE_NAMES.key?(state) && uuid.is_a?(String) && uuid.bytesize == 16
        raise ProtocolError, "invalid syncStateValue state or entryUUID"
      end

      result = { state: state, uuid: uuid.b }
      result[:cookie] = cookie if cookie.is_a?(String) && !cookie.empty?
      result
    end

    # Parse a syncDoneValue (section 2.4). The cookie field is OPTIONAL and
    # comes before the refreshDeletes BOOLEAN, so the elements are inspected
    # by type rather than by fixed position.
    #
    #   syncDoneValue ::= SEQUENCE {
    #       cookie          syncCookie OPTIONAL,
    #       refreshDeletes  BOOLEAN DEFAULT FALSE
    #   }
    def decode_done_value(ber)
      seq = as_array(ber)
      raise ProtocolError, "malformed syncDoneValue" unless seq

      cookie = nil
      refresh_deletes = false
      seq.each do |element|
        if element == true || element == false
          refresh_deletes = element
        elsif element.is_a?(String)
          cookie = element
        else
          raise ProtocolError, "unexpected element in syncDoneValue"
        end
      end

      { cookie: (cookie.nil? || cookie.empty?) ? nil : cookie.b, refresh_deletes: refresh_deletes }
    end

    # Parse a syncInfoValue CHOICE (section 2.5) carried in an Intermediate
    # Response. Returns a hash whose +:type+ is one of +:newcookie+,
    # +:refresh_delete+, +:refresh_present+ or +:sync_id_set+.
    #
    #   syncInfoValue ::= CHOICE {
    #       newcookie      [0] syncCookie,
    #       refreshDelete  [1] SEQUENCE { cookie OPTIONAL, refreshDone DEFAULT TRUE },
    #       refreshPresent [2] SEQUENCE { cookie OPTIONAL, refreshDone DEFAULT TRUE },
    #       syncIdSet      [3] SEQUENCE { cookie OPTIONAL,
    #                                     refreshDeletes DEFAULT FALSE,
    #                                     syncUUIDs SET OF syncUUID }
    #   }
    def decode_info_value(ber)
      parsed = ber.is_a?(String) ? ber.read_ber(SYNC_SYNTAX) : ber
      tag = parsed.respond_to?(:ber_identifier) ? parsed.ber_identifier : nil

      case tag
      when INFO_NEW_COOKIE
        raise ProtocolError, "newcookie syncInfoValue must be a string" unless parsed.is_a?(String)

        { type: :newcookie, cookie: parsed.b }
      when INFO_REFRESH_DELETE, INFO_REFRESH_PRESENT
        type = tag == INFO_REFRESH_DELETE ? :refresh_delete : :refresh_present
        # ASN.1 DEFAULT: refreshDone defaults to TRUE for refreshDelete and
        # FALSE for refreshPresent (RFC 4533 section 2.5). An omitted BOOLEAN
        # means the default applies.
        default_done = type == :refresh_delete
        cookie, refresh_done = parse_refresh_phase(parsed, default_done)
        { type: type, cookie: cookie, refresh_done: refresh_done }
      when INFO_SYNC_ID_SET
        parse_id_set(parsed)
      else
        raise ProtocolError, "unknown syncInfoValue choice (tag=#{tag.inspect})"
      end
    end

    # Locate and decode the Sync State Control on a SearchResultEntry PDU.
    # Returns nil when the entry carries no Sync State Control.
    def state_control(pdu)
      control = find_control(pdu, OID::STATE)
      control && decode_state_value(control.value)
    end

    # Locate and decode the Sync Done Control on a SearchResultDone PDU.
    # Returns nil when no Sync Done Control is present.
    def done_control(pdu)
      control = find_control(pdu, OID::DONE)
      control && decode_done_value(control.value)
    end

    # Decode the Sync Info intermediate response (application tag 25).
    # Returns nil unless the responseName is the Sync Info OID.
    def info_message(pdu)
      return nil unless pdu.respond_to?(:intermediate_response)
      response = pdu.intermediate_response
      return nil unless response && response[:name] == OID::INFO

      decode_info_value(response[:value])
    end

    def as_array(ber)
      return ber if ber.is_a?(Array)

      # RFC 4533 control values are universal SEQUENCEs. The LDAP AsnSyntax
      # table does not map the universal 0x30/0x31 tags encountered while
      # descending from a context-specific wrapper, so parse with a syntax
      # that knows universal SEQUENCE/SET/BOOLEAN alongside the sync choices.
      ber.read_ber(SYNC_SYNTAX) if ber.is_a?(String)
    end
    private :as_array

    # A context-specific constructed CHOICE ([1]/[2]/[3]) parses to an array
    # whose single element is the inner SEQUENCE. Collapse that wrapper so
    # the parsing methods see the field list directly.
    def unwrap_choice(seq)
      if seq.is_a?(Array) && seq.length == 1 && seq.first.is_a?(Array)
        seq.first
      else
        seq
      end
    end
    private :unwrap_choice

    def find_control(pdu, oid)
      return nil unless pdu.respond_to?(:ldap_controls)

      pdu.ldap_controls.find { |control| control.oid == oid }
    end
    private :find_control

    def parse_refresh_phase(seq, default_refresh_done)
      seq = unwrap_choice(seq)
      raise ProtocolError, "malformed refresh phase syncInfoValue" unless seq.is_a?(Array)

      cookie = nil
      refresh_done = default_refresh_done
      seq.each do |element|
        if element == true || element == false
          refresh_done = element
        elsif element.is_a?(String)
          cookie = element
        else
          raise ProtocolError, "unexpected element in refresh phase syncInfoValue"
        end
      end

      [cookie.nil? || cookie.empty? ? nil : cookie.b, refresh_done]
    end
    private :parse_refresh_phase

    def parse_id_set(seq)
      seq = unwrap_choice(seq)
      raise ProtocolError, "malformed syncIdSet syncInfoValue" unless seq.is_a?(Array)

      cookie = nil
      # ASN.1 DEFAULT FALSE (RFC 4533 section 2.5).
      refresh_deletes = false
      uuids = nil
      seq.each do |element|
        if element == true || element == false
          refresh_deletes = element
        elsif element.is_a?(String)
          cookie = element
        elsif element.is_a?(Array)
          uuids = element
        else
          raise ProtocolError, "unexpected element in syncIdSet syncInfoValue"
        end
      end

      raise ProtocolError, "syncIdSet missing syncUUIDs SET" unless uuids.is_a?(Array)

      uuids.each do |uuid|
        unless uuid.is_a?(String) && uuid.bytesize == 16
          raise ProtocolError, "syncIdSet contains an invalid syncUUID"
        end
      end

      {
        type: :sync_id_set,
        cookie: cookie.nil? || cookie.empty? ? nil : cookie.b,
        refresh_deletes: refresh_deletes,
        uuids: uuids.map(&:b),
      }
    end
    private :parse_id_set
  end
end
