require 'json'
require 'digest/sha2'
require 'time'

module Dnsruby
  # A portable record of the DNSSEC material that actually established (or
  # failed to establish) a validation conclusion.
  #
  # Evidence is content addressed: every RR and RRSIG is stored once under the
  # SHA-256 of its canonical wire form, and steps refer to those ids. Steps
  # describe only material the validator used. Candidate keys and signatures
  # that were considered but not selected are kept in "candidates" and are
  # deliberately excluded from the explanation digest, so adding an unrelated
  # valid signature cannot change the explanation.
  #
  # ValidationEvidence.replay rechecks the recorded edges without any network
  # access, at a fixed validation time and against a fixed anchor policy.
  class ValidationEvidence
    FORMAT = 'dnsruby-dnssec-evidence'.freeze
    VERSION = 1

    class ReplayError < VerifyError; end

    class << self
      def capture(query, message)
        recorder = Recorder.new(query, message)
        with(recorder) { yield recorder }
        recorder
      end

      def current
        Thread.current[:dnsruby_validation_evidence]
      end

      def scope(label)
        recorder = current
        return yield unless recorder
        recorder.scope(label) { yield }
      end

      def mark_attempt(ok)
        current&.mark_attempt(ok)
      end

      def with(recorder)
        previous = current
        Thread.current[:dnsruby_validation_evidence] = recorder
        yield
      ensure
        Thread.current[:dnsruby_validation_evidence] = previous
      end

      def encode_rr(rr)
        MessageEncoder.new { |encoder| encoder.put_rr(rr, true) }.to_s.unpack1('H*')
      end

      def decode_rr(hex)
        MessageDecoder.new([hex].pack('H*')).get_rr
      end

      def record_id(rr)
        Digest::SHA256.hexdigest(encode_rr(rr))
      end

      # Replay a Hash, a JSON document, or a ValidationEvidence instance.
      def replay(document, time: nil, policy: nil)
        evidence = document.is_a?(ValidationEvidence) ? document : from(document)
        evidence.replay(time: time, policy: policy)
      end

      def from(document)
        case document
        when ValidationEvidence then document
        when String then new(JSON.parse(document))
        when Hash then new(deep_copy(document))
        else raise ArgumentError, "Expected validation evidence Hash or JSON, got #{document.class}"
        end
      rescue JSON::ParserError => e
        raise ReplayError, "Invalid validation evidence: #{e.message}"
      end

      def deep_copy(value)
        case value
        when Hash then value.each_with_object({}) { |(k, v), out| out[k.to_s] = deep_copy(v) }
        when Array then value.map { |v| deep_copy(v) }
        else value
        end
      end
    end

    attr_reader :data

    def initialize(data)
      @data = self.class.deep_copy(data)
      validate_document!
    end

    def query
      data['query'] || {}
    end

    def conclusion
      data['conclusion']
    end

    def error
      data['error']
    end

    def validation_time
      data['validation_time']
    end

    def policy
      data['policy'] || {}
    end

    def cache
      data['cache']
    end

    def steps
      Array(data['steps'])
    end

    def candidates
      Array(data['candidates'])
    end

    def records
      data['records'] || {}
    end

    def used_step_ids
      Array(data['used_step_ids'])
    end

    def used_steps
      steps.select { |step| use_step?(step) }
    end

    def cache_hit?
      cache.is_a?(Hash) && cache['hit'] == true
    end

    # Human-readable account of the used path. It never mentions candidates,
    # so an unused signature cannot appear as a successful step.
    def explanation_text
      lines = ["#{query['name']} #{query['type']} => #{conclusion}"]
      lines << "error: #{error}" if error
      lines << "cached: original conclusion #{cache['original_conclusion']}" if cache_hit?
      used_steps.each do |step|
        case step['kind']
        when 'trust_anchor'
          lines << "trust anchor #{step['name']} #{step['type']} key_tag=#{step['key_tag']} (#{step['verifier']})"
        when 'delegation'
          lines << "delegation #{step['parent']} -> #{step['child']} via DS #{Array(step['ds']).join(',')}"
        when 'delegation_absent'
          lines << "delegation #{step['parent']} -> #{step['child']}: no DS (#{step['proof']})"
        when 'delegation_failure'
          lines << "delegation #{step['parent']} -> #{step['child']} FAILED: #{step['error']}"
        when 'dnskey'
          lines << "DNSKEY #{step['name']} keys #{Array(step['keys']).join(',')}"
        when 'signature'
          lines << "signature #{step['role']} #{step['name']} #{step['type']} by key_tag=#{step['key_tag']}"
        when 'signature_failure'
          lines << "signature FAILED #{step['name']} #{step['type']}: #{step['error']}"
        when 'denial'
          lines << "denial #{step['proof']} #{step['name']} #{step['qtype']} records #{Array(step['records']).join(',')}"
        when 'denial_failure'
          lines << "denial FAILED #{step['proof']} #{step['name']}: #{step['error']}"
        when 'no_anchor'
          lines << "no anchor covers #{step['name']}"
        when 'unsigned_answer'
          lines << "unsigned answer #{step['name']} in signed zone #{step['signed_zone']}"
        when 'message_verified'
          lines << "message verified at #{step['security_level']}"
        end
      end
      lines.join("\n")
    end

    def explanation_digest
      data['explanation_digest']
    end

    def to_h
      self.class.deep_copy(data)
    end

    def to_json(*args)
      JSON.generate(to_h, *args)
    end

    def record(id)
      records[id]
    end

    # Return a copy with a record removed. Steps that refer to the record keep
    # the dangling id; replay reports the missing evidence.
    def without_record(id)
      copy = self.class.new(to_h)
      copy.data['records'].delete(id)
      copy
    end

    # Record that this conclusion was served from the cache. The cache
    # observation is provenance, not part of the explanation digest, so the
    # original proof identity is retained.
    def with_cache_hit(note: nil)
      copy = self.class.new(to_h)
      copy.data['cache'] = {
        'hit' => true,
        'original_conclusion' => conclusion,
        'original_explanation_digest' => explanation_digest,
        'note' => note || 'Answer came from the cache; its original validation evidence is attached.'
      }
      copy
    end

    # Change the recorded validation time and reseal the document.
    def with_validation_time(time)
      copy = self.class.new(to_h)
      copy.data['validation_time'] = time.to_i
      copy.data['validation_time_iso8601'] = Time.at(time.to_i).utc.iso8601
      copy.data['integrity'] = copy.recompute_integrity
      copy
    end

    # Return a copy with one extra (possibly unrelated) RR. The record is not
    # referenced by any step, so the explanation digest is unchanged.
    def with_record(rr)
      copy = self.class.new(to_h)
      id = self.class.record_id(rr)
      copy.data['records'][id] = record_hash(rr)
      copy
    end

    def without_explanation_record(id)
      copy = self.class.new(to_h)
      copy.data['records'].delete(id) if explanation_record_ids.include?(id)
      copy
    end

    # Recheck every edge at a fixed time and policy without network access.
    def replay(time: nil, policy: nil)
      Replay.new(self, time: time, policy: policy).run
    end

    def used_records
      ids = steps.select { |step| use_step?(step) }.flat_map { |step| referenced_record_ids(step) }
      ids.uniq.sort.each_with_object({}) { |id, out| out[id] = records[id] if records[id] }
    end

    def explanation
      {
        'conclusion' => conclusion,
        'steps' => used_steps.reject { |step| %w[also_scopes rejected unused].any? { |key| step.key?(key) } },
        'records' => used_records
      }
    end

    def recompute_explanation_digest
      Digest::SHA256.hexdigest(JSON.generate(canonical_explanation))
    end

    # Integrity is a seal over the whole explanation, including the exact
    # bytes of each used record. Records and candidates outside the
    # explanation can be added or removed without changing it.
    def recompute_integrity
      used_ids = used_step_ids
      used_steps = steps.select { |step| used_ids.include?(step['id']) }
      referenced = explanation_record_ids
      Digest::SHA256.hexdigest(JSON.generate(
        'time' => validation_time,
        'policy' => policy,
        'query' => query,
        'conclusion' => conclusion,
        'steps' => used_steps.map { |step| step.sort_by { |key, _| key.to_s }.to_h },
        'records' => referenced.map { |id| [id, records[id]] }
      ))
    end

    def integrity_ok?
      data['integrity'] == recompute_integrity
    end

    def use_step?(step)
      used_step_ids.empty? ? step['status'] != 'attempt_failed' : used_step_ids.include?(step['id'])
    end

    private

    def canonical_explanation
      ordered = steps.select { |step| use_step?(step) }.map do |step|
        step.sort_by { |key, _| key.to_s }.to_h
      end
      used = used_records
      {
        'query' => query,
        'conclusion' => conclusion,
        'steps' => ordered,
        'records' => used.keys.sort.map { |id| [id, used[id]] }
      }
    end

    def referenced_record_ids(step)
      ids = []
      %w[record key rrset records keys ds next_keys proofs].each do |field|
        value = step[field]
        case value
        when String then ids << value
        when Array then ids.concat(value.select { |entry| entry.is_a?(String) })
        end
      end
      ids << step['signature'] if step['kind'] == 'signature' && step['signature'].is_a?(String)
      Array(step['signature_steps']).each do |id|
        child = steps.find { |candidate| candidate['id'] == id }
        ids.concat(referenced_record_ids(child)) if child
      end
      if step['signature'].is_a?(String) && step['kind'] != 'signature'
        child = steps.find { |candidate| candidate['id'] == step['signature'] }
        ids.concat(referenced_record_ids(child)) if child
      end
      ids
    end

    def candidate_signatures
      candidates.select { |candidate| candidate['selected'] == false }
    end

    def record_hash(rr)
      {
        'name' => rr.name.to_s(true),
        'type' => rr.type.string,
        'class' => rr.klass.string,
        'ttl' => rr.ttl,
        'wire' => self.class.encode_rr(rr)
      }
    end

    # Which record ids the used steps depend on, following step references.
    # The integrity seal covers these records, not merely their ids.
    def explanation_record_ids
      ids = steps.select { |step| use_step?(step) }.flat_map { |step| referenced_record_ids(step) }
      ids.uniq.sort
    end
    public :explanation_record_ids

    def validate_document!
      unless data.is_a?(Hash) && data['format'] == FORMAT
        raise ReplayError, 'Not a dnsruby DNSSEC evidence document'
      end
      unless data['version'] == VERSION
        raise ReplayError, "Unsupported evidence version #{data['version'].inspect}"
      end
      raise ReplayError, 'Evidence is missing its records' unless data['records'].is_a?(Hash)
      raise ReplayError, 'Evidence is missing its steps' unless data['steps'].is_a?(Array)
      if data['prior_evidence']
        unless data['prior_evidence'].is_a?(Array)
          raise ReplayError, 'prior_evidence must be a list of evidence documents'
        end
        data['prior_evidence'].each do |document|
          unless document.is_a?(Hash) && document['format'] == FORMAT
            raise ReplayError, 'prior_evidence contains a non-evidence document'
          end
        end
      end
    end

    # Captures one validation operation. All nested verification and chain
    # discovery in the same thread report to this recorder.
    class Recorder
      attr_reader :records, :steps, :candidates

      def initialize(query, message)
        @query = query
        @message = message
        @time = ValidationClock.now_i
        @records = {}
        @steps = []
        @candidates = []
        @scopes = []
        @current_scope = nil
        @cache = cache_observation(message)
        @conclusion = nil
        @error = nil
        @used_step_ids = []
        @seen_step_keys = {}
      end

      def note_cache_hit(message)
        @cache ||= cache_observation(message)
      end

      # Any verification work performed inside the block belongs to this
      # attempt. If it raises, those steps remain as diagnostics but are not
      # part of a successful explanation.
      # Every verification attempt gets its own scope. Steps recorded inside
      # a failed attempt remain available as diagnostics, but a later success
      # is explained only by its own steps.
      def scope(label)
        scope = { 'id' => "a#{@scopes.length + 1}", 'label' => label.to_s,
                  'status' => 'ok', 'level' => nil }
        @scopes << scope
        previous = @current_scope
        @current_scope = scope['id']
        begin
          result = yield
          scope['level'] = @message.security_level.to_s if @message
          result
        rescue Exception => error
          scope['status'] = 'failed'
          scope['error'] = error.message
          raise
        ensure
          @current_scope = previous
        end
      end

      def mark_attempt(ok)
        return unless @current_scope
        scope = @scopes.find { |candidate| candidate['id'] == @current_scope }
        return unless scope
        scope['status'] = ok ? 'ok' : 'failed'
        scope['level'] ||= @message.security_level.to_s if @message
      end

      def add_record(rr)
        return rr.rrs.map { |entry| add_record(entry) } if rr.is_a?(RRSet)
        id = ValidationEvidence.record_id(rr)
        @records[id] ||= {
          'name' => rr.name.to_s(true),
          'type' => rr.type.string,
          'class' => rr.klass.string,
          'ttl' => rr.ttl,
          'wire' => ValidationEvidence.encode_rr(rr)
        }
        id
      end

      def add_step(kind, fields = {})
        step = fields.transform_keys(&:to_s).merge('kind' => kind.to_s, 'status' => 'verified')
        step['scope'] = @current_scope if @current_scope
        key = step_key(step)
        if (existing = @seen_step_keys[key])
          other = @steps[existing]
          # The same anchor or proof can be reached from more than one
          # attempt. Remember the later scopes so a successful attempt still
          # gets to explain its own path.
          if @current_scope && other['scope'] != @current_scope
            (other['also_scopes'] ||= []) << @current_scope
            other['also_scopes'].uniq!
          end
          return other
        end
        step['id'] = "s#{@steps.length + 1}"
        @steps << step
        @seen_step_keys[key] = @steps.length - 1
        step
      end

      def trust_anchor(key, verifier:, source: nil, configured: nil, prior: nil)
        ids = add_record(key)
        ids = [ids] unless ids.is_a?(Array)
        step = add_step('trust_anchor',
          'verifier' => verifier.to_s,
          'records' => ids,
          'name' => key.name.to_s(true),
          'type' => key.type.string,
          'key_tag' => (key.respond_to?(:key_tag) ? key.key_tag : nil),
          'configured' => configured,
          'source' => source&.to_s)
        remember_prior(prior) if prior
        step
      end

      # A warm-cache start must cite the validation that established it.
      def remember_prior(prior)
        @prior_evidence ||= []
        return if @prior_evidence.any? { |document| document['explanation_digest'] == prior['explanation_digest'] }
        @prior_evidence << ValidationEvidence.deep_copy(prior)
      end

      def signature_verified(rrset, key, signature, role:, rejected: [], unused: [])
        # Candidate signatures that were present but not selected must never
        # look like part of the successful path. They are recorded outside the
        # explanation digest, so adding one cannot change the explanation.
        unused.each do |sig|
          next if @candidates.any? { |candidate| candidate['signature'] == ValidationEvidence.record_id(sig) }
          @candidates << {
            'name' => rrset.name.to_s(true),
            'type' => rrset.type.string,
            'signature' => add_record(sig),
            'key_tag' => sig.key_tag,
            'algorithm' => sig.algorithm.string,
            'signer' => sig.signers_name.to_s(true),
            'selected' => false,
            'reason' => 'matching signature was not used for this conclusion'
          }
        end
        add_step('signature',
          'role' => role.to_s,
          'name' => rrset.name.to_s(true),
          'type' => rrset.type.string,
          'rrset' => rrset.rrs.map { |rr| add_record(rr) },
          'key' => add_record(key),
          'signature' => add_record(signature),
          'signer' => signature.signers_name.to_s(true),
          'key_tag' => signature.key_tag,
          'algorithm' => signature.algorithm.string,
          'rejected' => rejected)
      end

      def signature_step_for(rrset, signer_name: nil)
        return signature_step_for_rr(rrset, signer_name) unless rrset.is_a?(RRSet)
        @steps.reverse.find do |candidate|
          next false unless candidate['kind'] == 'signature'
          next false unless candidate['name'] == rrset.name.to_s(true)
          next false unless candidate['type'] == rrset.type.string
          signer_name.nil? || candidate['signer'] == signer_name.to_s(true)
        end
      end

      def signature_step_for_rr(rr, signer_name = nil)
        @steps.reverse.find do |candidate|
          next false unless candidate['kind'] == 'signature'
          next false unless candidate['name'] == rr.name.to_s(true)
          next false unless candidate['type'] == rr.type.string
          signer_name.nil? || candidate['signer'] == signer_name.to_s(true)
        end
      end

      def signature_failed(rrset, error, attempted:, signatures:, keys:)
        add_step('signature_failure',
          'name' => rrset.name.to_s(true),
          'type' => rrset.type.string,
          'rrset' => rrset.rrs.map { |rr| add_record(rr) },
          'error' => error.message,
          'attempted' => attempted,
          'signatures' => signatures.map { |sig| add_record(sig) },
          'keys' => keys.map { |key| add_record(key) })
      end

      def delegation(parent, child, ds_rrset, parent_keys:)
        add_step('delegation',
          'parent' => parent.to_s(true),
          'child' => child.to_s(true),
          'ds' => ds_rrset.rrs.map { |rr| add_record(rr) },
          'ds_rrset' => ds_rrset.rrs.map { |rr| add_record(rr) },
          'parent_keys' => parent_keys.map { |key| add_record(key) },
          'signature' => signature_step_id_for(ds_rrset))
      end

      def delegation_absent(parent, child, source: nil, ds_count: 0)
        add_step('delegation_absent',
          'parent' => parent.to_s(true),
          'child' => child.to_s(true),
          'ds_count' => ds_count,
          'source' => source&.to_s,
          'proof' => 'unproven',
          'note' => 'No DS RRset was returned. Unsigned delegation was treated as insecure without an authenticated denial proof.')
      end

      def delegation_failed(parent, child, error, ds_rrset: nil)
        add_step('delegation_failure',
          'parent' => parent.to_s(true),
          'child' => child.to_s(true),
          'error' => error.message,
          'ds' => ds_rrset ? ds_rrset.rrs.map { |rr| add_record(rr) } : [])
      end

      def dnskey(zone, key_rrset, ds_rrset: nil)
        add_step('dnskey',
          'name' => zone.to_s(true),
          'keys' => key_rrset.rrs.map { |rr| add_record(rr) },
          'ds' => ds_rrset ? ds_rrset.rrs.map { |rr| add_record(rr) } : [],
          'signature' => signature_step_id_for(key_rrset))
      end

      def denial(proof, name:, qtype:, records:, assertions: [], extra: {})
        add_step('denial',
          extra.merge(
            'proof' => proof.to_s,
            'name' => name.to_s(true),
            'qtype' => qtype.nil? ? nil : qtype.to_s,
            'records' => records.map { |rr| add_record(rr) },
            'assertions' => (assertions + [{ 'wildcard_checked' => context['wildcard_checked'] == true,
                                           'wildcard_denied' => (context['wildcard_checked'] ? true : nil) }]).uniq,
            'signature_steps' => records.map { |rr| signature_step_id_for(rr) }.compact.uniq))
      end

      def denial_source(zone)
        @denial = @denial || {}
        @denial['source'] = zone.to_s(true)
      end

      def denial_wildcard_checked!
        @denial = @denial || {}
        @denial['wildcard_checked'] = true
      end

      # The pre-check verified the whole message using its trusted key cache.
      # The verifier records the nearest anchor and the proof that established
      # it, so the exported graph has a real trust start.
      def record_fast_path_anchor(_query, message)
        question = message.question.first
        return unless question
        Dnsruby::Dnssec.anchor_verifier.record_fast_path_anchor(question.qname)
      rescue StandardError => error
        Dnsruby.log.error { "Could not record warm-cache trust start: #{error}" }
      end

      # A key the validator published into its trusted cache during this
      # operation. Warm-cache validations legitimately start here.
      def learned_key(key, expiration: nil, via: 'DNSKEY RRSet', verifier: nil, prior: nil)
        ids = add_record(key)
        step = add_step('learned_key',
          'verifier' => verifier.to_s,
          'name' => key.name.to_s(true),
          'type' => key.type.string,
          'key_tag' => (key.respond_to?(:key_tag) ? key.key_tag : nil),
          'record' => ids,
          'expiration' => expiration,
          'via' => via.to_s)
        remember_prior(prior) if prior
        step
      end

      def learned_keys(keys, verifier: nil, prior: nil)
        keys.each { |key| learned_key(key, verifier: verifier, prior: prior) }
      end

      def no_anchor(name)
        add_step('no_anchor', 'name' => name.to_s(true), 'note' => 'No configured or learned trust anchor covers this name.')
      end

      # Collect the denial records that actually satisfied a check, so the
      # exported proof cannot be confused with unrelated NSEC material in the
      # same response.
      def begin_denial(proof, name:, qtype:)
        @denial = { 'proof' => proof.to_s, 'name' => name.to_s(true),
                    'qtype' => qtype.nil? ? nil : qtype.to_s, 'records' => [] }
      end

      def denial_record(rr)
        return unless @denial
        @denial['records'] << rr unless @denial['records'].include?(rr)
      end

      def complete_denial(assertions = [])
        context = @denial
        @denial = nil
        return unless context && !context['records'].empty?
        add_step('denial',
          'proof' => context['proof'],
          'name' => context['name'],
          'qtype' => context['qtype'],
          'source' => context['source'],
          'records' => context['records'].map { |rr| add_record(rr) },
          'assertions' => (assertions + [{ 'wildcard_checked' => context['wildcard_checked'] == true,
                                           'wildcard_denied' => (context['wildcard_checked'] ? true : nil) }]).uniq,
          'signature_steps' => context['records'].map { |rr| signature_step_id_for(rr) }.compact.uniq)
      end

      def abort_denial(error)
        context = @denial
        @denial = nil
        return unless context
        add_step('denial_failure',
          'proof' => context['proof'],
          'name' => context['name'],
          'qtype' => context['qtype'],
          'source' => context['source'],
          'records' => context['records'].map { |rr| add_record(rr) },
          'error' => error.message)
      end

      def unsigned_answer(name, signed_zone:)
        add_step('unsigned_answer', 'name' => name.to_s(true), 'signed_zone' => signed_zone.to_s(true))
      end

      def message_verified
        add_step('message_verified',
          'name' => (@query&.question&.first&.qname || @message.question.first.qname).to_s(true),
          'rcode' => @message.rcode.string,
          'security_level' => @message.security_level.to_s)
      end

      def finish(message, error = nil)
        @conclusion = message ? message.security_level.to_s : 'UNCHECKED'
        @error = error ? error.message : (message&.security_error.to_s.empty? ? nil : message.security_error.to_s)
      end

      def to_evidence
        attempts = @scopes.map(&:dup)
        chosen = choose_scope
        reconcile_denials(chosen) if chosen
        used = if chosen
          @steps.select do |step|
            step['scope'] == chosen['id'] || step['scope'].nil? ||
              Array(step['also_scopes']).include?(chosen['id'])
          end
        else
          @steps
        end
        used_ids = used.map { |step| step['id'] }
        # A candidate that an earlier attempt did not select may be the very
        # signature the successful attempt used. It then belongs to the path,
        # not to the candidate list.
        selected = @steps.select { |step| step['kind'] == 'signature' && used_ids.include?(step['id']) }
          .map { |step| step['signature'] }.compact
        candidates = @candidates.reject { |candidate| selected.include?(candidate['signature']) }
        candidates = candidates.uniq { |candidate| candidate['signature'] }
        evidence = {
          'format' => FORMAT,
          'version' => VERSION,
          'query' => query_hash,
          'rcode' => @message ? @message.rcode.string : nil,
          'validation_time' => @time,
          'validation_time_iso8601' => Time.at(@time).utc.iso8601,
          'policy' => policy_snapshot,
          'conclusion' => @conclusion,
          'error' => @error,
          'cache' => @cache,
          'attempts' => attempts,
          'chosen_attempt' => chosen && chosen['id'],
          'steps' => @steps,
          'candidates' => candidates,
          'used_step_ids' => used_ids,
          'records' => @records
        }
        evidence['prior_evidence'] = @prior_evidence if @prior_evidence && !@prior_evidence.empty?
        # Compute both digests from the constructed document so capture and
        # replay share exactly one canonicalisation path.
        document = ValidationEvidence.new(evidence)
        evidence['explanation_digest'] = document.recompute_explanation_digest
        evidence['integrity'] = document.recompute_integrity
        ValidationEvidence.new(evidence)
      end

      private

      def query_hash
        question = @query&.question&.first || @message&.question&.first
        return {} unless question
        {
          'name' => question.qname.to_s(true),
          'type' => question.qtype.string,
          'class' => question.qclass.string
        }
      end

      def cache_observation(message)
        return nil unless message&.cached
        original = message.validation_evidence
        {
          'hit' => true,
          'original_conclusion' => original&.conclusion,
          'original_explanation_digest' => original&.explanation_digest,
          'note' => original ? 'Answer came from the cache; its original validation evidence is attached.' :
            'Answer came from the cache without prior DNSSEC evidence.'
        }
      end

      def policy_snapshot
        anchors = []
        begin
          { 'root' => Dnssec.root_verifier, 'local' => Dnssec.anchor_verifier, 'dlv' => Dnssec.dlv_verifier }.each do |role, verifier|
            verifier.trust_anchors.each do |anchor|
              anchors << {
                'verifier' => role,
                'type' => anchor.type.string,
                'record' => add_record(anchor),
                'name' => anchor.name.to_s(true),
                'key_tag' => (anchor.respond_to?(:key_tag) ? anchor.key_tag : nil)
              }
            end
          end
        rescue StandardError
          # A policy snapshot must not make validation fail.
        end
        {
          'validation_policy' => Dnssec.validation_policy,
          'validation_policy_name' => policy_name(Dnssec.validation_policy),
          'do_validation_with_recursor' => (Dnssec.do_validation_with_recursor? rescue nil),
          'validation_limits' => Dnssec.validation_limits.transform_keys(&:to_s),
          'trust_anchors' => anchors
        }
      end

      def policy_name(value)
        Dnssec::ValidationPolicy.constants.find { |name| Dnssec::ValidationPolicy.const_get(name) == value }&.to_s
      end

      # Denial checks run during the initial whole-message verification, before
      # the chosen attempt's signatures are recorded. Move a denial proof into
      # the chosen attempt only when that attempt actually verified the NSEC
      # or NSEC3 signature it relies on.
      def reconcile_denials(chosen)
        @steps.each do |step|
          next unless %w[denial denial_failure].include?(step['kind'])
          next if step['scope'] == chosen['id']
          record_ids = Array(step['records'])
          signature_steps = @steps.select do |candidate|
            next false unless candidate['kind'] == 'signature' && candidate['scope'] == chosen['id']
            Array(candidate['rrset']).any? { |id| record_ids.include?(id) }
          end
          next if signature_steps.empty?
          step['scope'] = chosen['id']
          step['signature_steps'] = signature_steps.map { |candidate| candidate['id'] }
        end
      end

      def choose_scope
        return nil if @scopes.empty?
        desired = case @conclusion
        when 'SECURE' then 'SECURE'
        when 'INSECURE' then 'INSECURE'
        end
        concrete = @scopes.reject { |scope| %w[validation attempt].include?(scope['label']) }
        with_steps = concrete.select { |scope| @steps.any? { |step| step['scope'] == scope['id'] } }
        if desired
          candidates = with_steps.select { |scope| scope['status'] == 'ok' && scope['level'] == desired }
          return candidates.last unless candidates.empty?
        end
        successful = with_steps.select { |scope| scope['status'] == 'ok' }
        return successful.last unless successful.empty?
        with_steps.last || concrete.last || @scopes.last
      end

      def signature_step_id_for(rrset, signer_name: nil)
        step = signature_step_for(rrset, signer_name: signer_name)
        step && step['id']
      end

      def step_key(step)
        fields = step.reject { |key, _| %w[id status scope rejected unused].include?(key) }
        JSON.generate(fields.sort_by { |key, _| key.to_s }.to_h)
      end

      # The explanation digest must depend only on the material used to reach
      # the conclusion. Candidate signatures and unused records are excluded.
      def explanation_digest_for(evidence)
        used_ids = evidence['used_step_ids']
        steps = evidence['steps'].select { |step| used_ids.include?(step['id']) }
        records = referenced_records(evidence, steps)
        Digest::SHA256.hexdigest(JSON.generate(
          'query' => evidence['query'],
          'conclusion' => evidence['conclusion'],
          'steps' => steps.map { |step| step.sort_by { |key, _| key.to_s }.to_h },
          'records' => records
        ))
      end

      def integrity_for(evidence)
        used_ids = evidence['used_step_ids']
        steps = evidence['steps'].select { |step| used_ids.include?(step['id']) }
        records = referenced_records(evidence, steps)
        Digest::SHA256.hexdigest(JSON.generate(
          'time' => evidence['validation_time'],
          'policy' => evidence['policy'],
          'query' => evidence['query'],
          'conclusion' => evidence['conclusion'],
          'steps' => steps.map { |step| step.sort_by { |key, _| key.to_s }.to_h },
          'records' => records
        ))
      end

      def referenced_records(evidence, steps)
        ids = []
        steps.each { |step| ids.concat(referenced_ids(step)) }
        ids.uniq.sort.map { |id| [id, evidence['records'][id]] }
      end

      def referenced_ids(step)
        ids = []
        %w[record key signature rrset records keys ds parent_keys next_keys proofs signature_steps].each do |field|
          value = step[field]
          case value
          when String then ids << value
          when Array then ids.concat(value.select { |entry| entry.is_a?(String) })
          end
        end
        ids
      end
    end

    # Independent, network-free replay of the recorded steps.
    class Replay
      attr_reader :time, :policy

      def initialize(evidence, time:, policy:)
        @evidence = evidence
        @time = time.nil? ? evidence.validation_time : time.to_i
        @policy = policy.nil? ? evidence.policy : normalize_policy(policy)
        @records = {}
        @signature_steps = {}
        @steps = evidence.steps
        @zone_keys = Hash.new { |hash, key| hash[key] = [] }
        @prior = {}
      end

      def run
        load_records
        load_prior_evidence
        check_required_records!
        unless @evidence.integrity_ok?
          raise ReplayError, 'Evidence integrity check failed; the explanation was modified after capture'
        end
        check_policy_anchors!
        verify_signature_steps!
        verify_dnskey_steps!
        verify_delegations!
        establish_trust!
        result = reproduce_conclusion
        Result.new(
          security_level: result,
          time: time,
          explanation_digest: @evidence.explanation_digest,
          steps: @evidence.used_step_ids,
          policy: policy,
          cache: @evidence.cache,
          reason: @reason
        )
      rescue ReplayError
        raise
      rescue VerifyError => error
        raise ReplayError, "Replay failed: #{error.message}"
      end

      private

      def load_records
        @evidence.records.each do |id, record|
          raise ReplayError, "Malformed evidence record #{id}" unless record.is_a?(Hash) && record['wire']
          rr = ValidationEvidence.decode_rr(record['wire'])
          actual = ValidationEvidence.record_id(rr)
          unless actual == id
            raise ReplayError, "Evidence record #{id} does not match its contents"
          end
          @records[id] = rr
        rescue DecodeError => error
          raise ReplayError, "Cannot decode evidence record #{id}: #{error.message}"
        end
        @steps.each do |step|
          next unless step['kind'] == 'signature'
          @signature_steps[step['id']] = step
        end
      end

      def check_required_records!
        @evidence.used_step_ids.each do |id|
          step = @steps.find { |candidate| candidate['id'] == id }
          next unless step
          referenced = referenced_ids(step)
          referenced.each do |record_id|
            unless @evidence.records.key?(record_id)
              raise ReplayError, "Required evidence record #{record_id} is missing"
            end
          end
        end
      end

      # A recorded denial failure must still reproduce: its records must not
      # now prove existence or wildcard coverage for the queried name.
      def verify_denial_failures!
        failures = @steps.select { |step| step['kind'] == 'denial_failure' && used?(step) }
        failures.each do |step|
          records = Array(step['records']).map { |id| record!(id) }
          raise ReplayError, "Recorded denial failure for #{step['name']} has no NSEC evidence" if records.empty?
          name = Name.create(step['name'])
          nsecs = records.select { |rr| rr.type == Types::NSEC }
          if nsecs.any? { |rr| rr.check_name_in_range(name) }
            raise ReplayError, "Recorded denial failure for #{step['name']} no longer reproduces"
          end
          if step['qtype']
            qtype = Types.new(step['qtype'])
            if nsecs.any? { |rr| rr.check_name_in_range(name) && !rr.types.include?(qtype) }
              raise ReplayError, "Recorded denial failure for #{step['name']} no longer reproduces"
            end
          end
        end
      end

      # Step references (for example a delegation's ``signature``) point at
      # other steps. Resolve them so a missing record anywhere in the chain is
      # reported as missing evidence, not as an integrity failure.
      def referenced_ids(step, seen = {})
        return [] if seen[step['id']]
        seen[step['id']] = true
        ids = []
        %w[key rrset records keys ds parent_keys next_keys proofs].each do |field|
          value = step[field]
          case value
          when String then ids << value
          when Array then ids.concat(value.select { |entry| entry.is_a?(String) })
          end
        end
        if step['signature'].is_a?(String)
          if step['kind'] == 'signature'
            ids << step['signature']
          else
            child = @steps.find { |candidate| candidate['id'] == step['signature'] }
            ids.concat(referenced_ids(child, seen)) if child
          end
        end
        Array(step['signature_steps']).each do |id|
          child = @steps.find { |candidate| candidate['id'] == id }
          ids.concat(referenced_ids(child, seen)) if child
        end
        ids
      end

      # Warm-cache exports cite the earlier validation that taught the
      # validator to trust a key. Replay that evidence too, in the same
      # document, so a cache reuse cannot invent trust.
      def load_prior_evidence
        Array(@evidence.data['prior_evidence']).each do |document|
          prior = ValidationEvidence.new(document)
          # The prior proof is checked at the same fixed time; its own clock
          # is kept in the document for auditors.
          result = prior.replay(time: @time, policy: @policy)
          raise ReplayError, "Cited prior validation #{prior.explanation_digest} is not SECURE" unless result.security_level == 'SECURE'
          prior.used_steps.each do |step|
            # A prior validation proves that these keys are trusted at the
            # recorded time. Cite only the exact key record ids it used.
            case step['kind']
            when 'trust_anchor'
              Array(step['records']).each { |id| @prior[id] = step['name'] if step['type'] == 'DNSKEY' }
            when 'dnskey'
              Array(step['keys']).each { |id| @prior[id] = step['name'] }
            when 'signature'
              Array(step['key']).each { |id| @prior[id] = step['signer'] }
            end
          end
        end
      end

      def verified_prior_key?(record_id, zone)
        @prior.each do |key_id, prior_zone|
          next unless prior_zone == zone
          # The cited key must be the same record id cited by the prior proof.
          return true if key_id == record_id
        end
        false
      end

      def check_policy_anchors!
        # No supplied policy means "use the policy recorded with the evidence".
        # An explicit empty anchor list is a policy that trusts nothing.
        anchors = Array(policy['trust_anchors'])
        @evidence.used_step_ids.each do |id|
          step = @steps.find { |candidate| candidate['id'] == id }
          next unless step && step['kind'] == 'trust_anchor'
          allowed = anchors.any? do |anchor|
            anchor_record = anchor['record'] || anchor['records']
            ids = Array(anchor_record)
            (step['records'] & ids).any? && (!anchor['verifier'] || anchor['verifier'] == step['verifier'])
          end
          # A key learned from a prior validated delegation may start this
          # proof even though it is not a configured anchor, but only when the
          # cited prior evidence replayed and proved the same key.
          if !allowed && step['configured'] == false
            allowed = Array(step['records']).any? { |record_id| verified_prior_key?(record_id, step['name']) }
          end
          raise ReplayError, "Trust anchor #{step['records'].inspect} is not allowed by the supplied policy" unless allowed
        end
      end

      def verify_signature_steps!
        @steps.each do |step|
          next unless step['kind'] == 'signature'
          next unless used?(step)
          rrset = rrset_for(step['rrset'])
          signature = record!(step['signature'])
          keys = Array(step['key']).map { |id| record!(id) }
          rrset.add(signature)
          verifier = SingleVerifier.new(SingleVerifier::VerifierType::ANCHOR)
          begin
            ValidationClock.with_time(time) { verifier.verify_rrset(rrset, keys) }
          rescue VerifyError => error
            raise ReplayError, "Signature for #{step['name']} #{step['type']} no longer verifies: #{error.message}"
          end
        end
      end

      def verify_dnskey_steps!
        @steps.each do |step|
          next unless step['kind'] == 'dnskey'
          next unless used?(step)
          keys = Array(step['keys']).map { |id| record!(id) }
          unless keys.all? { |key| key.type == Types::DNSKEY }
            raise ReplayError, "DNSKEY evidence for #{step['name']} is missing keys"
          end
          next if Array(step['ds']).empty?
          ds_records = Array(step['ds']).map { |id| record!(id) }
          matching = keys.select { |key| ds_records.any? { |ds| ds.check_key(key) } }
          raise ReplayError, "No DNSKEY in #{step['name']} matches the recorded DS" if matching.empty?
          signature_step = step['signature'] && @signature_steps[step['signature']]
          if signature_step
            signer = record!(signature_step['key'])
            unless matching.any? { |key| key.key_tag == signer.key_tag && key.algorithm == signer.algorithm }
              raise ReplayError, "DNSKEY RRset for #{step['name']} was not signed by a DS-matched key"
            end
          end
        end
      end

      def verify_delegations!
        @steps.each do |step|
          case step['kind']
          when 'delegation'
            next unless used?(step)
            ds_rrset = rrset_for(step['ds_rrset'] || step['ds'])
            signature_step = step['signature'] && @signature_steps[step['signature']]
            raise ReplayError, "Delegation to #{step['child']} has no verified DS signature" unless signature_step
            parent_keys = Array(step['parent_keys']).map { |id| record!(id) }
            verify_rrset_with(ds_rrset, signature_step, parent_keys, "DS for #{step['child']}")
          when 'delegation_failure'
            next unless used?(step)
            raise ReplayError, "Recorded delegation failure for #{step['child']}: #{step['error']}"
          end
        end
      end

      def verify_rrset_with(rrset, signature_step, keys, label)
        signature = record!(signature_step['signature'])
        rrset.add(signature) unless rrset.sigs.include?(signature)
        verifier = SingleVerifier.new(SingleVerifier::VerifierType::ANCHOR)
        ValidationClock.with_time(time) { verifier.verify_rrset(rrset, keys) }
      rescue VerifyError => error
        raise ReplayError, "#{label} no longer verifies: #{error.message}"
      end

      def establish_trust!
        # Anchors first. A DNSKEY anchor is usable directly; a DS anchor is
        # linked to a recorded DNSKEY RRset for the same zone. Learned keys
        # are start points only when this operation began from the warm cache
        # and did not record the delegation that first established them.
        @evidence.used_step_ids.each do |id|
          step = @steps.find { |candidate| candidate['id'] == id }
          next unless step
          zone = step['name'] || step['name'].to_s
          case step['kind']
          when 'trust_anchor'
            if step['type'] == RR::DNSKEY.to_s || step['type'] == 'DNSKEY'
              @zone_keys[zone].concat(Array(step['records']))
            else
              dnskey_steps_for(zone).each do |key_step|
                next if Array(key_step['ds']).empty?
                matches = Array(key_step['keys']).select do |key_id|
                  key = @records[key_id]
                  Array(key_step['ds']).any? { |ds_id| ds = @records[ds_id]; ds && ds.check_key(key) }
                end
                @zone_keys[zone].concat(matches)
              end
            end
            @zone_keys[zone].uniq!
          when 'learned_key'
            # Only accept the learned key if the evidence shows it was
            # published during this validation. A bare claim would let the
            # export manufacture trust.
            record_id = step['record']
            key = @records[record_id]
            next unless key && key.type == Types::DNSKEY
            next unless learned_key_published_during_capture?(key, step) ||
              verified_prior_key?(record_id, key.name.to_s(true))
            @zone_keys[zone].concat([record_id])
            @zone_keys[zone].uniq!
          end
        end

        # Delegation edges. Each child DNSKEY set is trusted once a parent key
        # verifies its signed DS and the DS matches a key in the child set.
        loop do
          changed = false
          @steps.each do |step|
            next unless step['kind'] == 'delegation' && used?(step)
            parent_zone = step['parent']
            unless @zone_keys.key?(parent_zone) && !@zone_keys[parent_zone].empty?
              next
            end
            child_step = dnskey_steps_for(step['child']).first
            next unless child_step
            child_keys = Array(child_step['keys'])
            next if child_keys.empty? || (@zone_keys[step['child']] - child_keys).empty? && !@zone_keys[step['child']].empty?
            @zone_keys[step['child']] |= child_keys
            changed = true
          end
          break unless changed
        end
      end

      # A warm-cache export starts at a key the previous validation learned.
      # Accept it only when the capture also records the anchor and chain that
      # first taught the validator to trust that key, or when the key itself
      # was reached through a recorded delegation edge in this document.
      def learned_key_published_during_capture?(key, step)
        zone = key.name.to_s(true)
        return true if @steps.any? { |candidate| candidate['kind'] == 'delegation' && used?(candidate) && candidate['child'] == zone }
        return true if @steps.any? { |candidate| candidate['kind'] == 'trust_anchor' && used?(candidate) && candidate['name'] == zone }
        # A root learned key can only have come from a root trust anchor.
        return true if zone == '.' && @steps.any? { |candidate| candidate['kind'] == 'trust_anchor' && used?(candidate) }
        false
      end

      def dnskey_steps_for(zone)
        @steps.select do |step|
          step['kind'] == 'dnskey' && step['name'] == zone && used?(step)
        end
      end

      def reproduce_conclusion
        claimed = @evidence.conclusion
        case claimed
        when 'SECURE'
          if uses_denial_proof_only?
            reproduce_secure_denial!
          else
            require_secure_path!
          end
          'SECURE'
        when 'INSECURE'
          reproduce_insecure!
        when 'BOGUS'
          reproduce_bogus!
        when 'UNCHECKED', 'INDETERMINATE'
          claimed
        else
          raise ReplayError, "Unknown evidence conclusion #{claimed.inspect}"
        end
      end

      # Secure NXDOMAIN/NODATA answers are explained by their signed denial
      # proof; there is no positive data signature to recheck. A response that
      # also contains answer data must instead be checked as a positive answer.
      def uses_denial_proof_only?
        question = @evidence.query
        has_data = @steps.any? do |step|
          step['kind'] == 'signature' && used?(step) && step['role'] == 'data' &&
            same_name?(step['name'], question['name']) &&
            step['type'] == question['type']
        end
        !has_data && @steps.any? { |step| step['kind'] == 'denial' && used?(step) }
      end

      def reproduce_secure_denial!
        question = @evidence.query
        denial = @steps.select { |step| step['kind'] == 'denial' && used?(step) }.find do |step|
          same_name?(step['name'], question['name']) && step['qtype'] == question['type']
        end
        denial ||= @steps.select { |step| step['kind'] == 'denial' && used?(step) }.find do |step|
          same_name?(step['name'], question['name'])
        end
        raise ReplayError, "No denial proof covers #{question['name']} #{question['type']}" unless denial
        signer = signer_for_denial(denial)
        unless signer && @zone_keys.key?(signer) && !@zone_keys[signer].empty?
          raise ReplayError, "No trusted key path to #{signer || denial['name']}"
        end
        verify_denials!(@steps.select { |step| step['kind'] == 'denial' && used?(step) })
      end

      def require_secure_path!
        question = @evidence.query
        data_steps = @steps.select do |step|
          step['kind'] == 'signature' && used?(step) && step['role'] == 'data'
        end
        denial_steps = @steps.select { |step| step['kind'] == 'denial' && used?(step) }
        target = data_steps.find do |step|
          same_name?(step['name'], question['name']) && step['type'] == question['type']
        end
        target ||= denial_steps.find { |step| same_name?(step['name'], question['name']) }
        unless target
          raise ReplayError, "No verified signature or denial proof covers #{question['name']} #{question['type']}"
        end
        signer = target['kind'] == 'signature' ? target['signer'] : signer_for_denial(target)
        unless signer && @zone_keys.key?(signer) && !@zone_keys[signer].empty?
          raise ReplayError, "No trusted key path to #{signer || target['name']}"
        end
        if target['kind'] == 'signature'
          key_ids = Array(target['key'])
          unless key_ids.any? { |id| @zone_keys[signer].include?(id) }
            raise ReplayError, "Signature for #{target['name']} was not made by a key on the trusted path"
          end
        end
        verify_denials!(denial_steps)
        'SECURE'
      end

      def reproduce_insecure!
        denial = @steps.find { |step| used?(step) && %w[delegation_absent no_anchor].include?(step['kind']) }
        raise ReplayError, 'No recorded reason for the insecure conclusion' unless denial
        verify_denials!(@steps.select { |step| step['kind'] == 'denial' && used?(step) })
        'INSECURE'
      end

      def reproduce_bogus!
        failures = @steps.select { |step| used?(step) && %w[signature_failure delegation_failure unsigned_answer].include?(step['kind']) }
        raise ReplayError, 'No failed verification step explains the bogus conclusion' if failures.empty?
        verify_denial_failures!
        failures.each do |step|
          case step['kind']
          when 'signature_failure'
            # The recorded signatures must still fail to verify. A tampered
            # "failure" that now succeeds is not the same explanation.
            rrset = rrset_for(step['rrset'])
            keys = Array(step['keys']).map { |id| record!(id) }
            signatures = Array(step['signatures']).map { |id| record!(id) }
            signatures.each do |signature|
              copy = RRSet.new(rrset.rrs)
              copy.add(signature)
              begin
                ValidationClock.with_time(time) { SingleVerifier.new(SingleVerifier::VerifierType::ANCHOR).verify_rrset(copy, keys) }
                raise ReplayError, "Recorded failing signature for #{step['name']} now verifies"
              rescue VerifyError
                # Expected: it must still fail.
              end
            end
          when 'delegation_failure'
            raise ReplayError, "Recorded delegation failure for #{step['child']} no longer reproduces"
          when 'unsigned_answer'
            # An unsigned answer in a signed zone stays bogus while the zone
            # key remains trusted.
            zone = step['signed_zone']
            unless @zone_keys.key?(zone) && !@zone_keys[zone].empty?
              raise ReplayError, "Recorded unsigned answer for #{step['name']} is no longer in a trusted zone"
            end
          end
        end
        'BOGUS'
      end

      def verify_denials!(steps)
        steps.each do |step|
          records = Array(step['records']).map { |id| record!(id) }
          raise ReplayError, "Denial proof for #{step['name']} has no records" if records.empty?
          signature_steps = Array(step['signature_steps']).map { |id| @signature_steps[id] }.compact
          raise ReplayError, "Denial proof for #{step['name']} is not signed" if signature_steps.empty?
          signature_steps.each do |signature_step|
            rrset = RRSet.new(records.select do |rr|
              rr.name.to_s(true) == signature_step['name'] && rr.type.string == signature_step['type']
            end)
            if rrset.rrs.empty?
              raise ReplayError, "Denial signature for #{signature_step['name']} covers no recorded record"
            end
            verify_rrset_with(rrset, signature_step, [record!(signature_step['key'])],
              "Denial proof for #{step['name']}")
            signer = signature_step['signer']
            unless @zone_keys.key?(signer) && !@zone_keys[signer].empty?
              raise ReplayError, "Denial proof for #{step['name']} is not signed by a trusted zone key"
            end
          end
          nsecs = records.select { |rr| rr.type == Types::NSEC }
          nsec3s = records.select { |rr| rr.type == Types::NSEC3 }
          name = Name.create(step['name'])
          case step['proof']
          when 'name_error', 'no_data'
            if nsecs.any?
              covering = nsecs.select { |rr| rr.check_name_in_range(name) }
              raise ReplayError, "NSEC evidence does not cover #{step['name']}" if covering.empty?
              if step['proof'] == 'no_data' && step['qtype']
                qtype = Types.new(step['qtype'])
                if covering.any? { |rr| rr.types.include?(qtype) }
                  raise ReplayError, "NSEC evidence does not deny #{step['qtype']} at #{step['name']}"
                end
              end
              # An NXDOMAIN proof also needs to show no wildcard could have
              # matched. The validator records that assertion only when it
              # checked a wildcard-covering NSEC, so replay enforces it here.
              if step['proof'] == 'name_error' && Array(step['assertions']).any? { |a| a['wildcard_checked'] && !a['wildcard_denied'].nil? }
                unless nsecs.any? { |rr| wildcard_absence_covered?(rr, name) }
                  raise ReplayError, "NXDOMAIN proof for #{step['name']} has no NSEC denying wildcard expansion"
                end
              end
            elsif nsec3s.empty?
              raise ReplayError, "Denial proof for #{step['name']} is neither NSEC nor NSEC3"
            end
          when 'wildcard_absence'
            raise ReplayError, 'Wildcard denial has no NSEC evidence' if records.empty?
          end
        end
      end

      def wildcard_absence_covered?(nsec, name)
        return false if nsec.name.wild?
        wildcard = Name.create("*.#{nsec.name.to_s(true).sub(/\.\z/, '')}")
        wildcard.canonically_before(nsec.next_domain) || nsec.check_name_in_range(name)
      end

      def signer_for_denial(step)
        signature_steps = Array(step['signature_steps']).map { |id| @signature_steps[id] }.compact
        signature_steps.map { |sig| sig['signer'] }.find { |signer| @zone_keys.key?(signer) }
      end

      def rrset_for(ids)
        id_list = Array(ids)
        raise ReplayError, 'A recorded RRset has no records' if id_list.empty?
        RRSet.new(id_list.map { |id| record!(id) })
      end

      def record!(id)
        @records[id] || raise(ReplayError, "Required evidence record #{id} is missing")
      end

      def used?(step)
        @evidence.used_step_ids.empty? || @evidence.used_step_ids.include?(step['id'])
      end

      def same_name?(left, right)
        left && right && Name.create(left).canonical == Name.create(right).canonical
      end

      def normalize_policy(value)
        case value
        when Hash then ValidationEvidence.deep_copy(value)
        when String then JSON.parse(value)
        else raise ReplayError, "Unsupported policy #{value.class}"
        end
      end
    end

    Result = Struct.new(:security_level, :time, :explanation_digest, :steps, :policy, :cache, :reason, keyword_init: true)
  end
end
