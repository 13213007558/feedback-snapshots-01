# frozen_string_literal: true

require "rails_helper"

describe Doorkeeper::OpenidConnect::KeyRing do
  # Build JWKs the same way the production module does so kids are real
  # thumbprints; this keeps the spec independent of how `build_jwk` parses PEMs.
  let(:builder) do
    ->(entry) { ::JWT::JWK.new(OpenSSL::PKey.read(entry.fetch(:key)),
                               { kid_generator: ::JWT::JWK::Thumbprint }) }
  end
  let(:predecessor_pem) { OpenSSL::PKey::RSA.generate(2048).to_pem }
  let(:candidate_pem) { OpenSSL::PKey::RSA.generate(2048).to_pem }
  let(:entries) { [{ key: predecessor_pem }] }

  subject(:ring) { described_class.new(entries: entries, builder: builder) }

  describe "#initialize" do
    it "makes the first configured entry the active key" do
      expect(ring.active_entry.export[:kty]).to eq "RSA"
    end

    it "raises InvalidConfiguration for an empty entry set" do
      expect { described_class.new(entries: [], builder: builder) }
        .to raise_error(Doorkeeper::OpenidConnect::Errors::InvalidConfiguration)
    end

    it "preserves declaration order while numbering oldest-to-newest" do
      second = OpenSSL::PKey::RSA.generate(2048).to_pem
      multi = described_class.new(
        entries: [{ key: predecessor_pem }, { key: second }], builder: builder,
      )

      expect(multi.published_entries.map(&:generation)).to eq [1, 0]
      expect(multi.active_entry.kid).to eq multi.published_entries.first.kid
    end

    it "accepts both bare keys and per-key option hashes" do
      second = OpenSSL::PKey::RSA.generate(2048).to_pem
      multi = described_class.new(
        entries: [predecessor_pem, { key: second }], builder: builder,
      )

      expect(multi.published_entries.size).to eq 2
    end
  end

  describe "#prepare" do
    it "parks the candidate as pending without publishing it" do
      ring.prepare(candidate_pem)

      expect(ring).to be_pending
      expect(ring.pending_entry.kid).not_to eq ring.active_entry.kid
      expect(ring.published_entries.map(&:kid)).to eq [ring.active_entry.kid]
    end

    it "validates the candidate before changing any state" do
      expect { ring.prepare("not-a-valid-pem") }.to raise_error(OpenSSL::PKey::PKeyError)

      expect(ring).not_to be_pending
      expect(ring.published_entries.size).to eq 1
    end

    it "leaves discovery/JWKS readers on the previous configuration" do
      before = ring.published_entries.map(&:kid)
      ring.prepare(candidate_pem)

      expect(ring.published_entries.map(&:kid)).to eq before
      expect(ring.active_entry.kid).to eq before.first
    end
  end

  describe "#commit" do
    it "promotes the pending key to the active generation" do
      pending = ring.prepare(candidate_pem)
      ring.commit

      expect(ring).not_to be_pending
      expect(ring.active_entry.kid).to eq pending.kid
      expect(ring.published_entries.size).to eq 2
    end

    it "assigns a strictly higher generation to each committed key" do
      first_generation = ring.active_entry.generation
      ring.prepare(candidate_pem)
      ring.commit

      expect(ring.active_entry.generation).to eq first_generation + 1
    end

    it "keeps the predecessor verifiable through generation_for" do
      predecessor_kid = ring.active_entry.kid
      ring.prepare(candidate_pem)
      ring.commit

      expect(ring.generation_for(predecessor_kid)).to eq 0
      expect(ring.generation_for(ring.active_entry.kid)).to eq 1
      expect(ring.generation_for("unknown-kid")).to be_nil
    end

    it "raises when there is no pending key" do
      expect { ring.commit }
        .to raise_error(Doorkeeper::OpenidConnect::Errors::InvalidConfiguration)
    end

    context "when persistence fails" do
      before do
        ring.persister = ->(_snapshot) { raise "persistence outage" }
        ring.prepare(candidate_pem)
      end

      it "aborts the commit and keeps the previous generation active" do
        predecessor_kid = ring.active_entry.kid

        expect { ring.commit }.to raise_error(RuntimeError, "persistence outage")
        expect(ring).to be_pending
        expect(ring.active_entry.kid).to eq predecessor_kid
        expect(ring.published_entries.size).to eq 1
      end

      it "can be retried successfully once persistence recovers" do
        expect { ring.commit }.to raise_error(RuntimeError)

        ring.persister = described_class::NullPersister
        expect { ring.commit }.not_to raise_error
        expect(ring.published_entries.size).to eq 2
      end
    end

    it "hands the persister a snapshot before swapping the active generation" do
      seen = nil
      ring.persister = ->(snapshot) { seen = snapshot }
      ring.prepare(candidate_pem)
      ring.commit

      expect(seen[:active_generation]).to eq 0
      expect(seen[:pending][:kid]).to eq ring.active_entry.kid
      expect(seen[:generations].size).to eq 1
    end
  end

  describe "#rollback" do
    it "discards the pending candidate without touching the active generation" do
      active_kid = ring.active_entry.kid
      pending = ring.prepare(candidate_pem)
      rolled_back = ring.rollback

      expect(rolled_back.kid).to eq pending.kid
      expect(ring).not_to be_pending
      expect(ring.active_entry.kid).to eq active_kid
      expect(ring.published_entries.size).to eq 1
    end
  end

  describe "#snapshot" do
    it "never includes the pending key in the published generations" do
      ring.prepare(candidate_pem)
      snapshot = ring.snapshot

      expect(snapshot[:pending]).not_to be_nil
      expect(snapshot[:generations].map { |g| g[:kid] })
        .to eq [ring.published_entries.first.kid]
    end
  end

  describe "concurrency at the rotation boundary" do
    it "resolves concurrent reads to a single identifiable generation" do
      ring.prepare(candidate_pem)
      barrier = Queue.new
      selected = []

      reader = Thread.new do
        entry = ring.active_entry
        selected << ring.generation_for(entry.kid)
        barrier << :go
        barrier.pop
        # The commit happens while this thread holds the entry it selected.
        selected << ring.generation_for(entry.kid)
      end

      barrier.pop # wait until the reader has captured its generation
      ring.commit
      barrier << :release
      reader.join

      expect(selected).to eq [0, 0]
      expect(ring.active_entry.generation).to eq 1
    end
  end
end
