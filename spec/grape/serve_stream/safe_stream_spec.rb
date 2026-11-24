# frozen_string_literal: true

describe Grape::ServeStream::SafeStream do
  # A body that records how it was driven and can fail at either point.
  let(:body) { BodyDouble.new(chunks, failure_at:) }
  let(:env) { Rack::MockRequest.env_for('/') }
  let(:chunks) { ['first', 'second'] }
  let(:failure_at) { nil }

  let(:safe_stream) { described_class.new(body, env) }

  def drain(stream)
    received = []
    stream.each { |chunk| received << chunk }
    received
  end

  describe '#probe' do
    context 'when the body yields a first chunk' do
      it 'buffers it without dropping it' do
        safe_stream.probe
        expect(drain(safe_stream)).to eq(%w[first second])
      end

      it 'drives the body through a single iteration' do
        safe_stream.probe
        drain(safe_stream)
        expect(body.iterations).to eq(1)
      end
    end

    context 'when the body yields a falsy first chunk' do
      let(:chunks) { [nil, false, 'tail'] }

      it 'replays every chunk without dropping the falsy ones' do
        safe_stream.probe
        expect(drain(safe_stream)).to eq([nil, false, 'tail'])
      end
    end

    context 'when the body is empty' do
      let(:chunks) { [] }

      it 'probes without raising and each yields nothing' do
        expect { safe_stream.probe }.not_to raise_error
        expect(drain(safe_stream)).to eq([])
        expect(body).to be_closed
      end
    end

    context 'when the body fails before the first chunk' do
      let(:failure_at) { :before }

      it 'wraps the failure in a ProbeError carrying the original as cause' do
        expect { safe_stream.probe }.to raise_error(Grape::ServeStream::ProbeError) do |error|
          expect(error.cause).to be_a(RuntimeError)
          expect(error.message).not_to include('SECRET')
        end
      end

      it 'closes the wrapped body' do
        safe_stream.probe
      rescue Grape::ServeStream::ProbeError
        expect(body).to be_closed
      end
    end
  end

  describe '#each' do
    context 'when the body fails after the first chunk' do
      let(:failure_at) { :after }

      it 'keeps the chunks already sent and ends without raising' do
        safe_stream.probe
        expect(drain(safe_stream)).to eq(['first'])
      end

      it 'closes the wrapped body' do
        safe_stream.probe
        drain(safe_stream)
        expect(body).to be_closed
      end

      it 'publishes the original exception on the rack env' do
        safe_stream.probe
        drain(safe_stream)
        expect(env[Grape::Env::GRAPE_EXCEPTION]).to be_a(RuntimeError)
        expect(env[Grape::Env::RACK_EXCEPTION]).to be(env[Grape::Env::GRAPE_EXCEPTION])
      end

      it 'writes only the exception class to rack.errors, never its message' do
        errors = StringIO.new
        env[Rack::RACK_ERRORS] = errors
        safe_stream.probe
        drain(safe_stream)
        expect(errors.string).to include('RuntimeError')
        expect(errors.string).not_to include('SECRET')
      end
    end

    context 'when the body completes' do
      it 'yields every chunk once and closes' do
        safe_stream.probe
        expect(drain(safe_stream)).to eq(%w[first second])
        expect(body).to be_closed
      end
    end

    it 'is idempotent on close' do
      safe_stream.close
      safe_stream.close
      expect(body.close_count).to eq(1)
    end
  end

  # Minimal enumerable body with explicit lifecycle tracking.
  class BodyDouble
    attr_reader :iterations, :close_count

    def initialize(chunks, failure_at:)
      @chunks = chunks
      @failure_at = failure_at
      @iterations = 0
      @close_count = 0
    end

    def each
      @iterations += 1
      raise RuntimeError, 'SECRET-before-first-byte' if @failure_at == :before

      @chunks.each_with_index do |chunk, index|
        yield chunk
        raise RuntimeError, 'SECRET-after-first-byte' if @failure_at == :after && index.zero?
      end
    end

    def close
      @close_count += 1
    end

    def closed?
      @close_count.positive?
    end
  end
end
