# frozen_string_literal: true

describe Grape::UploadRegistry do
  subject(:registry) { described_class.new }

  def file_hash(filename)
    tempfile = Tempfile.new('upload')
    tempfile.write('content')
    tempfile.rewind
    { filename:, type: 'text/plain', tempfile: }
  end

  def request_with(params)
    instance_double(Rack::Request, POST: params)
  end

  describe '#track_request and #close_retained!' do
    it 'closes every tracked tempfile the endpoint did not take over' do
      kept = file_hash('kept.txt')
      dropped = file_hash('dropped.txt')
      registry.track_request(request_with('kept' => kept, 'dropped' => dropped, 'title' => 'hi'))

      registry.hand_over('kept')
      registry.close_retained!

      expect(kept[:tempfile]).not_to be_closed
      expect(dropped[:tempfile]).to be_closed
    end

    it 'tracks files nested in arrays under the param they arrived with' do
      files = [file_hash('a.txt'), file_hash('b.txt')]
      registry.track_request(request_with('files' => files))

      handed_over = registry.hand_over('files')
      expect(handed_over).to eq(files)
      registry.close_retained!
      expect(files.map { |file| file[:tempfile].closed? }).to eq([false, false])
    end

    it 'is idempotent' do
      upload = file_hash('a.txt')
      registry.track_request(request_with('file' => upload))

      registry.close_retained!
      expect { registry.close_retained! }.not_to change(registry.audit_trail, :size)
    end
  end

  describe '#hand_over' do
    it 'raises a KeyError for a param without an upload' do
      expect { registry.hand_over(:missing) }.to raise_error(KeyError, /missing/)
    end
  end

  describe 'internal names' do
    subject(:registry) { described_class.new(internal_names: %w[draft]) }

    it 'replaces the filename the endpoint sees and keeps the original in the audit trail' do
      draft = file_hash('client-draft.txt')
      registry.track_request(request_with('draft' => draft))

      expect(draft[:filename]).to eq('draft.internal')
      expect(registry.audit_trail).to eq([{ event: :tracked, param: 'draft', filename: 'client-draft.txt' }])
    end
  end
end
