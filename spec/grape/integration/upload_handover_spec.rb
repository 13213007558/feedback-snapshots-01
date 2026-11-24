# frozen_string_literal: true

describe Grape::Middleware::UploadHandover do
  let(:client_tempfiles) { [] }
  let(:captured) { {} }
  let(:registry) { last_request.env[Grape::Env::GRAPE_UPLOAD_REGISTRY] }

  after do
    client_tempfiles.each(&:close!)
  end

  def make_upload(name, content, filename:)
    tempfile = Tempfile.new(name)
    tempfile.write(content)
    tempfile.rewind
    client_tempfiles << tempfile
    Rack::Test::UploadedFile.new(tempfile.path, 'text/plain', original_filename: filename)
  end

  def entry(param)
    registry.entries.find { |e| e.param == param }
  end

  context 'when a field of the form fails validation' do
    let(:app) do
      Class.new(Grape::API) do
        format :json

        params do
          requires :title, type: String, regexp: /\A[a-z]+\z/
          requires :approved, type: File
          requires :rejected, type: File
        end

        post do
          { title: params[:title] }
        end
      end
    end

    before do
      post '/',
           title: 'NOT lowercase!',
           approved: make_upload('approved', 'approved content', filename: 'approved.txt'),
           rejected: make_upload('rejected', 'rejected content', filename: 'rejected.txt')
    end

    it 'rejects the form' do
      expect(last_response.status).to eq(400)
    end

    it 'closes both tempfiles itself' do
      expect(entry('approved').tempfile).to be_closed
      expect(entry('rejected').tempfile).to be_closed
    end

    it 'records the whole lifecycle without a handover' do
      expect(registry.audit_trail).to eq(
        [
          { event: :tracked, param: 'approved', filename: 'approved.txt' },
          { event: :tracked, param: 'rejected', filename: 'rejected.txt' },
          { event: :closed, param: 'approved', filename: 'approved.txt' },
          { event: :closed, param: 'rejected', filename: 'rejected.txt' }
        ]
      )
    end
  end

  context 'when the endpoint takes one of the files over' do
    let(:app) do
      captured_uploads = captured
      Class.new(Grape::API) do
        format :json

        params do
          requires :approved, type: File
          requires :rejected, type: File
        end

        post do
          captured_uploads[:kept] = take_over_upload(:approved)
          { kept: captured_uploads[:kept][:filename] }
        end
      end
    end

    before do
      post '/',
           approved: make_upload('approved', 'approved content', filename: 'approved.txt'),
           rejected: make_upload('rejected', 'rejected content', filename: 'rejected.txt')
    end

    it 'answers with the kept file' do
      expect(last_response.status).to eq(201)
      expect(JSON.parse(last_response.body)).to eq('kept' => 'approved.txt')
    end

    it 'leaves the taken-over tempfile open for the business' do
      expect(captured[:kept][:tempfile]).not_to be_closed
      expect(captured[:kept][:tempfile].read).to eq('approved content')
    end

    it 'closes the rejected tempfile' do
      expect(entry('rejected').tempfile).to be_closed
      expect { entry('rejected').tempfile.read }.to raise_error(IOError)
    end

    it 'records the handover boundary' do
      expect(registry.audit_trail).to eq(
        [
          { event: :tracked, param: 'approved', filename: 'approved.txt' },
          { event: :tracked, param: 'rejected', filename: 'rejected.txt' },
          { event: :handed_over, param: 'approved', filename: 'approved.txt' },
          { event: :closed, param: 'rejected', filename: 'rejected.txt' }
        ]
      )
    end
  end

  context 'when the endpoint stops the request itself' do
    let(:app) do
      Class.new(Grape::API) do
        format :json

        params do
          requires :approved, type: File
          requires :rejected, type: File
        end

        post do
          error!('materials rejected', 422)
        end
      end
    end

    before do
      post '/',
           approved: make_upload('approved', 'approved content', filename: 'approved.txt'),
           rejected: make_upload('rejected', 'rejected content', filename: 'rejected.txt')
    end

    it 'answers the error' do
      expect(last_response.status).to eq(422)
    end

    it 'closes both tempfiles itself' do
      expect(entry('approved').tempfile).to be_closed
      expect(entry('rejected').tempfile).to be_closed
    end

    it 'records the whole lifecycle without a handover' do
      expect(registry.audit_trail).to eq(
        [
          { event: :tracked, param: 'approved', filename: 'approved.txt' },
          { event: :tracked, param: 'rejected', filename: 'rejected.txt' },
          { event: :closed, param: 'approved', filename: 'approved.txt' },
          { event: :closed, param: 'rejected', filename: 'rejected.txt' }
        ]
      )
    end
  end

  context 'when a filename is internal diagnostics only' do
    let(:app) do
      captured_uploads = captured
      Class.new(Grape::API) do
        format :json

        internal_upload_names :draft

        params do
          requires :approved, type: File
          requires :draft, type: File
        end

        post do
          captured_uploads[:draft_name] = params[:draft][:filename]
          take_over_upload(:approved)
          { draft: params[:draft][:filename] }
        end
      end
    end

    before do
      post '/',
           approved: make_upload('approved', 'approved content', filename: 'approved.txt'),
           draft: make_upload('draft', 'draft content', filename: 'client-draft.txt')
    end

    it 'shows the business a placeholder name' do
      expect(last_response.status).to eq(201)
      expect(JSON.parse(last_response.body)).to eq('draft' => 'draft.internal')
      expect(captured[:draft_name]).to eq('draft.internal')
    end

    it 'never exposes the client filename to the business' do
      expect(last_response.body).not_to include('client-draft.txt')
    end

    it 'keeps the client filename in the audit trail for the support side' do
      draft_events = registry.audit_trail.select { |event| event[:param] == 'draft' }
      expect(draft_events).to eq(
        [
          { event: :tracked, param: 'draft', filename: 'client-draft.txt' },
          { event: :closed, param: 'draft', filename: 'client-draft.txt' }
        ]
      )
    end
  end
end
