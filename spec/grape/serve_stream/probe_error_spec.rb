# frozen_string_literal: true

describe Grape::ServeStream::ProbeError do
  let(:cause) { RuntimeError.new('SECRET internal state') }

  it 'preserves the original exception as its cause' do
    expect(described_class.new(cause).cause).to be(cause)
  end

  it 'does not relay the original message through its own' do
    expect(described_class.new(cause).message).not_to include('SECRET')
  end

  it 'is a StandardError so middleware rescue clauses still match it' do
    expect(described_class.new(cause)).to be_a(StandardError)
  end
end
