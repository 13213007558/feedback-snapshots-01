# frozen_string_literal: true

require_relative "spec_helper"

describe Rack::Attack::Configuration do
  subject { Rack::Attack::Configuration.new }

  describe 'attributes' do
    it 'exposes the safelists attribute' do
      _(subject.safelists).must_equal({})
    end

    it 'exposes the blocklists attribute' do
      _(subject.blocklists).must_equal({})
    end

    it 'exposes the throttles attribute' do
      _(subject.throttles).must_equal({})
    end

    it 'exposes the tracks attribute' do
      _(subject.tracks).must_equal({})
    end

    it 'exposes the account_guards attribute' do
      _(subject.account_guards).must_equal({})
    end

    it 'registers and clears account guards' do
      classifier = ->(result) { result.status == 401 ? :failure : :success }
      subject.account_guard('logins', maxretry: 3, findtime: 60, bantime: 60,
                                      classifier: classifier) { |_| 'acct' }
      _(subject.account_guards.keys).must_equal(['logins'])
      _(subject.account_guards['logins']).must_be_kind_of Rack::Attack::AccountGuard

      subject.clear_configuration
      _(subject.account_guards).must_equal({})
    end

    it 'exposes the anonymous_blocklists attribute' do
      _(subject.anonymous_blocklists).must_equal([])
    end

    it 'exposes the anonymous_safelists attribute' do
      _(subject.anonymous_safelists).must_equal([])
    end
  end
end
