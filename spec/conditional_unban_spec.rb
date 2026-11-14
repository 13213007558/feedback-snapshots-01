# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/freeze_time_helper'

# Minimal in-memory store with atomic compare-and-delete, used to
# demonstrate the conditional unban timelines.
class ConditionalUnbanInMemoryStore
  Entry = Struct.new(:value, :expires_at)

  attr_accessor :fail_conditional_delete

  def initialize
    @data = {}
    @fail_conditional_delete = false
  end

  def read(key)
    entry = @data[key]
    return nil if entry.nil? || expired?(entry)

    entry.value
  end

  def write(key, value, options = {})
    expires_in = options[:expires_in]
    @data[key] = Entry.new(value, expires_in && (Time.now + expires_in))
    true
  end

  def increment(key, amount, options = {})
    value = (read(key) || 0) + amount
    write(key, value, options)
    value
  end

  def delete(key)
    @data.delete(key)
  end

  def delete_if_equal(key, expected)
    return nil if @fail_conditional_delete

    entry = @data[key]
    return :absent if entry.nil? || expired?(entry)
    return :mismatch unless entry.value == expected

    @data.delete(key)
    :deleted
  end

  def expires_at(key)
    entry = @data[key]
    entry && entry.expires_at
  end

  private

  def expired?(entry)
    entry.expires_at && entry.expires_at <= Time.now
  end
end

describe 'conditional unban' do
  [Rack::Attack::Fail2Ban, Rack::Attack::Allow2Ban].each do |filter_class|
    describe filter_class.name do
      before do
        @filter = filter_class
        @store = ConditionalUnbanInMemoryStore.new
        Rack::Attack.cache.store = @store
        @options = { bantime: 60, findtime: 60, maxretry: 2 }
      end

      def ban(discriminator)
        @options[:maxretry].times { @filter.filter(discriminator, @options) { true } }
      end

      it 'reads ban info without refreshing the ban expiry' do
        ban('1.2.3.4')
        key = "rack::attack:#{@filter.send(:key_prefix)}:ban:1.2.3.4"
        expires_before = @store.expires_at(key)

        info = @filter.ban_info('1.2.3.4')

        refute_nil info
        assert_equal '1.2.3.4', info.discriminator
        refute_nil info.version
        assert_equal expires_before, @store.expires_at(key)
      end

      it 'returns nil ban info when not banned' do
        assert_nil @filter.ban_info('1.2.3.4')
      end

      describe 'timeline: read penalty -> new penalty -> stale unban' do
        it 'rejects the stale unban and keeps the new penalty' do
          ban('1.2.3.4')
          stale_info = @filter.ban_info('1.2.3.4')

          # The first ban expires, a new attack wave triggers a new penalty.
          Timecop.travel(Time.now + @options[:bantime] + 1) do
            ban('1.2.3.4')
            new_info = @filter.ban_info('1.2.3.4')
            refute_equal stale_info.version, new_info.version

            result = @filter.unban('1.2.3.4', @options, version: stale_info.version)

            assert_equal :changed, result
            assert @filter.banned?('1.2.3.4')
            assert_equal new_info.version, @filter.ban_info('1.2.3.4').version
          end
        end

        it 'ignores a stale unban when the ban simply expired' do
          ban('1.2.3.4')
          stale_info = @filter.ban_info('1.2.3.4')

          Timecop.travel(Time.now + @options[:bantime] + 1) do
            refute @filter.banned?('1.2.3.4')

            assert_equal :unbanned, @filter.unban('1.2.3.4', @options, version: stale_info.version)
            refute @filter.banned?('1.2.3.4')
          end
        end
      end

      describe 'timeline: repeated unban' do
        it 'lifts the matching ban once and stays idempotent' do
          ban('1.2.3.4')
          info = @filter.ban_info('1.2.3.4')

          assert_equal :unbanned, @filter.unban('1.2.3.4', @options, version: info.version)
          refute @filter.banned?('1.2.3.4')

          # The fail count was reset too: one new failure does not re-ban.
          @filter.filter('1.2.3.4', @options) { true }
          refute @filter.banned?('1.2.3.4')

          # Repeating the same unban request is a harmless no-op.
          assert_equal :unbanned, @filter.unban('1.2.3.4', @options, version: info.version)
          refute @filter.banned?('1.2.3.4')
        end
      end

      it 'reports storage failure when the store cannot execute the delete' do
        ban('1.2.3.4')
        info = @filter.ban_info('1.2.3.4')
        @store.fail_conditional_delete = true

        assert_equal :storage_failure, @filter.unban('1.2.3.4', @options, version: info.version)
        assert @filter.banned?('1.2.3.4')
      end

      it 'refuses conditional unban when the store does not support it' do
        Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
        ban('1.2.3.4')
        info = @filter.ban_info('1.2.3.4')

        error = assert_raises(Rack::Attack::IncompatibleStoreError) do
          @filter.unban('1.2.3.4', @options, version: info.version)
        end
        assert_match(/doesn't support conditional delete/, error.message)
      end

      it 'requires a findtime option' do
        assert_raises(ArgumentError) do
          @filter.unban('1.2.3.4', {}, version: 'whatever')
        end
      end
    end
  end
end
