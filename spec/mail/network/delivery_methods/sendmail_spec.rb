# encoding: utf-8
# frozen_string_literal: true
require 'securerandom'
require 'tmpdir'
require 'spec_helper'

RSpec.describe Mail::Sendmail do
  let :mail do
    Mail.new do
      from    'roger@test.lindsaar.net'
      to      'marcel@test.lindsaar.net, bob@test.lindsaar.net'
      subject 'some subject'
    end
  end

  before do
    Mail.defaults do
      delivery_method :sendmail
    end
  end

  it 'sends an email using sendmail' do
    expect(mail.delivery_method).to receive(:popen).
      with(%w[ /usr/sbin/sendmail -i
        -f roger@test.lindsaar.net
        -- marcel@test.lindsaar.net bob@test.lindsaar.net ])

    mail.deliver!
  end

  it 'spawns a sendmail process' do
    expect(mail.delivery_method).to receive(:popen).
      with(%w[ /usr/sbin/sendmail -i
        -f roger@test.lindsaar.net
        -- marcel@test.lindsaar.net bob@test.lindsaar.net ])

    mail.deliver!
  end

  context 'SMTP From' do
    it 'explicitly passes an envelope From address to sendmail' do
      expect(mail.delivery_method).to receive(:popen).
        with(%w[ /usr/sbin/sendmail -i
          -f smtp_from@test.lindsaar.net
          -- marcel@test.lindsaar.net bob@test.lindsaar.net ])

      mail.smtp_envelope_from = 'smtp_from@test.lindsaar.net'
      mail.deliver
    end

    it 'escapes the From address' do
      expect(mail.delivery_method).to receive(:popen).
        with([ '/usr/sbin/sendmail', '-i',
          '-f', '"from+suffix test"@test.lindsaar.net',
          '--', 'marcel@test.lindsaar.net', 'bob@test.lindsaar.net' ])

      mail.from = '"from+suffix test"@test.lindsaar.net'
      mail.deliver
    end

    it 'does not escape ~ in From address' do
      expect(mail.delivery_method).to receive(:popen).
        with(%w[ /usr/sbin/sendmail -i
          -f tilde~@test.lindsaar.net
          -- marcel@test.lindsaar.net bob@test.lindsaar.net ])

      mail.from = 'tilde~@test.lindsaar.net'
      mail.deliver
    end
  end

  context 'SMTP To' do
    it 'explicitly passes envelope To addresses to sendmail' do
      expect(mail.delivery_method).to receive(:popen).
        with(%w[ /usr/sbin/sendmail -i
          -f roger@test.lindsaar.net
          -- smtp_to@test.lindsaar.net ])

      mail.smtp_envelope_to = 'smtp_to@test.lindsaar.net'
      mail.deliver
    end

    it 'escapes the To address' do
      expect(mail.delivery_method).to receive(:popen).
        with([ '/usr/sbin/sendmail', '-i',
          '-f', 'roger@test.lindsaar.net',
          '--', '"to+suffix test"@test.lindsaar.net' ])

      mail.to = '"to+suffix test"@test.lindsaar.net'
      mail.deliver
    end

    it 'does not escape ~ in To address' do
      expect(mail.delivery_method).to receive(:popen).
        with(%w[ /usr/sbin/sendmail -i
          -f roger@test.lindsaar.net
          -- tilde~@test.lindsaar.net ])

      mail.to = 'tilde~@test.lindsaar.net'
      mail.deliver
    end

    it 'quotes the destinations to ensure leading -hyphen doesn\'t confuse sendmail' do
      expect(mail.delivery_method).to receive(:popen).
        with(%w[ /usr/sbin/sendmail -i
          -f roger@test.lindsaar.net
          -- -hyphen@test.lindsaar.net ])

      mail.to = '-hyphen@test.lindsaar.net'
      mail.deliver
    end
  end

  it 'still sends an email if the arguments setting have been set to nil' do
    expect(mail.delivery_method).to receive(:popen).
      with(%w[ /usr/sbin/sendmail
        -f roger@test.lindsaar.net
        -- marcel@test.lindsaar.net bob@test.lindsaar.net ])

    mail.delivery_method.settings[:arguments] = nil
    mail.deliver!
  end

  it 'escapes evil haxxor attempts' do
    evil = '"foo\";touch /tmp/PWNED;\""@blah.com'

    expect(mail.delivery_method).to receive(:popen).
      with([ '/usr/sbin/sendmail', '-i', '-f', evil, '--', evil ])

    mail.from = evil
    mail.to   = evil
    mail.deliver!
  end

  it 'raises an error if no sender is defined' do
    mail = Mail.new do
      to "to@somemail.com"
      subject "Email with no sender"
      body "body"
    end

    expect(mail.smtp_envelope_from).to be_nil

    expect do
      mail.deliver
    end.to raise_error('SMTP From address may not be blank: nil')
  end

  it 'raises an error if no recipient is defined' do
    mail = Mail.new do
      from "from@somemail.com"
      subject "Email with no recipient"
      body "body"
    end

    expect(mail.smtp_envelope_to).to eq([])

    expect do
      mail.deliver!
    end.to raise_error('SMTP To address may not be blank: []')
  end

  describe 'process and pipe handling with a real transport', :slow do
    let(:fake_sendmail) do
      File.expand_path('../../../../fixtures/sendmail/fake_sendmail.rb', __FILE__)
    end

    let(:tmp_id) { "#{Process.pid}-#{object_id}-#{SecureRandom.hex(4)}" }
    let(:outfile) { File.join(Dir.tmpdir, "mail-sendmail-#{tmp_id}.eml") }
    let(:pidfile) { File.join(Dir.tmpdir, "mail-sendmail-pid-#{tmp_id}.txt") }

    def delivery_method(mode, options = {})
      env = options.delete(:env) || {}
      env.each { |key, value| ENV[key] = value.to_s }

      Mail::Sendmail.new(
        {
          :location => RbConfig.ruby,
          :arguments => [fake_sendmail],
          :read_timeout => 2,
          :max_stderr_bytesize => 256
        }.merge(options)
      )
    end

    def big_mail(size, recipients = 3)
      addresses = ['roger@test.lindsaar.net'] +
                  (2..recipients).map { |i| "recipient-#{i}@test.lindsaar.net" }
      Mail.new do
        from    'sender@test.lindsaar.net'
        to      addresses
        subject 'backpressure'
        body    'Z' * size
      end
    end

    def fake_env(mode, extra = {})
      {
        'FAKE_SENDMAIL_MODE' => mode,
        'FAKE_SENDMAIL_OUTFILE' => outfile,
        'FAKE_SENDMAIL_PIDFILE' => pidfile,
        'FAKE_SENDMAIL_READ_DELAY' => '0',
        'FAKE_SENDMAIL_CHUNK' => '128'
      }.merge(extra)
    end

    def alive?(pid)
      Process.kill(0, pid)
      true
    rescue Errno::ESRCH
      false
    end

    def open_fds
      Dir.glob('/dev/fd/*').map { |path| File.basename(path).to_i }.reject { |fd| fd < 3 }
    end

    after do
      ENV.delete_if { |key, _| key.start_with?('FAKE_SENDMAIL_') }
      [outfile, pidfile].each { |path| File.delete(path) if File.exist?(path) }
    end

    it 'streams the whole message and returns the delivery method on success' do
      method = delivery_method('success', :env => fake_env('success'))
      message = big_mail(500_000)

      expect(method.deliver!(message)).to equal(method)

      delivered = File.binread(outfile)
      expect(delivered).to include('ZZZ')
      expect(delivered.bytesize).to eq(Mail::Utilities.binary_unsafe_to_lf(message.encoded).bytesize)
    end

    it 'raises a known DeliveryError on a non-zero exit after the full body is written' do
      method = delivery_method('fail', :env => fake_env('fail'))

      expect { method.deliver!(big_mail(10_000)) }.
        to raise_error(Mail::Sendmail::DeliveryError, /exitstatus 3/)
    end

    it 'distinguishes a definite failure from an unknown result' do
      expect(Mail::Sendmail::DeliveryUnknownError.new('x')).to be_a(Mail::Sendmail::DeliveryError)
    end

    it 'reports an unknown result when the transport exits before reading the body' do
      method = delivery_method('exit_early', :env => fake_env('exit_early'))

      expect { method.deliver!(big_mail(2_000_000)) }.
        to raise_error(Mail::Sendmail::DeliveryUnknownError, /delivery result unknown/)
    end

    it 'never echoes the message body or the full recipient list in an error' do
      secret = 'TOP-SECRET-MESSAGE-CONTENT'
      message = Mail.new do
        from 'sender@test.lindsaar.net'
        to   ['one@test.lindsaar.net', 'two@test.lindsaar.net', 'three@test.lindsaar.net']
        subject 'secret'
        body secret
      end
      method = delivery_method('fail', :env => fake_env('fail'))

      expect { method.deliver!(message) }.to raise_error(Mail::Sendmail::DeliveryError) do |error|
        expect(error.message).not_to include(secret)
        expect(error.message).not_to include('one@test.lindsaar.net')
        expect(error.message).not_to include('two@test.lindsaar.net')
        expect(error.message).not_to include('three@test.lindsaar.net')
      end
    end

    it 'caps retained diagnostics instead of buffering unbounded output' do
      method = delivery_method(
        'noisy_fail',
        :env => fake_env('noisy_fail', 'FAKE_SENDMAIL_NOISE_BYTES' => 2_000_000),
        :max_stderr_bytesize => 128
      )

      expect { method.deliver!(big_mail(2_000_000)) }.to raise_error(Mail::Sendmail::DeliveryError) do |error|
        expect(error.message.length).to be < 400
        expect(error.message).to include('...')
      end
    end

    it 'completes under simultaneous stdin and diagnostics backpressure without deadlock' do
      method = delivery_method(
        'bidirectional',
        :env => fake_env('bidirectional', 'FAKE_SENDMAIL_NOISE_BYTES' => 3_000_000),
        :read_timeout => 20,
        :max_stderr_bytesize => 512
      )
      message = big_mail(3_000_000)

      expect { method.deliver!(message) }.not_to raise_error
      expect(File.binread(outfile).bytesize).
        to eq(Mail::Utilities.binary_unsafe_to_lf(message.encoded).bytesize)
    end

    it 'times out, terminates and reaps a transport that never reads or exits' do
      method = delivery_method('hang', :env => fake_env('hang'), :read_timeout => 1)

      expect { method.deliver!(big_mail(100_000)) }.
        to raise_error(Mail::Sendmail::DeliveryUnknownError, /Timed out|terminated|unknown/)

      pid = File.read(pidfile).to_i
      sleep 0.2
      expect(alive?(pid)).to eq(false)
    end

    it 'reclaims every child process and file descriptor across mixed outcomes' do
      modes = %w[success fail exit_early hang bidirectional]
      spawned_pids = []
      fds_before = open_fds

      25.times do |index|
        mode = modes[index % modes.length]
        method = delivery_method(
          mode,
          :env => fake_env(mode, 'FAKE_SENDMAIL_NOISE_BYTES' => '100000'),
          :read_timeout => 1
        )
        begin
          method.deliver!(big_mail(250_000))
        rescue Mail::Sendmail::DeliveryError
        end
        spawned_pids << File.read(pidfile).to_i if File.exist?(pidfile)
      end

      GC.start
      sleep 0.2

      expect(spawned_pids.reject { |pid| !alive?(pid) }).to eq([])
      expect(open_fds - fds_before).to eq([])
    end
  end
end
