#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Configurable stand-in for a sendmail(8)-compatible local transport.
#
# The real Mail delivery method spawns this program with arbitrary sendmail
# flags (-i, -f, --, recipients ...); those are intentionally ignored. Behavior
# is driven entirely by FAKE_SENDMAIL_* environment variables so the same
# binary can model every failure/backpressure shape the tests need:
#
#   FAKE_SENDMAIL_MODE
#     success       read the whole message, exit 0 (default)
#     fail          read the whole message, emit diagnostics, exit non-zero
#     exit_early    exit immediately without reading stdin (broken pipe race)
#     hang          never read stdin and never exit (forces a timeout)
#     slow_read     read stdin one small chunk at a time, sleeping between
#     noisy         flood stderr while reading (diagnostics-pipe backpressure)
#     noisy_fail    flood stderr while reading, then exit non-zero
#     bidirectional slow reader *and* noisy writer (both pipes under pressure)
#
#   FAKE_SENDMAIL_EXIT_STATUS   integer status for fail/exit_early (default 3)
#   FAKE_SENDMAIL_READ_DELAY    seconds slept between stdin reads (default 0.01)
#   FAKE_SENDMAIL_CHUNK         bytes read per stdin read (default 64)
#   FAKE_SENDMAIL_NOISE_BYTES   max bytes written to stderr (default 0)
#   FAKE_SENDMAIL_OUTFILE       where the received message body is stored
#   FAKE_SENDMAIL_PIDFILE       where this process writes its pid
#
# Reading stdin and writing diagnostics run on separate threads, mirroring a
# real MTA that drains the message and emits status independently. All output
# goes to stderr, which the delivery method merges with stdout.

def env_int(name, default)
  ENV.key?(name) ? Integer(ENV[name]) : default
end

mode        = ENV.fetch('FAKE_SENDMAIL_MODE', 'success')
exit_status = env_int('FAKE_SENDMAIL_EXIT_STATUS', 3)
read_delay  = ENV.key?('FAKE_SENDMAIL_READ_DELAY') ? Float(ENV['FAKE_SENDMAIL_READ_DELAY']) : 0.01
chunk_size  = env_int('FAKE_SENDMAIL_CHUNK', 64)
noise_bytes = env_int('FAKE_SENDMAIL_NOISE_BYTES', 0)
outfile     = ENV['FAKE_SENDMAIL_OUTFILE']
pidfile     = ENV['FAKE_SENDMAIL_PIDFILE']

File.write(pidfile, Process.pid.to_s) if pidfile

slow = mode == 'slow_read' || mode == 'bidirectional' || mode == 'noisy_fail'
noisy = mode == 'noisy' || mode == 'bidirectional' || mode == 'noisy_fail'

# Independent producer: keeps writing diagnostics up to the byte budget so the
# diagnostics pipe can fill and exert backpressure on the parent regardless of
# how slowly the message is consumed.
noise_stop = false
noise_thread = Thread.new do
  written = 0
  stamp = "fake-sendmail diagnostics stream: ".b
  until noise_stop
    if noisy && written < noise_bytes
      remaining = noise_bytes - written
      piece = stamp.byteslice(0, [stamp.bytesize, remaining].min)
      written += $stderr.write(piece)
      $stderr.flush
    else
      sleep 0.005
    end
  end
rescue IOError, Errno::EPIPE
  # Parent closed the read end; stop quietly.
end

reader_thread = Thread.new do
  received = +''.b
  if slow
    until (piece = $stdin.read(chunk_size)).nil?
      received << piece
      sleep read_delay
    end
  else
    received << $stdin.read
  end
  File.binwrite(outfile, received) if outfile
  received.bytesize
rescue IOError
  received.bytesize
end

case mode
when 'hang'
  # Never touch stdin and never finish on our own; the parent must time out,
  # terminate and reap us.
  sleep
when 'exit_early'
  # Leave without consuming stdin so the parent's write hits a broken pipe.
  $stdin.close
  noise_stop = true
  noise_thread.join
  exit(exit_status)
when 'fail', 'noisy_fail'
  reader_thread.join
  $stderr.puts "fake-sendmail: simulated local delivery failure"
  $stderr.flush
  noise_stop = true
  noise_thread.join
  exit(exit_status)
else
  reader_thread.join
  noise_stop = true
  noise_thread.join
  exit 0
end
