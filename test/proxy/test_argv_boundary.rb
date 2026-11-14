require_relative '../common'
require 'tmpdir'
require 'json'
require 'net/ssh/proxy/command'
require 'net/ssh/proxy/jump'

module NetSSH
  # These tests run the real shell that IO.popen uses with a stand-in that only
  # records its argv, so a value that crosses an argument boundary is visible
  # even when nothing is executed. The stand-in never connects anywhere.
  class TestProxyArgvBoundary < NetSSHTest
    def setup
      skip "argv stub needs a POSIX shell" if Gem.win_platform?

      @dir = Dir.mktmpdir
      @argv_log = File.join(@dir, "argv.log")
      @dir_on_path = File.join(@dir, "bin")
      Dir.mkdir(@dir_on_path)
      stub = File.join(@dir_on_path, "ssh")
      File.write(stub, "#!/usr/bin/env ruby\nrequire 'json'\n" \
                       "File.open(ENV.fetch('ARGV_LOG'), 'a') { |f| f.puts(JSON.generate(ARGV)) }\n")
      File.chmod(0o755, stub)
      @saved_path = ENV["PATH"]
      @saved_log = ENV["ARGV_LOG"]
      ENV["PATH"] = "#{@dir_on_path}:#{ENV["PATH"]}"
      ENV["ARGV_LOG"] = @argv_log
    end

    def teardown
      ENV["PATH"] = @saved_path
      ENV["ARGV_LOG"] = @saved_log
      FileUtils.remove_entry(@dir) if @dir
    end

    def test_proxy_command_substituted_values_keep_their_argument
      assert_argv ["relay", "u", "example.com", "22"], proxy: command("ssh relay %r %h %p")
      assert_argv ["relay", "u", "fe80::1%en0", "22"], proxy: command("ssh relay %r %h %p"), host: "fe80::1%en0"
      assert_argv ["relay", "first.last", "192.0.2.1", "65535"], proxy: command("ssh relay %r %h %p"),
                                                               host: "192.0.2.1", port: 65_535, user: "first.last"
    end

    def test_proxy_command_rejects_untrusted_values_before_the_child_starts
      command("ssh relay %r %h %p").tap do |proxy|
        ["a b", "a\nb", "a\tb", 'a"b', "a'b", "*", "~", "foo#bar", "$HOME", "a\\b", "x=y", "[::1]", "-oProxyCommand=id"].each do |host|
          assert_no_child(host.inspect) { proxy.open(host, 22, remote_user: "user") }
        end
        ["u v", "u\nv", 'u"v', "u'v", "u*", "u$v", "u\\v", "-u"].each do |user|
          assert_no_child(user.inspect) { proxy.open("example.com", 22, remote_user: user) }
        end
        ["", "0", "65536", "22\n", "22 ", "22;id"].each do |port|
          assert_no_child(port.inspect) { proxy.open("example.com", port, remote_user: "user") }
        end
      end
    end

    def test_proxy_jump_hop_and_destination_are_separate_arguments
      assert_argv ["-l", "u", "-p", "2222", "-J", "b@[fe80::1]:2200,[::2]", "-W", "[::1]:22", "::1"],
                  proxy: jump("u@[::1]:2222,b@[fe80::1]:2200,[::2]"), host: "[::1]"
      assert_argv ["-l", "u", "-J", "u@j2:2200,h3", "-W", "[example.com]:22", "j1"],
                  proxy: jump("u@j1,u@j2:2200,h3")
    end

    def test_proxy_jump_repeated_options_and_config_files_stay_separate_arguments
      proxy = jump("u@jump", options: { "IdentityFile" => ["/tmp/id one", "/tmp/id%h two"], "StrictHostKeyChecking" => "no" })
      # Net::SSH::Config lets an earlier file win, while ssh lets the last -F
      # win, so the files are passed in reverse to keep the same precedence.
      assert_argv ["-l", "u", "-F", "/tmp/conf two", "-F", "/tmp/conf one",
                   "-o", "IdentityFile=/tmp/id one", "-o", "IdentityFile=/tmp/id%h two",
                   "-o", "StrictHostKeyChecking=no", "-W", "[example.com]:22", "jump"],
                  proxy: proxy, config: ["/tmp/conf one", "/tmp/conf two"]
    end

    def test_proxy_jump_rejects_hop_and_destination_that_change_argv
      ["u$(id)@jump", "u@jump;id", "u@jump,x$(id)@j2", "u@jump/path", "u@jump?x", "u@jump#x"].each do |hop|
        assert_no_child(hop.inspect) { jump(hop).open("example.com", 22, remote_user: "u") }
      end
      ["*", "~", "foo#bar", "a b", "x=y"].each do |host|
        assert_no_child(host.inspect) { jump("u@jump").open(host, 22, remote_user: "u") }
      end
    end

    private

    def command(template)
      Net::SSH::Proxy::Command.new(template)
    end

    def jump(spec, options: {})
      Net::SSH::Proxy::Jump.new(spec, options: options)
    end

    def assert_no_child(message)
      File.write(@argv_log, "")
      assert_raises(ArgumentError, message) { yield }
      assert_equal "", File.read(@argv_log), "a child process was started for #{message}"
    end

    def assert_argv(expected, proxy:, host: "example.com", port: 22, user: "u", config: false)
      File.write(@argv_log, "")
      begin
        proxy.open(host, port, remote_user: user, config: config)
      rescue Net::SSH::Proxy::ConnectError
        # The stand-in exits without a connection; argv was already recorded.
      end
      sleep 0.05
      lines = File.readlines(@argv_log, chomp: true).reject(&:empty?)
      assert_equal 1, lines.length, "expected one child invocation, got #{lines.inspect}"
      assert_equal expected, JSON.parse(lines.first)
    end
  end
end
