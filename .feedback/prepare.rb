# Prepare local, independent test dependencies; never change project sources.
require 'fileutils'
require 'digest'
require 'open3'
root = File.expand_path('..', __dir__)
Dir.chdir(root)
def checked(*argv)
  abort("Preparation failed: #{argv.first}") unless system(*argv)
end
exclude = `git rev-parse --git-path info/exclude`.strip
abort('Not a Git checkout') unless $?.success?
File.open(exclude, 'a') { |f| f.puts "\n.bundle/\n.feedback/vendor/\n.feedback/.bundle/\ncoverage/\nspec/tmp/\nspec/fixtures/database/\n" }
ENV['BUNDLE_GEMFILE'] = File.join(root, '.feedback', 'Gemfile')
checked('bundle', 'config', 'set', '--local', 'path', 'vendor/bundle')
cache = ARGV.first && File.expand_path(ARGV.first)
lock = '.feedback/Gemfile.lock'
if cache && File.directory?(File.join(cache, '.feedback/vendor/bundle')) &&
   File.file?(File.join(cache, lock)) && Digest::SHA256.file(lock).hexdigest == Digest::SHA256.file(File.join(cache, lock)).hexdigest &&
   !File.exist?('.feedback/vendor/bundle')
  FileUtils.mkdir_p('.feedback/vendor')
  FileUtils.cp_r(File.join(cache, '.feedback/vendor/bundle'), '.feedback/vendor/bundle')
end
# Also make ordinary `bundle exec` discover this preparation Gemfile.
FileUtils.mkdir_p('.bundle')
File.write('.bundle/config', "---\nBUNDLE_GEMFILE: \".feedback/Gemfile\"\n")
unless system('bundle', 'check', out: File::NULL, err: File::NULL)
  checked('bundle', 'install', '--jobs', '2', '--retry', '1')
end
actual, status = Open3.capture2('bundle', 'exec', 'ruby', '-e', 'require "bundler"; puts Bundler.bundle_path')
abort('Dependencies are not workspace-local') unless status.success? && actual.strip.start_with?(File.join(root, '.feedback/vendor/bundle') + '/')
