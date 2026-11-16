require 'json'
require 'rubygems'
root = File.expand_path('..', __dir__)
JSON.parse(File.read(File.join(__dir__, 'gems.json'))).each do |name, version|
  ok = system('gem', 'install', name, '--version', version, '--install-dir', File.join(root, '.gems'), '--no-document')
  abort "gem install failed: #{name}" unless ok
end
