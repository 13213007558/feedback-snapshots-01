require 'json'
require 'rubygems'
root = File.expand_path('..', __dir__)
gem_root = File.join(root, '.gems')
exclude = File.join(root, '.git', 'info', 'exclude')
if File.file?(exclude)
  current = File.read(exclude)
  File.open(exclude, 'a') do |file|
    ['.gems/', 'coverage/'].each { |pattern| file.puts("\n#{pattern}") unless current.lines.map(&:strip).include?(pattern) }
  end
end
Gem.use_paths(gem_root, [gem_root])
JSON.parse(File.read(File.join(__dir__, 'gems.json'))).each do |name, version|
  installed = Gem::Specification.find_all_by_name(name, "=#{version}").any? { |spec| spec.full_gem_path.start_with?(gem_root + '/') }
  next if installed
  ok = system({'GEM_HOME' => gem_root, 'GEM_PATH' => gem_root}, 'gem', 'install', name, '--version', version, '--install-dir', gem_root, '--no-document')
  abort "gem install failed: #{name}" unless ok
  Gem::Specification.reset
end
