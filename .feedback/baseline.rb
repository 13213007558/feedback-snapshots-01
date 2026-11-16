require 'rubygems'
root = File.expand_path('..', __dir__)
Gem.use_paths(File.join(root, '.gems'), [File.join(root, '.gems')])
$LOAD_PATH.unshift(File.join(root, 'lib'))
$LOAD_PATH.unshift(File.join(root, 'test'))
gem 'minitest', '=5.27.0'
Dir[File.join(root,'test/test_*.rb')].sort.each { |f| require f }
