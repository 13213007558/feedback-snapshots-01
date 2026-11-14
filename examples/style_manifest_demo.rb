# frozen_string_literal: true

# Demonstrates generating a CSP style manifest bound to sanitized email HTML,
# and how the manifest fails to approve the output after any authorized style
# is modified.

require "json"
require_relative "../lib/sanitize"

input = <<~HTML
  <style>
    .banner {
      color: red;
      behavior: url(evil.htc);   /* 不在允许列表,将被删除 */
    }
  </style>
  <div class="banner" style="color:&#32;red; position: fixed">促销!</div>
  <p style="font-weight: bold">你好</p>
  <p style="font-weight: bold">世界</p>
HTML

sanitizer = Sanitize.new(Sanitize::Config::RELAXED)
html, manifest = sanitizer.document_with_manifest(input)

puts "== 清洗后的 HTML =="
puts html
puts

puts "== 样式摘要清单 (JSON) =="
puts JSON.pretty_generate(manifest.to_h)
puts

puts "== 调用方可生成的 CSP 授权 =="
puts manifest.csp_header
puts

result = manifest.verify(html)
puts "== 验证原始输出 =="
puts "approved? #{result.approved?}"
puts

tampered = html.sub("font-weight: bold", "font-weight: normal")
result = manifest.verify(tampered)
puts "== 篡改一个受授权样式后 (font-weight: bold -> normal) =="
puts "approved? #{result.approved?}"
result.unauthorized.each do |item|
  puts "未授权: kind=#{item.kind} content=#{item.content.inspect} at #{item.position}"
end
result.missing.each do |entry|
  puts "缺失:   kind=#{entry.kind} digest=#{entry.digest} 少 #{entry.count} 处"
end
