# frozen_string_literal: true
#
# 演示：把“已审核”的 XML 子树插入另一份文档时保持命名空间身份。
# 源文档与目标文档把相同前缀 sec 绑定到不同 URI；若直接搬节点，
# sec:* 元素/属性会在新上下文里被重新解释，审核过的安全元素就变成另一种元素。
#
# 做法：深拷贝子树，把子树根在源文档里可见的命名空间绑定显式固定（pin）
# 到拷贝根上（只补插入点上下文里不一致的绑定），再插入目标文档。
# 不修改目标文档的任何既有节点。
#
# 运行：ruby -Ilib ns_safe_insert_demo.rb

require "rexml/document"

SEC_V1 = "http://sec.example/v1"      # 审核时 sec 绑定的 URI
SEC_V9 = "http://sec.example/v9"      # 目标文档里同一前缀 sec 绑定的另一个 URI
CORE   = "http://review.example/core" # 审核子树内的默认命名空间
META   = "http://meta.example/ns"     # 声明在审核子树祖先上的前缀
INNER  = "http://sec.example/v1-inner" # 子树内部对 sec 的遮蔽（shadowing）

# 源文档：sec:policy 子树是“已审核”的部分
SRC_XML = <<~XML
  <review-log xmlns:sec="#{SEC_V1}" xmlns:meta="#{META}">
    <sec:policy sec:action="allow" data-review-id="R-1" xmlns="#{CORE}">
      <rule effect="permit">read</rule>
      <meta:note meta:level="strict">audited</meta:note>
      <sec:override xmlns:sec="#{INNER}" sec:mode="log"/>
    </sec:policy>
  </review-log>
XML

# 目标文档：同样的前缀 sec 绑定到不同的 URI，且有自己的默认命名空间和既有声明
DST_XML = <<~XML
  <envelope xmlns:sec="#{SEC_V9}"
            xmlns:audit="http://audit.example/ns"
            xmlns="http://target.example/default">
    <sec:instrument sec:knob="gain">7</sec:instrument>
    <audit:trail audit:seq="42"/>
    <payload>untouched</payload>
    <slot/>
  </envelope>
XML

# ---------- 工具 ----------

def xname(el) = "{#{el.namespace}}#{el.name}" # 扩展名 {URI}local

def semantic_attrs(el)
  attrs = []
  el.attributes.each_attribute do |a|
    next if a.namespace_declaration? # xmlns 声明是语法，不参与语义核对
    name = a.prefix.empty? ? a.name : "{#{a.namespace}}#{a.name}"
    attrs << "#{name}=#{a.value}"
  end
  attrs.sort
end

# 按文档顺序收集 [扩展名, 属性列表]
def snapshot(el, acc = [])
  acc << [xname(el), semantic_attrs(el)]
  el.elements.each { |c| snapshot(c, acc) }
  acc
end

def snapshot_skip(el, skip_root, acc = [])
  return acc if el.equal?(skip_root)
  acc << [xname(el), semantic_attrs(el)]
  el.elements.each { |c| snapshot_skip(c, skip_root, acc) }
  acc
end

def serialize(doc)
  s = +""
  doc.write(output: s, indent: 2)
  s
end

# 关键步骤：把 in_scope（子树根在源文档中可见的全部绑定）固定到拷贝根上。
# - 拷贝根自己已声明的（含内部遮蔽所需的声明）不重复添加；
# - 插入点上下文里绑定一致的无需重复声明；
# - 只在新插入子树的根上加 xmlns 属性，目标文档其他节点一概不碰。
def pin_namespaces(copy_root, in_scope, insertion_parent)
  in_scope.each do |prefix, uri|
    next if prefix == "xml" # xml 前缀由规范隐式绑定
    decl = prefix == "xmlns" ? "xmlns" : "xmlns:#{prefix}"
    next if copy_root.attributes.get_attribute(decl)
    current = insertion_parent.namespace(prefix == "xmlns" ? "" : prefix)
    next if current == uri
    copy_root.add_attribute(decl, uri)
  end
end

$failures = 0
def check(ok, label)
  puts "  #{ok ? '✓' : '✗'} #{label}"
  $failures += 1 unless ok
  ok
end

# ---------- 输入 ----------

puts "=" * 72
puts "源文档（sec => #{SEC_V1}）："
puts SRC_XML
puts "目标文档（sec => #{SEC_V9}，插入前）："
puts DST_XML

src = REXML::Document.new(SRC_XML)
reviewed = src.root.elements["sec:policy"]
in_scope = reviewed.namespaces # 必须在脱离源文档之前捕获
before_reviewed = snapshot(reviewed)

# ---------- 反面示例：不固定命名空间直接搬 ----------

puts "=" * 72
puts "反面示例：直接 deep_clone + 插入（不固定命名空间）"
dst_bad = REXML::Document.new(DST_XML)
dst_bad.root.elements["slot"].add_element(reviewed.deep_clone)
# REXML 动态解析命名空间：在活树上即可看到被重新绑定的扩展名
moved = dst_bad.root.elements["slot"].elements.to_a.find { |e| e.attributes["data-review-id"] }
after_bad = snapshot(moved)
mutated = 0
before_reviewed.zip(after_bad).each do |(bx, ba), (ax, aa)|
  same = (bx == ax && ba == aa)
  mutated += 1 unless same
  puts "  #{same ? '  不变' : '→ 变异'} #{bx} #{ba.inspect}  =>  #{ax} #{aa.inspect}"
end
check(mutated.positive?, "朴素搬运确实改变了扩展名（反面示例成立）")
puts "  ↑ sec:* 被重新绑定到 #{SEC_V9}，meta: 前缀失去绑定——审核元素已变成另一种元素"
begin
  REXML::Document.new(serialize(dst_bad)) # 序列化后重新解析
  check(false, "重新解析朴素搬运的输出")
rescue REXML::UndefinedNamespaceException => e
  check(true, "重新解析朴素搬运的输出直接报错：#{e.message}")
end

# ---------- 正确做法：固定命名空间后再插入 ----------

puts "=" * 72
puts "正确做法：深拷贝 + pin_namespaces + 插入"
dst = REXML::Document.new(DST_XML)
target_before = snapshot(dst.root) # 目标既有节点快照
slot = dst.root.elements["slot"]

copy = reviewed.deep_clone
pin_namespaces(copy, in_scope, slot)
slot.add_element(copy)

out = serialize(dst)
puts "插入后目标文档（序列化输出）："
puts out

# ---------- 核对：重新解析输出，逐个节点验证 ----------

puts "=" * 72
puts "核对 1：重新解析输出，已审核节点的扩展名与属性值逐一比对"
reparsed = REXML::Document.new(out)
inserted = reparsed.root.elements["slot"].elements.to_a.find { |e| e.attributes["data-review-id"] }
after_reviewed = snapshot(inserted)
check(before_reviewed.size == after_reviewed.size,
      "节点数一致（#{before_reviewed.size}）")
before_reviewed.zip(after_reviewed).each do |(bx, ba), (ax, aa)|
  check(bx == ax && ba == aa, "#{ax}  attrs=#{aa.inspect}")
end

puts "核对 2：目标文档既有节点未被改写"
target_after = snapshot_skip(reparsed.root, inserted)
check(target_before.size == target_after.size,
      "既有节点数一致（#{target_before.size}）")
target_before.zip(target_after).each do |(bx, ba), (ax, aa)|
  check(bx == ax && ba == aa, "#{ax}  attrs=#{aa.inspect}")
end

puts "=" * 72
if $failures.zero?
  puts "全部通过：已审核子树命名空间身份保持，目标其余节点未受影响。"
else
  puts "失败 #{$failures} 项"
  exit 1
end
