# 运行：ruby examples/rotation/demo.rb
#
# 用内存存储 + 可推进时钟走完以下序列，并逐步打印每个版本的能力：
#   1. 成功轮换：旧版本授权 -> 新版本确认 -> 旧版本撤销
#   2. 双浏览器并行轮换 + 较早挑战迟到 + 确认后重复提交
#   3. 用户取消后，迟到的确认无法复活已撤销版本
# 输出只含版本号与状态；二维码 URI 与秘密一律以 [redacted] 表示。

$LOAD_PATH.unshift File.expand_path('../../lib', __dir__)
require_relative 'authenticator_rotation'

# ---- 可推进时钟 ------------------------------------------------------------
$t = 1_700_000_000
def advance(seconds = 30)
  $t += seconds
end
CLOCK = -> { $t }

SERVICE = RotationExample::RotationService.new(clock: CLOCK)
USER = 'alice'

# ---- 输出辅助 ---------------------------------------------------------------
def banner(title)
  puts
  puts '=' * 72
  puts title
  puts '=' * 72
end

def show_capabilities(step)
  puts "  [#{step}] t=#{$t} 版本能力快照（login=普通登录, rotate=授权轮换, confirm=确认）"
  SERVICE.capabilities(USER).each do |c|
    puts format('    %-4s state=%-8s login=%-5s rotate=%-5s confirm=%-5s terminal=%s',
                c[:id], c[:state], c[:can_login], c[:can_authorize_rotation],
                c[:can_confirm], c[:terminal])
  end
end

def check(desc)
  result = yield
  raise "断言失败: #{desc}" unless result
  puts "    ✓ #{desc}"
end

def expect_rotation_error(desc)
  yield
  raise "断言失败: #{desc}（未抛出 RotationError）"
rescue RotationExample::RotationError => e
  puts "    ✓ #{desc}（拒绝: #{e.message}）"
end

# 演示侧持有秘密（模拟用户认证器 App），服务端能力快照与日志均不接触它。
SECRETS = {}
def otp_for(version_id)
  ROTP::TOTP.new(SECRETS.fetch(version_id)).at($t)
end

def capture_secret(user, version_id)
  # 示例内部读取秘密仅供演示端生成口令；真实系统里秘密只在注册响应中出现一次。
  SERVICE.instance_variable_get(:@versions)[user].find { |v| v.id == version_id }.secret
end

# ---- 场景 1：成功轮换 -------------------------------------------------------
banner '场景 1：成功轮换（旧版本授权，新版本确认后顶替）'

v1 = SERVICE.enroll(USER)
SECRETS[v1] = capture_secret(USER, v1)
show_capabilities('初始注册')

advance
v2, uri = SERVICE.begin_rotation(USER, otp_for(v1))
SECRETS[v2] = capture_secret(USER, v2)
puts "  浏览器收到 provisioning URI: [redacted]（#{uri.start_with?('otpauth://') ? '已生成' : '异常'}，不写入日志）"
show_capabilities('v1 授权后创建待确认版本 v2')

advance
SERVICE.confirm_rotation(USER, v2, otp_for(v2))
show_capabilities('v2 用新秘密口令完成确认')

advance
check('v2 可登录') { SERVICE.verify_login(USER, otp_for(v2)) }
advance
check('v1 已撤销，不能登录') { SERVICE.verify_login(USER, otp_for(v1)) == false }
advance
expect_rotation_error('v1 已撤销，不能再授权轮换') { SERVICE.begin_rotation(USER, otp_for(v1)) }

# ---- 场景 2：双浏览器并行 + 迟到挑战 + 重复提交 ------------------------------
banner '场景 2：两个浏览器并行轮换，先确认者胜，迟到挑战不得复活'

advance
v3, _uri_a = SERVICE.begin_rotation(USER, otp_for(v2)) # 浏览器 A
SECRETS[v3] = capture_secret(USER, v3)
advance
v4, _uri_b = SERVICE.begin_rotation(USER, otp_for(v2)) # 浏览器 B
SECRETS[v4] = capture_secret(USER, v4)
show_capabilities('A、B 各自拿到待确认挑战 v3、v4')

advance
SERVICE.confirm_rotation(USER, v4, otp_for(v4)) # B 先完成确认
show_capabilities('B 的 v4 先确认：v2、v3 被撤销')

advance
expect_rotation_error('A 迟到的 v3 确认被拒绝（v3 已撤销，终态）') do
  SERVICE.confirm_rotation(USER, v3, otp_for(v3))
end
expect_rotation_error('对 v4 重复提交确认被拒绝（已非 pending）') do
  SERVICE.confirm_rotation(USER, v4, otp_for(v4))
end
show_capabilities('迟到确认与重复提交之后（无任何状态变化）')

advance
check('v4 可登录') { SERVICE.verify_login(USER, otp_for(v4)) }
advance
check('v3 不能登录') { SERVICE.verify_login(USER, otp_for(v3)) == false }

# ---- 场景 3：用户取消 -------------------------------------------------------
banner '场景 3：用户取消待确认版本，之后任何确认都无法复活它'

advance
v5, _uri = SERVICE.begin_rotation(USER, otp_for(v4))
SECRETS[v5] = capture_secret(USER, v5)
show_capabilities('创建待确认版本 v5')

advance
SERVICE.cancel_rotation(USER, v5)
show_capabilities('用户取消 v5')

advance
expect_rotation_error('取消后用正确口令确认 v5 仍被拒绝') do
  SERVICE.confirm_rotation(USER, v5, otp_for(v5))
end
advance
check('v5 不能登录') { SERVICE.verify_login(USER, otp_for(v5)) == false }
check('v4 仍是唯一可登录版本') { SERVICE.verify_login(USER, otp_for(v4)) }

# ---- 审计日志 ---------------------------------------------------------------
banner '审计日志（只含版本号与状态迁移，无秘密、无 URI）'
SERVICE.audit_log.each { |entry| puts "  #{entry}" }

leaks = SERVICE.audit_log.map(&:to_s).join("\n")
SECRETS.each_value do |secret|
  raise '审计日志泄露了秘密！' if leaks.include?(secret)
end
raise '审计日志泄露了 provisioning URI！' if leaks.include?('otpauth://')
puts
puts '✓ 审计日志不含任何秘密或 provisioning URI'
puts '✓ 全部场景与断言通过'
