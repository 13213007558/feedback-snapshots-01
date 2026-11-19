# 基于 ROTP 的认证器轮换示例。
#
# 每个认证器版本处于三种状态之一：
#   pending  待确认：已生成秘密、等待用户用新秘密的口令完成确认
#   active   已启用：可用于普通登录，也可用于授权发起轮换
#   revoked  已撤销：终态，不可用于任何操作，且永远不能重新启用
#
# 审计日志只记录版本号与状态迁移，秘密与 provisioning URI 绝不落日志。

require 'rotp'

module RotationExample
  class RotationError < StandardError; end

  Version = Struct.new(:id, :secret, :state, :created_at, :state_changed_at)

  class AuditEntry
    attr_reader :at, :user, :version_id, :event, :detail

    def initialize(at:, user:, version_id:, event:, detail: nil)
      @at = at
      @user = user
      @version_id = version_id
      @event = event
      @detail = detail
    end

    def to_s
      base = format('t=%<at>4d user=%<user>s version=%<version>s event=%<event>s',
                    at: @at, user: @user, version: @version_id || '-', event: @event)
      @detail ? "#{base} (#{@detail})" : base
    end
  end

  class RotationService
    DRIFT_BEHIND = 30 # 容忍一个时间步的客户端时钟偏差

    attr_reader :audit_log

    def initialize(clock:)
      @clock = clock
      @audit_log = []
      @versions = Hash.new { |h, k| h[k] = [] }
      @sequences = Hash.new(0)
      @mutex = Mutex.new
    end

    # 初始注册（示例辅助）：直接建立一个已启用版本。
    def enroll(user)
      @mutex.synchronize do
        version = new_version(user, :active)
        @versions[user] << version
        audit(user, version.id, :enrolled, 'state=active')
        version.id
      end
    end

    # 发起轮换：必须用当前 active 版本的口令授权（旧版本的轮换授权权限）。
    # 返回 [version_id, provisioning_uri]；URI 只交给调用方展示二维码，绝不写日志。
    def begin_rotation(user, otp)
      @mutex.synchronize do
        active = active_version(user)
        raise RotationError, 'no active authenticator to authorize rotation' unless active

        unless totp(active).verify(otp, drift_behind: DRIFT_BEHIND, at: now)
          audit(user, active.id, :rotation_authorization_denied)
          raise RotationError, 'rotation authorization failed: bad OTP'
        end
        audit(user, active.id, :rotation_authorized)

        version = new_version(user, :pending)
        @versions[user] << version
        audit(user, version.id, :challenge_created, 'state=pending')
        [version.id, totp(version).provisioning_uri(user)]
      end
    end

    # 确认轮换：必须用待确认版本自己的秘密对应的口令验证。
    # 成功后该版本变为 active，其余所有版本（旧 active 与其他 pending）一律撤销。
    # 已撤销版本是终态：迟到的确认、重复提交都无法让它复活。
    def confirm_rotation(user, version_id, otp)
      @mutex.synchronize do
        version = find_version(user, version_id)
        raise RotationError, "unknown version #{version_id}" unless version

        unless version.state == :pending
          audit(user, version.id, :confirm_rejected, "state=#{version.state}")
          raise RotationError, "cannot confirm version #{version_id}: state=#{version.state}"
        end

        unless totp(version).verify(otp, drift_behind: DRIFT_BEHIND, at: now)
          audit(user, version.id, :confirm_rejected, 'bad_otp')
          raise RotationError, 'confirmation failed: bad OTP'
        end

        @versions[user].each do |other|
          transition(user, other, :revoked) unless other.equal?(version) || other.state == :revoked
        end
        transition(user, version, :active)
        version.id
      end
    end

    # 用户取消：仅 pending 可取消，进入终态 revoked。
    def cancel_rotation(user, version_id)
      @mutex.synchronize do
        version = find_version(user, version_id)
        raise RotationError, "unknown version #{version_id}" unless version

        unless version.state == :pending
          audit(user, version.id, :cancel_rejected, "state=#{version.state}")
          raise RotationError, "cannot cancel version #{version_id}: state=#{version.state}"
        end

        transition(user, version, :revoked)
        version.id
      end
    end

    # 普通登录：只有 active 版本的秘密能放行；pending/revoked 一律拒绝。
    def verify_login(user, otp)
      @mutex.synchronize do
        active = active_version(user)
        unless active
          audit(user, nil, :login_denied, 'no active version')
          return false
        end

        if totp(active).verify(otp, drift_behind: DRIFT_BEHIND, at: now)
          audit(user, active.id, :login_ok)
          true
        else
          audit(user, active.id, :login_denied)
          false
        end
      end
    end

    # 各版本当前能力快照（只含版本号与状态，供演示/调试输出）。
    def capabilities(user)
      @versions[user].map do |v|
        {
          id: v.id,
          state: v.state,
          can_login: v.state == :active,
          can_authorize_rotation: v.state == :active,
          can_confirm: v.state == :pending,
          terminal: v.state == :revoked
        }
      end
    end

    private

    def now
      @clock.call
    end

    def totp(version)
      ROTP::TOTP.new(version.secret)
    end

    def new_version(user, state)
      @sequences[user] += 1
      Version.new("v#{@sequences[user]}", ROTP::Base32.random_base32, state, now, now)
    end

    def find_version(user, version_id)
      @versions[user].find { |v| v.id == version_id }
    end

    def active_version(user)
      @versions[user].find { |v| v.state == :active }
    end

    def transition(user, version, to)
      from = version.state
      version.state = to
      version.state_changed_at = now
      audit(user, version.id, :transition, "#{from}->#{to}")
    end

    def audit(user, version_id, event, detail = nil)
      @audit_log << AuditEntry.new(at: now, user: user, version_id: version_id,
                                   event: event, detail: detail)
    end
  end
end
