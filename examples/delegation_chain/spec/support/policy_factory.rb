# frozen_string_literal: true

module Support
  module PolicyFactory
    AUDIENCE = 'api:orders'

    def audience
      AUDIENCE
    end

    def build_policy(**overrides)
      defaults = {
        max_depth: 3,
        cross_tenant_allowed: false,
        tenants: {
          'user' => 't-a', 'gw' => 't-a', 'billing' => 't-a',
          'shipping' => 't-a', 'attacker' => 't-b'
        },
        allowed_edges: [
          %w[user gw],
          %w[gw billing],
          %w[billing shipping],
          %w[gw shipping]
        ],
        audience_subjects: {
          AUDIENCE => %w[user gw billing shipping]
        }
      }
      ActChain::Policy.new(**defaults.merge(overrides))
    end
  end
end
