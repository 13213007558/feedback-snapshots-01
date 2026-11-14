def relay(...)
  # SINK: query - forward_args node must survive both AST conversions
  query(...)
end
# SOURCE: params
# SINK: relay - params explicitly forwarded into relay at the call site
relay(params[:q])
# SINK: eval - keyword argument forwarding preserves the kwarg node
def evaluate(code:)
  eval(code)
end
# SOURCE: params - explicit kwargs keep the source adjacent to the call
evaluate(code: params[:code])
# SINK: eval - direct params sink alongside the forwarding variants
eval(params[:inline])
