# SOURCE: params
input = params[:entry]
# SINK: eval - direct params source inside a safe-navigation block body
eval(params[:entry])
# SINK: constantize - chained safe navigation keeps the params source inline
params[:name]&.strip&.constantize
# SINK: public_send - safe-nav receiver derived directly from params
params[:role]&.public_send(:destroy)
# SINK: query - safe navigation with params as an explicit argument
input&.query(params[:id])
