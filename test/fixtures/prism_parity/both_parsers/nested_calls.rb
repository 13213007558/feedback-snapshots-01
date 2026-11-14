# SOURCE: params
# SINK: find - source flows through nested receiver/argument chain
User.find(params[:id]).posts.each { |post| post.audit! }
# SOURCE: params
# SINK: constantize - deep nesting with indexing and chaining
klass = params[:type].to_s.strip.constantize
# SOURCE: params
# SINK: where - nested call inside an interpolation argument
User.where("owner = #{params[:owner]}").first
