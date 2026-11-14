# SOURCE: params
name = params[:name]
# SINK: eval - interpolated source inside dstr/evstr
eval("user=#{name}")
# SINK: query - nested interpolation must preserve evstr nesting
query("a=#{"b=#{name}"}")
# SINK: render - interpolation built through a local alias
label = "hello #{name}"
render(plain: label)
