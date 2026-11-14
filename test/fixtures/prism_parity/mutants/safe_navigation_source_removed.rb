# MUTANT of both_parsers/safe_navigation.rb: SOURCE NODES DELIBERATELY REMOVED.
# Every params[:...] call below is replaced with a static literal, so the
# source-to-sink relationship no longer exists while every dangerous sink
# remains. The mutation test asserts the harness notices the missing params
# source, proving it can catch a false negative from a broken AST conversion.
input = "static"
eval("static")
"static"&.strip&.constantize
"static"&.public_send(:destroy)
input&.query("static")
