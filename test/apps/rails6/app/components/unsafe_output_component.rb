# Confirmed renderable (defines render_in) but its template output is not
# inherently safe. Internal XSS must be caught by the XSS checks, not by the
# dynamic render path check.
class UnsafeOutputComponent
  def initialize(prop)
    @prop = prop
  end

  def render_in
    "<div>#{@prop}</div>"
  end
end
