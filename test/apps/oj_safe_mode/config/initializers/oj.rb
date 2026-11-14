# All Oj default changes live in this one file, so line order is knowable.
# The last assignment is the effective global default.
Oj.mimic_JSON                                   # JSON-compatible default (safe)
Oj.default_options = { mode: :strict }          # strict mode (safe) and the final assignment
