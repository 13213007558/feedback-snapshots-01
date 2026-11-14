# Single file again, but the final assignment switches the global default back
# to :object mode, overriding the earlier safe settings.
Oj.mimic_JSON                                   # safe, but overwritten below
Oj.default_options = { mode: :strict }          # safe, but overwritten below
Oj.default_options = { mode: :object }          # effective default: object mode (unsafe)
