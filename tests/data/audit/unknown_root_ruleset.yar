rule allowlisted_module_without_import
{
    condition:
        pe.machine == 332
}

rule unknown_module_root
{
    condition:
        mystery.thing == 1
}
