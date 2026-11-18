// Small ruleset for read-only module access auditing.
// Covers allowed members, same-name strings and regexes, forbidden members,
// dynamic indexing and unused imports. Line numbers are asserted in tests.

import "pe"
import "hash"

rule allowed_pe_fields
{
    condition:
        pe.number_of_sections == 1 and pe.exports("CPlApplet")
}

rule same_name_string_is_not_module_access
{
    strings:
        $pe = "pe.number_of_sections appears inside a text string"
        $rx = /pe.forbidden_member/
    condition:
        $pe and $rx
}

rule forbidden_pe_member
{
    condition:
        pe.forbidden_member == true
}

rule dynamic_index_is_indeterminate
{
    condition:
        for any i in (0..pe.number_of_sections - 1) :
            ( pe.sections[i].characteristics & pe.DLL )
}

rule static_index_nested_member
{
    condition:
        pe.sections[0].name == ".text"
}

rule exempted_forbidden_member
{
    condition:
        pe.forbidden_member == false
}

rule hash_import_never_used
{
    condition:
        pe.DLL
}
