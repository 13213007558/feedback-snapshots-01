import "pe"
import "math"

rule valid_simple_contract
{
    condition:
        ext_integer > 10 and ext_string contains "safe" and ext_boolean == true
}

rule valid_module_mix
{
    condition:
        pe.is_dll and
        pe.number_of_sections >= ext_integer and
        pe.sections[0].name contains ext_string and
        math.means(0, filesize) > ext_integer
}

rule valid_true_false_branches
{
    condition:
        (ext_boolean and ext_integer > 0) or (not ext_boolean and ext_string startswith "a")
}

rule valid_nested_loops
{
    strings:
        $a = "alpha"
        $b = "beta"
    condition:
        for all section_index in (0 .. #a) : (
            for any offset in (1 .. 3) : (
                uint8(section_index + offset) > ext_integer and
                math.means(section_index, offset) >= ext_integer
            )
        )
}

rule valid_same_name_local_shadows_external
{
    condition:
        for any ext_integer in (1 .. 5) : ( ext_integer > 0 ) and ext_integer > 0
}

rule valid_string_quantifiers
{
    strings:
        $a = "alpha"
        $b = "beta"
    condition:
        any of them and all of ($a, $b) and 2 of ($a, $*) and
        for any of ($a, $b) : ( $ at filesize ) and #a > 0
}

rule invalid_string_compared_as_integer
{
    condition:
        ext_string > 5
}

rule invalid_integer_used_as_string
{
    condition:
        ext_integer contains "value"
}

rule invalid_boolean_used_in_arithmetic
{
    condition:
        ext_boolean + 1 > 0
}

rule invalid_undeclared_variable
{
    condition:
        ext_missing == 1
}

rule invalid_loop_local_type_misuse
{
    condition:
        for any index in (1 .. 3) : ( index contains "x" )
}

rule invalid_loop_local_leaves_scope
{
    condition:
        for any index in (1 .. 3) : ( index > 0 ) and index > 0
}
