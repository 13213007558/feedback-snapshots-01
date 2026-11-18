import "pe"

// G_Platform is mentioned in a comment: G_Platform must not create an edge.
global rule G_Platform
{
    condition:
        filesize < 100MB
}

global rule G_SupportedOS
{
    condition:
        os_ext == "windows"
}

private rule Priv_FileHeader
{
    strings:
        $mz = "MZ"
        // the literal "G_Platform" inside a string must not count as a reference
        $decoy = "G_Platform G_SupportedOS Priv_FileHeader"
    condition:
        $mz at 0 and #mz == 1
}

private rule Priv_PEAttributes
{
    condition:
        Priv_FileHeader and pe.imphash() != "" and pe.number_of_sections >= 1
}

rule Detection_Dropper
{
    strings:
        $drop = "dropper.exe"
    condition:
        Priv_PEAttributes and $drop and ext_var == 1
}

rule Detection_Generic
{
    // G_Platform here is only in this comment, not in the condition.
    condition:
        Priv_FileHeader or ext_var
}

rule Detection_Wildcard
{
    condition:
        Detection_* and os_ext != "linux"
}

rule Cycle_A
{
    condition:
        Cycle_B or true
}

rule Cycle_B
{
    condition:
        Cycle_A
}

rule Uses_External_Only
{
    condition:
        ext_var defined and os_ext == "windows"
}
