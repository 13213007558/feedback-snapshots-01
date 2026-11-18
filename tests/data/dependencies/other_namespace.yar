// Separate file => separate namespace. G_Platform here must be unresolved,
// and the global gate from security_ruleset.yar must not reach this rule.
rule Isolated_Detection
{
    condition:
        G_Platform and ext_var
}

global rule G_Platform
{
    condition:
        true
}

rule Isolated_Follower
{
    condition:
        Isolated_Detection
}
