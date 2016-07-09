// Copyright (C) 2013 Claudio "nex" Guarnieri

rule embedded_pe
{
    meta:
        author = "nex"
        description = "Contains an embedded PE32 file"

    strings:
        $a = "PE32"
        $b = "This program"
        $mz = { 4d 5a }
    condition:
        ($a and $b) and not ($mz at 0)
}