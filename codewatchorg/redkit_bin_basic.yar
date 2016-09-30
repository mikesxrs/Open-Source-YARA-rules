rule redkit_bin_basic : exploit_kit
{
    strings:
        $a = /\/\d{2}.html\s/
    condition:
        $a
}