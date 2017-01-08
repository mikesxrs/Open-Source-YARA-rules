rule pbot_strings
{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-03-13"
        description = "Identify pBot"
    strings:
        $config = "var $config = array"
        $c = "class pBot"
    condition:
        all of them
}