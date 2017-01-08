rule VertexNet
{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-03-25"
        description = "Identify VertexNet"
    strings:
        $s1 = "vertexnet" nocase
        $s2 = "urldl::"
        $s3 = "%LAPPDATA%"
        $s4 = "[ERROR] while loading ressource"
    condition:
        all of them
}