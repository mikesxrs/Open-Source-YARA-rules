rule generic_jsp
{
    meta:
        description = "Generic JSP"
        family = "JSP Backdoor"
        filetype = "JSP"
        hash = "6517e4c8f19243298949711b48ae2eb0b6c764235534ab29603288bc5fa2e158"

    strings:
        $exec = /Runtime.getRuntime\(\).exec\(request.getParameter\(\"[a-zA-Z0-9]+\"\)\);/ ascii

    condition:
        all of them
}
