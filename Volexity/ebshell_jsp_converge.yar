rule webshell_jsp_converge : Webshell
{
    meta:
        author = "threatintel@volexity.com"
        description = "File upload webshell observed in incident involving compromise of Confluence server."
        reference = "https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/"
        date = "2022-06-01"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        
    strings:
        $s1 = "if (request.getParameter(\"name\")!=null && request.getParameter(\"name\").length()!=0){" ascii

    condition:
        $s1
}
