rule webshell_aspx_sportsball : Webshell
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-01"
        description = "The SPORTSBALL webshell allows attackers to upload files or execute commands on the system."
        reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
        hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
        $uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE=" 

        $var1 = "Result.InnerText = string.Empty;"
        $var2 = "newcook.Expires = DateTime.Now.AddDays("
        $var3 = "System.Diagnostics.Process process = new System.Diagnostics.Process()"
        $var4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
        $var5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
        $var6 = "<input type=\"submit\" value=\"Upload\" />" 

    condition:
        any of ($uniq*) or
        all of ($var*)
}
