rule Pirate
{
	meta:
    	Author = "mikesxrs"
        Description = "Looking for unique strings"
        SHA256 = "7efa0ad7465d2fd051d44b4f4c9062bf204ebafbd27b7d068afbfb386e96c2d8"
        SHA256 = "8468f07f5bbc80b7608c848e582e5d23ab22282cc3eb5922dbb8df23cb33cdea"
    strings:
      	$STR1 = "Dim Pirates 'As String"
        $STR2 = "Pirates =\"Microsoft.\" + Pirates+"
        $SRT3 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)"
    condition:
        all of them
}
