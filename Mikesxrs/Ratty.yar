rule Ratty
{
	meta:
    	Author = "mikesxrs"
        Description = "Looking for unique code"
        Date = "2017-10-28"
        Reference1 = "https://github.com/shotskeber/Ratty/tree/master/Ratty/src/de/sogomn/rat"
        Reference2 = "https://www.first.org/resources/papers/conf2016/FIRST-2016-122.pdf"
        md5 = "6882e9a5973384e096bd41f210cddb54"
        md5 = "5159798395b2e0a91e28a457c935668b"
    strings:
    	$STR1 = "RattyClient.class"
        $STR2 = "sogomn/rat/"
        $STR3 = "RattyServer.class"
    condition:
        all of them
}
