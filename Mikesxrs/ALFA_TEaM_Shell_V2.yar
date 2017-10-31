rule ALFA_TEaM_Shell_V2
{
	meta:
    	Author = "@X0RC1SM"
        Description = "Looking for ALFA TEaM Shell"
        Reference = "https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html"
        Date = "2017-10-28"
		
  strings:
		$STR1 = "Alfa Team Starter"
		$STR2 = "Alfa_Protect_Shell"
		$STR3 = "Alfa_Login_Page"
		$STR4 = "$Alfa_Pass = '"
		$STR5 = "Alfa_User = 'alfa'"
		$STR6 = "#Author Sole Sad & Invisible"
		$STR7 = "#solevisible@gmail.com"
		$STR8 = "#Copyright 2014-2016"
		
	condition:
		5 of them
}
