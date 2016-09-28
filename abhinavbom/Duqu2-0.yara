*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/

/* Certificate Matches for Patterns seen in Duqu 2.0 infection */

/* https://securelist.com/files/2015/06/The_Mystery_of_Duqu_2_0_a_sophisticated_cyberespionage_actor_returns.pdf */

import "pe"
rule honhaicert_goodcheck {
  strings:
    $honhai = "HON HAI"
  condition:
    $honhai and pe.version_info["LegalCopyright"] contains "Microsoft"
}



rule sysinternals_not_signed
{
strings:
       $sysinternals = "sysinternals" wide nocase
       $mz = "MZ"
       $url = "technet.microsoft.com" wide 
       $castuff = "Microsoft Code Signing PCA" wide

condition:
       $mz at 0 and $sysinternals and ( not $castuff and not $url)
}