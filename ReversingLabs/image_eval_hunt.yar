rule image_eval_hunt
{
	meta:
     author = "ReversingLabs"
     reference = "https://blog.reversinglabs.com/blog/malware-in-images"
   strings:
      $png = {89 50 4E 47}
      $jpeg = {FF D8 FF}
      $gif = "GIF"
      $eval = "eval("
   condition:
      (($png at 0) or ($jpeg at 0) or ($gif at 0)) and $eval
}
