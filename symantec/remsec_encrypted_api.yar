rule remsec_encrypted_api
{
meta:
copyright = "Symantec"
strings:
$open_process =
/*
"OpenProcess
\
x00" in encrypted form
*/
{ 91 9A 8F B0 9C 90 8D AF 8C 8C 9A FF }
condition:
all of them
}