rule Pony_gate_php_POST
{
    meta:
        description = "Possible Pony Sample POST to gate php"
        author = "Brian Carter"
        last_modified = "June 14, 2016"
        
    condition:
        cuckoo.network.http_post(/gate\.php/)
        and file_type contains "pe"
        and positives > 5
        and new_file
        
}
