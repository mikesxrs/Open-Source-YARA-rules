rule XYPayload : Payload
{
    meta:
        description = "Identifier for payloads using XXXXYYYY/YYYYXXXX markers"
        author = "Seth Hardy"
        last_modified = "2014-05-05"
        
    strings:
        $start_marker = "XXXXYYYY"
        $end_marker = "YYYYXXXX"
    
    condition:
        $start_marker and $end_marker
}