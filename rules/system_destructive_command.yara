rule System_Destruction_Commands {
    meta:
        score = 5
        description = "Commands used to delete backups or disable recovery"
    strings:
        $c1 = "vssadmin delete shadows" ascii
        $c2 = "bcdedit /set" ascii
        $c3 = "wbadmin delete catalog" ascii
        $c4 = "schtasks /delete" ascii
    condition:
        any of them
}
