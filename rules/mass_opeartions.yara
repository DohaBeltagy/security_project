rule Mass_File_Operations {
    meta:
        score = 3
    strings:
        // Common file extensions targeted by ransomware
        $ext1 = ".encrypted" wide ascii
        $ext2 = ".locked" wide ascii
        $ext3 = ".crypt" wide ascii
        $ext4 = ".key" wide ascii
        $vault = "vault" wide ascii
        $secret = "secret.key" wide ascii

        // File traversal patterns 
        $traversal1 = "/home/" wide ascii
        $traversal2 = "C:\\Users\\" wide ascii
    condition:
        any of ($ext*) or any of ($traversal*)
}