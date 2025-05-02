rule Ransom_Note {
    meta:
        score = 30
    strings:
        // Common phrases in ransom notes
        $note1 = "Your files have been encrypted" wide ascii
        $note2 = "Send payment to" wide ascii
        $note3 = "Decryption key" wide ascii
        $note4 = "Contact this email" wide ascii
        $note5 = "You are hacked" wide ascii
        $note6 = "Bitcoin" wide ascii
        $note7 = "Pay" wide ascii
        $note8 = "Ransom" wide ascii
        $note9 = "Decrypt" wide ascii
        $note10 = "Recover your files" wide ascii
    condition:
        any of them
}