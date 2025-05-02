rule Base64_Overflow {
    meta:
        score = 4
        description = "Large Base64 strings possibly hiding keys or payloads"
    strings:
        $b64_string = /[A-Za-z0-9+\/=]{100,}/ ascii
    condition:
        $b64_string
}
