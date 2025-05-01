rule Cloaked_Files {
meta: 
    score = 2
   condition:
      (extension == ".jpg" or extension == ".jpeg" or extension == ".pdf") and
      (filetype == "EXE" or filetype == "Python")
}