#   python setup.py build
#   python setup.py bdist_msi
#   python setup.py bdist_dmg

from cx_Freeze import setup, Executable
import sys

app_title = "HashGen"
main_file = "HashGen.py"
base = None
if(sys.platform == "win32"):
    base = "Win32GUI"

includes = ["atexit"]
includefiles = ["icon.png"]

shortcut_table = [
    ("DesktopShortcut",        # Shortcut
     "DesktopFolder",          # Directory_
     "HashGen",                # Name
     "TARGETDIR",              # Component_
     "[TARGETDIR]HashGen.exe", # Target
     None,                     # Arguments
     None,                     # Description
     None,                     # Hotkey
     None,                     # Icon
     None,                     # IconIndex
     None,                     # ShowCmd
     'TARGETDIR'               # WkDir
     )
    ]
# Now create the table dictionary
msi_data = {"Shortcut": shortcut_table}

# Change some default MSI options and specify the use of the above defined tables
bdist_msi_options = {'data': msi_data}

setup(
        name = app_title,
        version = "1.2",
        description = "Hash Generator",
        author = "Rizal Muhammed",
        author_email = "risalmuhammed@gmail.com",
        options = {"bdist_msi" : bdist_msi_options ,"build_exe" : {"includes" : includes,"include_files": includefiles}},
        executables = [Executable(main_file, base = base, icon = "icon.ico")]
    )
