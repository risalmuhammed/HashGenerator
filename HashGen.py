__author__ = 'Rizal'
from tkinter import *
from tkinter import filedialog, messagebox
from tkinter.ttk import Separator
from zlib import crc32, adler32
import hashlib as hlb
import os.path


class MyClass:
    def __init__(self, master):
        self.filename = ''
        # By default drop down menu will have Text mode
        self.list_choice = 'Text'

        self.label = Label(master, text="DATA:", fg="blue")
        self.label.grid(row=2, sticky=W, padx=5)

        self.entry = Entry(master, width="128")
        self.entry.grid(row=2, column=1, padx=5)
        # add mouse click event to the data entry field
        self.entry.bind('<Button-1>', self.clean_up)

        self.button = Button(master, text="Hashify!", command=self.calc_hash)
        self.button.grid(row=16, column=1, padx=5, pady=3)
        self.op_button = Button(master, text="Choose File", command=self.open_box)

        self.var = StringVar()
        self.lst = ["Text", "File"]  # , "HexString"]
        self.var.set(self.lst[0])
        self.drop_menu = OptionMenu(master, self.var, *self.lst, command=self.toggle_open_btn)
        self.drop_menu.grid(row=0, column=0, padx=5, sticky=W)

        self.sep1 = Separator(master, orient=HORIZONTAL)
        self.sep1.grid(row=1, sticky='we', columnspan=2, pady=5, padx=5)

        self.sep2 = Separator(master, orient=HORIZONTAL)
        self.sep2.grid(row=3, sticky='we', columnspan=2, pady=5, padx=5)

        self.l_md5 = Label(master, text="MD5:", fg="blue")
        self.l_sha1 = Label(master, text="SHA1:", fg="blue")
        self.l_sha224 = Label(master, text="SHA-224:", fg="blue")
        self.l_sha256 = Label(master, text="SHA-256:", fg="blue")
        self.l_sha384 = Label(master, text="SHA-384:", fg="blue")
        self.l_sha512 = Label(master, text="SHA-512:", fg="blue")
        self.l_ripemd = Label(master, text="RIPE-MD-160:", fg="blue")
        self.l_md4 = Label(master, text="MD4:", fg="blue")
        self.l_whirl = Label(master, text="WHIRLPOOL:", fg="blue")
        self.l_dsa = Label(master, text="DSA:", fg="blue")
        self.l_crc32 = Label(master, text="CRC-32:", fg="blue")
        self.l_adler32 = Label(master, text="ADLER-32:", fg="blue")

        self.entryMd5 = Entry(master, width="128")
        self.entryMd4 = Entry(master, width="128")
        self.entrySha1 = Entry(master, width="128")
        self.entrySha224 = Entry(master, width="128")
        self.entrySha256 = Entry(master, width="128")
        self.entrySha384 = Entry(master, width="128")
        self.entrySha512 = Entry(master, width="128")
        self.entryRipeMd = Entry(master, width="128")
        self.entryWhirl = Entry(master, width="128")
        self.entryDsa = Entry(master, width="128")
        self.entryCrc = Entry(master, width="128")
        self.entryAdler = Entry(master, width="128")

        self.l_md5.grid(row=4, sticky=W, padx=5)
        self.entryMd5.grid(row=4, column=1)

        self.l_sha1.grid(row=5, sticky=W, padx=5)
        self.entrySha1.grid(row=5, column=1)

        self.l_sha224.grid(row=6, sticky=W, padx=5)
        self.entrySha224.grid(row=6, column=1)

        self.l_sha256.grid(row=7, sticky=W, padx=5)
        self.entrySha256.grid(row=7, column=1)

        self.l_sha384.grid(row=8, sticky=W, padx=5)
        self.entrySha384.grid(row=8, column=1)

        self.l_sha512.grid(row=9, sticky=W, padx=5)
        self.entrySha512.grid(row=9, column=1)

        self.l_md4.grid(row=10, sticky=W, padx=5)
        self.entryMd4.grid(row=10, column=1)

        self.l_ripemd.grid(row=11, sticky=W, padx=5)
        self.entryRipeMd.grid(row=11, column=1)

        self.l_whirl.grid(row=12, sticky=W, padx=5)
        self.entryWhirl.grid(row=12, column=1)

        self.l_dsa.grid(row=13, sticky=W, padx=5)
        self.entryDsa.grid(row=13, column=1)

        self.l_crc32.grid(row=14, sticky=W, padx=5)
        self.entryCrc.grid(row=14, column=1)

        self.l_adler32.grid(row=15, sticky=W, padx=5)
        self.entryAdler.grid(row=15, column=1)

        # Disable all the Entry fields
        self.disable_entry()

    def clean_up(self, event):
        self.entry.delete(0, END)
        self.enable_entry()
        self.clear_fields()
        self.disable_entry()

        if self.filename != '':
            self.filename = ''

    def toggle_open_btn(self, val):
        # The method for cleanup
        self.clean_up(0)

        self.list_choice = val
        if val == "Text":
            self.op_button.grid_forget()
        if val == "File":
            self.op_button.grid(row=0, column=1, padx=5, pady=5, sticky=W)

    def open_box(self):
        self.clean_up(0)
        self.filename = filedialog.askopenfilename()
        self.entry.insert(0, self.filename)

    def calc_hash(self):

        if self.list_choice == "File":
            if os.path.isfile(self.filename):
                # read() from file as bytes
                txt = open(self.filename, 'rb').read()
            else:
                # No such file, warning
                self.filename = ''
                messagebox.showinfo('Error', 'File not found !\n' + self.entry.get())
                return
        elif self.list_choice == "Text":
            txt = self.entry.get().encode()

        self.enable_entry()
        self.clear_fields()
        print(self.list_choice)
        # algorithms_guaranteed
        self.entryMd5.insert(0, hlb.md5(txt).hexdigest())
        self.entrySha1.insert(0, hlb.sha1(txt).hexdigest())
        self.entrySha224.insert(0, hlb.sha224(txt).hexdigest())
        self.entrySha256.insert(0, hlb.sha256(txt).hexdigest())
        self.entrySha384.insert(0, hlb.sha384(txt).hexdigest())
        self.entrySha512.insert(0, hlb.sha512(txt).hexdigest())

        # algorithms_not_guaranteed
        # Collisions might occur

        # Using the same object initialized in __init__ method results in unsecured hashes.
        # So initialize objects each time
        self.init_insecure_hashes()

        # ripemd160
        self.ripe.update(txt)
        self.entryRipeMd.insert(0, self.ripe.hexdigest())
        # md4
        self.md4.update(txt)
        self.entryMd4.insert(0, self.md4.hexdigest())
        # whirlpool
        self.whirl.update(txt)
        self.entryWhirl.insert(0, self.whirl.hexdigest())
        # dsa
        self.dsa.update(txt)
        self.entryDsa.insert(0, self.dsa.hexdigest())

        # Starting from index 2 to get rid of the '0x'
        # crc32
        self.entryCrc.insert(0, (8 - len(hex(crc32(txt))[2:])) * '0' + hex(crc32(txt))[2:])
        # adler32
        self.entryAdler.insert(0, (8 - len(hex(adler32(txt))[2:])) * '0' + hex(adler32(txt))[2:])

        self.disable_entry()

    def clear_fields(self):
        self.entryMd5.delete(0, END)
        self.entrySha1.delete(0, END)
        self.entrySha224.delete(0, END)
        self.entrySha256.delete(0, END)
        self.entrySha384.delete(0, END)
        self.entrySha512.delete(0, END)
        self.entryRipeMd.delete(0, END)
        self.entryMd4.delete(0, END)
        self.entryWhirl.delete(0, END)
        self.entryDsa.delete(0, END)
        self.entryCrc.delete(0, END)
        self.entryAdler.delete(0, END)

    def init_insecure_hashes(self):
        self.ripe = hlb.new("ripemd160")
        self.md4 = hlb.new("md4")
        self.whirl = hlb.new("whirlpool")
        self.dsa = hlb.new("dsaEncryption")

    def disable_entry(self):
        self.entryMd5.config(state="readonly")
        self.entryMd4.config(state="readonly")
        self.entrySha1.config(state="readonly")
        self.entrySha224.config(state="readonly")
        self.entrySha256.config(state="readonly")
        self.entrySha384.config(state="readonly")
        self.entrySha512.config(state="readonly")
        self.entryRipeMd.config(state="readonly")
        self.entryWhirl.config(state="readonly")
        self.entryDsa.config(state="readonly")
        self.entryCrc.config(state="readonly")
        self.entryAdler.config(state="readonly")

    def enable_entry(self):
        self.entryMd5.config(state=NORMAL)
        self.entryMd4.config(state=NORMAL)
        self.entrySha1.config(state=NORMAL)
        self.entrySha224.config(state=NORMAL)
        self.entrySha256.config(state=NORMAL)
        self.entrySha384.config(state=NORMAL)
        self.entrySha512.config(state=NORMAL)
        self.entryRipeMd.config(state=NORMAL)
        self.entryWhirl.config(state=NORMAL)
        self.entryDsa.config(state=NORMAL)
        self.entryCrc.config(state=NORMAL)
        self.entryAdler.config(state=NORMAL)


mainWindow = Tk()
my = MyClass(mainWindow)
mainWindow.resizable(width=FALSE, height=FALSE)
mainWindow.title("HashGen")
mainWindow.mainloop()



