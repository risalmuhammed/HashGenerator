__author__ = 'Rizal'
from tkinter import *
import hashlib as hlb
from zlib import crc32, adler32


class MyClass:
    def __init__(self, master):

        self.label = Label(master, text="Key:", fg="blue")
        self.label.grid(row=0)
        self.entry = Entry(master, width="128")
        self.entry.grid(row=0, column=1, padx=5)
        self.button = Button(master, text="Hashify!", fg="red", command=self.calc_hash)
        self.button.grid(row=13, column=1, padx=5, pady=3)

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

        self.l_md5.grid(row=1)
        self.entryMd5.grid(row=1, column=1)

        self.l_sha1.grid(row=2)
        self.entrySha1.grid(row=2, column=1)

        self.l_sha224.grid(row=3)
        self.entrySha224.grid(row=3, column=1)

        self.l_sha256.grid(row=4)
        self.entrySha256.grid(row=4, column=1)

        self.l_sha384.grid(row=5)
        self.entrySha384.grid(row=5, column=1)

        self.l_sha512.grid(row=6)
        self.entrySha512.grid(row=6, column=1)

        self.l_md4.grid(row=7)
        self.entryMd4.grid(row=7, column=1)

        self.l_ripemd.grid(row=8)
        self.entryRipeMd.grid(row=8, column=1)

        self.l_whirl.grid(row=9)
        self.entryWhirl.grid(row=9, column=1)

        self.l_dsa.grid(row=10)
        self.entryDsa.grid(row=10, column=1)

        self.l_crc32.grid(row=11)
        self.entryCrc.grid(row=11, column=1)

        self.l_adler32.grid(row=12)
        self.entryAdler.grid(row=12, column=1)

        # Disable all the Entry fields
        self.disable_entry()

    def calc_hash(self):
        self.enable_entry()
        self.clear_fields()
        txt = self.entry.get()

        # algorithms_guaranteed
        self.entryMd5.insert(0, hlb.md5(txt.encode()).hexdigest())
        self.entrySha1.insert(0, hlb.sha1(txt.encode()).hexdigest())
        self.entrySha224.insert(0, hlb.sha224(txt.encode()).hexdigest())
        self.entrySha256.insert(0, hlb.sha256(txt.encode()).hexdigest())
        self.entrySha384.insert(0, hlb.sha384(txt.encode()).hexdigest())
        self.entrySha512.insert(0, hlb.sha512(txt.encode()).hexdigest())

        # algorithms_not_guaranteed
        # Collisions might occur

        # Using the same object initialized in __init__ method results in unsecured hashes.
        # So initialize objects each time
        self.init_unsecure_hashes()

        # ripemd160
        self.ripe.update(txt.encode("utf-8"))
        self.entryRipeMd.insert(0, self.ripe.hexdigest())
        # md4
        self.md4.update(txt.encode("utf-8"))
        self.entryMd4.insert(0, self.md4.hexdigest())
        # whirlpool
        self.whirl.update(txt.encode("utf-8"))
        self.entryWhirl.insert(0, self.whirl.hexdigest())
        # dsa
        self.dsa.update(txt.encode("utf-8"))
        self.entryDsa.insert(0, self.dsa.hexdigest())

        # Staring from index 2 to get rid of the '0x'
        # crc32
        self.entryCrc.insert(0, hex(crc32(txt.encode("utf-8")))[2:])
        # adler32
        self.entryAdler.insert(0, hex(adler32(txt.encode("utf-8")))[2:])

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

    def init_unsecure_hashes(self):
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
mainWindow.title("HashCalc")
mainWindow.mainloop()



