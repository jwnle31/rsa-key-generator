from tkinter import *
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import rabin_miller
import base64
import time
import binascii


def mod_inverse(a, x):
    m = pow(a, -1, x)
    return m


# Initializing Window
root = Tk()
root.title("RSA Key Generator")
root.config(bd=20, padx=15, pady=15, relief=GROOVE)
root.iconbitmap("room_key.ico")
root.resizable(width=False, height=False)

# Heading Elements
headingFrame = Frame(root, bd=5)
headingFrame.grid(column=0, row=0, columnspan=8)
headerLabel = Label(headingFrame, text="- RSA Key Generator -")
headerLabel.grid()
headerLabel.config(font=("Verdana", 24))

# Initializing Variables
p = q = n = phi = e = d = IntVar()
exeTime = StringVar()
public_key = private_key = None
message = ""
ciphertext = bytearray()
exeTime.set("Generated in n/a ms.")

# Setting Section
settingFrame = Frame(root, bd=5, padx=5, pady=5, relief=GROOVE)
settingFrame.grid(column=0, row=1, columnspan=2)

keyLabel = Label(settingFrame, font="Verdana", text="Key Size (bits):").grid(column=0, row=1, sticky=W)

# Key Size Dropdown Menu
keySel = IntVar()
keySel.set(1024)
keySizeOpt = OptionMenu(
    settingFrame, keySel,
    512, 1024, 2048, 4096
)

keySizeOpt.grid(column=1, row=1)
keySizeOpt.config(width=20, bg="#DCDCDC")

fmtLabel = Label(settingFrame, font="Verdana", text="Format Scheme:").grid(column=0, row=2, sticky=W)

# Format Dropdown Menu
fmtSel = StringVar()
fmtSel.set("Components (Base 16)")
fmtSchemeOpt = OptionMenu(
    settingFrame, fmtSel,
    "Components (Base 16)",
    "PKCS #1 (Base 64)",
    "PKCS #8 (Base 64)"
)

fmtSchemeOpt.grid(column=1, row=2)
fmtSchemeOpt.config(width=20, bg="#DCDCDC")


# Generates the keys
def show():
    key_size = keySel.get()
    fmt_scheme = fmtSel.get()

    global p, q, n, phi, e, d, public_key, private_key, exeTime

    start_time = time.process_time()

    p = rabin_miller.gen_large_prime(key_size // 2)
    q = rabin_miller.gen_large_prime(key_size // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)

    public_key = RSA.construct((n, e))
    private_key = RSA.construct((n, e, d))

    pubBox.configure(state="normal")
    priBox.configure(state="normal")
    pubBox.delete(1.0, END)
    priBox.delete(1.0, END)

    if fmt_scheme == "Components (Base 16)":
        pubBox.insert(1.0, "e:\n" + str(hex(e)[2:]) + "\n\n" + "n:\n" + str(hex(n)[2:]))
        priBox.insert(1.0, "p:\n" + str(hex(p)[2:]) + "\n\nq:\n" + str(hex(q)[2:]) + "\n\nd:\n" + str(hex(d)[2:]))
    elif fmt_scheme == "PKCS #1 (Base 64)":
        pubBox.insert(1.0, public_key.exportKey())
        priBox.insert(1.0, private_key.exportKey())
    elif fmt_scheme == "PKCS #8 (Base 64)":
        pubBox.insert(1.0, public_key.exportKey(pkcs=8))
        priBox.insert(1.0, private_key.exportKey(pkcs=8))

    end_time = time.process_time()

    pubBox.configure(state="disabled")
    priBox.configure(state="disabled")

    exeTime.set("Generated in " + str(round(1000 * (end_time - start_time))) + " ms.")


# "Generate" Button
genButtonFrame = Frame(root)
genButtonFrame.grid(column=0, row=2, columnspan=8, pady=15)
genButton = Button(genButtonFrame, text="Generate", width=15, height=2, command=show)
genButton.grid(row=0, padx=10, pady=(10, 0))
genButton.config(font=("Verdana", 12), bg="#DCDCDC")

timeLabel = Label(genButtonFrame)
timeLabel.grid(row=1)
timeLabel.config(font=("Verdana", 8), textvariable=exeTime)

pubKeyLabel = Label(root, text="Public Key:")
pubKeyLabel.grid(column=0, row=3, sticky=W, padx=5)
pubKeyLabel.config(font=("Verdana", 12))

priKeyLabel = Label(root, text="Private Key:")
priKeyLabel.grid(column=4, row=3, sticky=W, padx=5)
priKeyLabel.config(font=("Verdana", 12))


# Public Key Text Box
pubBox = Text(root, height=10)
pubText = "The public key will be generated here..."
pubBox.insert(1.0, pubText)
pubBox.configure(state="disabled")
pubBox.grid(column=0, row=4, columnspan=3, padx=5, pady=5)

pubScroll = Scrollbar(root)
pubScroll.config(command=pubBox.yview)
pubBox.config(yscrollcommand=pubScroll.set)
pubScroll.grid(column=3, row=4, sticky=N+S+W)

# Private Key Text Box
priBox = Text(root, height=10)
priText = "The private key will be generated here..."
priBox.insert(1.0, priText)
priBox.configure(state="disabled")
priBox.grid(column=4, row=4, columnspan=3, padx=5, pady=5)

priScroll = Scrollbar(root)
priScroll.config(command=priBox.yview)
priBox.config(yscrollcommand=priScroll.set)
priScroll.grid(column=7, row=4, sticky=N+S+W)


# Encrypts Messages
def enc_show():
    global encBox, ciphertext

    try:
        enc_input = str.encode(encBox.get(1.0, END))
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = base64.b64encode(cipher.encrypt(enc_input))

        encBox.delete(1.0, END)
        decBox.delete(1.0, END)
        decBox.insert(1.0, ciphertext)
    except AttributeError:
        if public_key is None:
            show()
        encBox.delete(1.0, END)
        decBox.delete(1.0, END)
        decBox.insert(1.0, "False")


# Decrypts Ciphertexts
def dec_show():
    global decBox, message

    try:
        dec_input = base64.b64decode(decBox.get(1.0, END))
        cipher = PKCS1_OAEP.new(private_key)
        message = cipher.decrypt(dec_input)

        decBox.delete(1.0, END)
        encBox.delete(1.0, END)
        encBox.insert(1.0, message)
    except (binascii.Error, ValueError):
        enc_show()
        encBox.delete(1.0, END)
        decBox.delete(1.0, END)
        encBox.insert(1.0, "Error: This is a default text!")


encFrame = Frame(root)
encFrame.grid(column=0, row=5, columnspan=3, pady=(10, 0), sticky=W)
encLabel = Label(encFrame, text="Message:")
encLabel.grid(column=0, row=0, padx=5)
encLabel.config(font=("Verdana", 12))
encButton = Button(encFrame, text="Encrypt", bg="#DCDCDC", command=enc_show).grid(column=1, row=0)

decFrame = Frame(root)
decFrame.grid(column=4, row=5, columnspan=3, pady=(10, 0), sticky=W)
decLabel = Label(decFrame, text="Ciphertext:")
decLabel.grid(column=0, row=0, padx=5)
decLabel.config(font=("Verdana", 12))
decButton = Button(decFrame, text="Decrypt", bg="#DCDCDC", command=dec_show).grid(column=1, row=0)

# Message Text Box
encBox = Text(root, height=10)
encText = "Enter a message to encrypt..."
encBox.insert(1.0, encText)
encBox.grid(column=0, row=6, columnspan=3, padx=5, pady=5)

encScroll = Scrollbar(root)
encScroll.config(command=encBox.yview)
encBox.config(yscrollcommand=encScroll.set)
encScroll.grid(column=3, row=6, sticky=N+S+W)

# Ciphertext Text Box
decBox = Text(root, height=10)
decText = "Enter a ciphertext to decrypt..."
decBox.insert(1.0, decText)
decBox.grid(column=4, row=6, columnspan=3, padx=5, pady=5)

decScroll = Scrollbar(root)
decScroll.config(command=decBox.yview)
decBox.config(yscrollcommand=decScroll.set)
decScroll.grid(column=7, row=6, sticky=N+S+W)

root.mainloop()
