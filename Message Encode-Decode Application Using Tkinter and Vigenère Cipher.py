from tkinter import *
import random
import time
import base64

# Global Color and Font Scheme
BG_COLOR = "#2d2d2d"  # Dark background color
BTN_COLOR = "#3498db"  # Blue button color
BTN_RESET = "#27ae60"  # Green reset button color
BTN_EXIT = "#e74c3c"  # Red exit button color
TXT_COLOR = "#ecf0f1"  # Light text color
ENTRY_BG = "#34495e"  # Darker background for entry fields
FONT = ('Helvetica', 14)

# Login function
def check_login():
    username = entry_username.get()
    password = entry_password.get()
    if username == "admin" and password == "password":  # Set your credentials here
        login_window.destroy()  # Close login window on success
        show_encryption_window()  # Open the encryption window
    else:
        lbl_login_error.config(text="Invalid credentials, try again!", fg="red")

# Show the encryption window after login
def show_encryption_window():
    root = Tk()
    root.geometry("800x600")
    root.title("Message Encryption and Decryption")
    root.configure(bg=BG_COLOR)

    # Center the entire content frame using pack with expand
    content_frame = Frame(root, bg=BG_COLOR)
    content_frame.pack(expand=True, fill=BOTH)

    # Top Frame for Title and Time
    header_frame = Frame(content_frame, bg=BG_COLOR)
    header_frame.pack(side=TOP, pady=20)

    # Title and time centered using pack
    lblInfo = Label(header_frame, font=('Helvetica', 28, 'bold'),
                    text="Secret Messaging\nVigenère Cipher",
                    fg=TXT_COLOR, bg=BG_COLOR)
    lblInfo.pack(pady=10)

    localtime = time.asctime(time.localtime(time.time()))
    lblTime = Label(header_frame, font=('Helvetica', 12),
                    text=localtime, fg=TXT_COLOR, bg=BG_COLOR)
    lblTime.pack()

    # Frame for input fields and buttons, centered
    f1 = Frame(content_frame, bg=BG_COLOR)
    f1.pack(side=TOP, pady=20)

    # Variables
    Msg = StringVar()
    key = StringVar()
    mode = StringVar()
    Result = StringVar()

    # Functions
    def qExit():
        root.destroy()

    def Reset():
        Msg.set("")
        key.set("")
        mode.set("")
        Result.set("")

    # Vigenère cipher functions
    def encode(key, clear):
        enc = []
        for i in range(len(clear)):
            key_c = key[i % len(key)]
            enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
            enc.append(enc_c)
        return base64.urlsafe_b64encode("".join(enc).encode()).decode()

    def decode(key, enc):
        dec = []
        enc = base64.urlsafe_b64decode(enc).decode()
        for i in range(len(enc)):
            key_c = key[i % len(key)]
            dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
            dec.append(dec_c)
        return "".join(dec)

    def Ref():
        clear = Msg.get()
        k = key.get()
        m = mode.get()
        if m == 'e':
            Result.set(encode(k, clear))
        else:
            Result.set(decode(k, clear))

    # Labels and Text Fields
    lblMsg = Label(f1, text="Message", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
    lblMsg.grid(row=1, column=0, padx=10, pady=10, sticky=E)

    txtMsg = Entry(f1, font=FONT, textvariable=Msg, bd=5, width=40, bg=ENTRY_BG, fg=TXT_COLOR)
    txtMsg.grid(row=1, column=1, padx=10, pady=10)

    lblkey = Label(f1, text="Key", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
    lblkey.grid(row=2, column=0, padx=10, pady=10, sticky=E)

    txtkey = Entry(f1, font=FONT, textvariable=key, bd=5, width=40, bg=ENTRY_BG, fg=TXT_COLOR)
    txtkey.grid(row=2, column=1, padx=10, pady=10)

    lblmode = Label(f1, text="Mode (e for encrypt, d for decrypt)", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
    lblmode.grid(row=3, column=0, padx=10, pady=10, sticky=E)

    txtmode = Entry(f1, font=FONT, textvariable=mode, bd=5, width=40, bg=ENTRY_BG, fg=TXT_COLOR)
    txtmode.grid(row=3, column=1, padx=10, pady=10)

    lblService = Label(f1, text="Result", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
    lblService.grid(row=4, column=0, padx=10, pady=10, sticky=E)

    txtService = Entry(f1, font=FONT, textvariable=Result, bd=5, width=40, bg=ENTRY_BG, fg=TXT_COLOR)
    txtService.grid(row=4, column=1, padx=10, pady=10)

    # Buttons centered
    button_frame = Frame(content_frame, bg=BG_COLOR)
    button_frame.pack(side=TOP, pady=20)

    btnShow = Button(button_frame, text="Show Message", padx=10, pady=5, bd=5, fg="white", bg=BTN_COLOR,
                     font=('Helvetica', 12, 'bold'), command=Ref)
    btnShow.grid(row=0, column=0, padx=10)

    btnReset = Button(button_frame, text="Reset", padx=10, pady=5, bd=5, fg="white", bg=BTN_RESET,
                      font=('Helvetica', 12, 'bold'), command=Reset)
    btnReset.grid(row=0, column=1, padx=10)

    btnExit = Button(button_frame, text="Exit", padx=10, pady=5, bd=5, fg="white", bg=BTN_EXIT,
                     font=('Helvetica', 12, 'bold'), command=qExit)
    btnExit.grid(row=0, column=2, padx=10)

    # Keeps window alive
    root.mainloop()

# Create login window
login_window = Tk()
login_window.geometry("400x300")
login_window.title("Login")
login_window.configure(bg=BG_COLOR)

# Username and Password fields
lbl_username = Label(login_window, text="Username", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
lbl_username.pack(pady=10)

entry_username = Entry(login_window, font=FONT, bg=ENTRY_BG, fg=TXT_COLOR, bd=5)
entry_username.pack(pady=5)

lbl_password = Label(login_window, text="Password", font=FONT, bg=BG_COLOR, fg=TXT_COLOR)
lbl_password.pack(pady=10)

entry_password = Entry(login_window, font=FONT, bg=ENTRY_BG, fg=TXT_COLOR, bd=5, show="*")
entry_password.pack(pady=5)

# Error label
lbl_login_error = Label(login_window, text="", font=('Helvetica', 12), fg="red", bg=BG_COLOR)
lbl_login_error.pack(pady=5)

# Login button
btn_login = Button(login_window, text="Login", font=('Helvetica', 12, 'bold'), bg=BTN_COLOR, fg="white", bd=5, command=check_login)
btn_login.pack(pady=20)

# Keeps window alive
login_window.mainloop()
