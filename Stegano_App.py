from tkinter import *
from tkinter import filedialog, simpledialog, messagebox
import tkinter as tk 
from tkinter import ttk
from PIL import Image, ImageTk
import os 
import base64
import secrets
from stegano import lsb
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

root = Tk()
root.title("Steganography - Hide a Secret Text Message in an Image")
root.geometry("700x500+150+180")
root.resizable(False,False)
root.configure(bg = "#2f4155")

# Create a key for encryption 
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Create a key derivation function (KDF) for password hashing 
def derive_key(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    
    password_provided = password
    password = password_provided.encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,   # Adjust this according to your security needs 
        salt=salt,
        length=32    # This is the length of the derived key
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key, salt

# Updated encrypt function
def encrypt(message, password):
    key, salt = derive_key(password)
    cipher_suite = Fernet(key)
    encrypted_message = cipher_suite.encrypt(salt + message.encode())
    return encrypted_message, salt

# Updated decrypt function
def decrypt(encrypted_message, password, salt):
    derived_key = derive_key(password, salt)[0]
    cipher_suite = Fernet(derived_key)
    
    try:
        decrypted_message_bytes = cipher_suite.decrypt(encrypted_message)
        return decrypted_message_bytes
    except InvalidToken:
        print("Invalid token - decryption failed.")
        return None

def save_key(filename, key):
    with open(filename, 'wb') as file:
        file.write(key.encode())

def read_key(filename):
    with open(filename, 'rb') as file:
        return file.read().decode()
    
# Updated save_to_file function
def save_to_file(data, filename):
    with open(filename, 'wb') as file:
        file.write(data)

# Updated read_from_file function
def read_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()
    
def save_salt(filename, salt):
    with open(filename, 'wb') as file:
        file.write(base64.urlsafe_b64encode(salt))

def read_salt(filename):
    with open(filename, 'rb') as file:
        return base64.urlsafe_b64decode(file.read())
    
#icon
image_icon = PhotoImage(file = "logo.png")
root.iconphoto(False,image_icon)

#logo
#logo = PhotoImage(file = "label1.png")
#Label(root,image = logo, bg = "#2f4155").place(x = 25, y = 15)

# Home Page
def home_page():
    page = Frame(root, bg="#2f4155")
    page.place(x=0, y=0, relwidth=1, relheight=1)

    # Title
    label = Label(page, text="Welcome to the Steganography App", bg="#2f4155", fg="white", font="arial 20 bold")
    label.pack(pady=20)      

    # Instructions
    instructions = Label(page, text="This app allows you to hide and reveal secret messages in images. \n The purpose of this application is safely encode and decode the images. \n The features of this application are as follows: - \n 1. To encode and decode the images. \n 2. To secure it with passwords. ", bg="#2f4155", fg="white", font="arial 10")
    instructions.pack(pady=10)

    # Image or Logo
    logo_img = PhotoImage(file="logo.png")
    logo_label = Label(page, image=logo_img, bg="#2f4155")
    logo_label.image = logo_img
    logo_label.pack(pady=20)

    # Additional Information or Tips
    tips_label = Label(page, text="Tip: You can use this app to send hidden messages securely.", bg="#2f4155", fg="white", font="arial 12 italic")
    tips_label.pack(pady=10)

# Hide and Show
def hide_show():
    page = Frame(root, bg = "#2f4155")
    page.place(x=0, y=0, relwidth=1, relheight=1)
    #label = Label(page, text="Hide and Show", bg="#2f4155", fg="white", font="arial 16 bold")
    #label.pack(pady=50)

    #logo
    #logo = PhotoImage(file = "label1.png")
    #Label(root,image = logo, bg = "#2f4155").place(x = 25, y = 15)

    Label(root,text = "CYBER SCIENCE", bg = "#2d4155", fg = "white", font = "arial 25 bold").place( x = 15, y = 20)    # the x value used to be 100 instead of 15 

    def showimage():
        global filename
        filename = filedialog.askopenfilename(initialdir = os.getcwd(), title = 'Select Image File', filetype = (("PNG file","*.png"),("JPG file","*.jpg"),("All file","*.txt")))

        img = Image.open(filename)
        img = ImageTk.PhotoImage(img)
        lbl.configure(image = img, width = 250, height = 250)
        lbl.image = img

    # Updated Hide function
    def Hide():
        global secret
        message = text1.get(1.0, END)
        password = simpledialog.askstring("Password", "Enter a password:", show='*')
        result = encrypt(message, password)
        
        # Unpack the result tuple
        encrypted_message, salt = result
        
        # Save salt to file
        save_salt("salt.txt", salt)
        
        # Save encrypted message to file
        save_to_file(encrypted_message, "encrypted_message.txt")
        secret = lsb.hide(str(filename), "encrypted_message.txt")
        return salt


    # Updated Show function
    def Show():
        password = simpledialog.askstring("Password", "Enter the password:", show='*')

        try:
            # Extract the file using stegano
            stegano_result = lsb.reveal(filename)

            if not stegano_result:
                messagebox.showerror("Error", "No hidden data found in the image.")
                return

            # Read the salt used during encryption
            salt = read_salt("salt.txt")

            # Decrypt the content directly
            decrypted_message_bytes = decrypt(read_from_file("encrypted_message.txt"), password, salt)

            if decrypted_message_bytes is None:
                messagebox.showerror("Error", "Failed to decrypt. Check your password.")
                return

            # Display the decrypted message
            text1.delete(1.0, END)
            text1.insert(END, decrypted_message_bytes.decode('utf-8', errors='replace'))

        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt: {str(e)}")

        
    def save():
        secret.save("hidden.png")

    #first frame 
    f = Frame(root,bd = 3, bg = "black", width = 340, height = 280, relief = GROOVE)
    f.place(x = 10, y = 80)

    lbl = Label(f, bg = "black")
    lbl.place(x = 40, y = 10)

    #Second Frame 
    frame2 = Frame(root, bd = 3, width = 340, height = 280, bg = "white", relief = GROOVE)
    frame2.place(x = 350, y = 80)

    text1 = Text(frame2, font = "Robote 20", bg = "white", fg = "black", relief = GROOVE, wrap = WORD)
    text1.place(x = 0, y = 0, width = 320, height = 295)

    scrollbar1 = Scrollbar(frame2)
    scrollbar1.place(x = 320, y = 0, height = 300)

    scrollbar1.configure(command = text1.yview)
    text1.configure(yscrollcommand = scrollbar1.set)

    #third frame
    frame3 = Frame(root, bd = 3, bg = "#2f4155", width = 330, height = 100, relief = GROOVE)
    frame3.place(x = 10, y = 370)

    Button(frame3, text = "Open Image", width = 10, height = 2, font = "arial 14 bold", command = showimage).place(x = 20, y = 30)
    Button(frame3, text = "Save Image", width = 10, height = 2, font = "arial 14 bold", command = save).place(x = 180, y = 30)
    Label(frame3, text = "Picture, Image, Photo File", bg = "#2f4155", fg = "yellow").place(x = 20, y = 5)

    #fourth frame
    frame4 = Frame(root, bd = 3, bg = "#2f4155", width = 330, height = 100, relief = GROOVE)
    frame4.place(x = 360, y = 370)

    Button(frame4, text = "Hide Data", width = 10, height = 2, font = "arial 14 bold", command = Hide).place(x = 20, y = 30)
    Button(frame4, text = "Show Data", width = 10, height = 2, font = "arial 14 bold", command = Show).place(x = 180, y = 30)
    Label(frame4, text = "Picture, Image, Photo File", bg = "#2f4155", fg = "yellow").place(x = 20, y = 5)

# About Page
def about_page():
    page = Frame(root, bg="#2f4155")
    page.place(x=0, y=0, relwidth=1, relheight=1)

    # Title
    label = Label(page, text="About Us", bg="#2f4155", fg="white", font="arial 20 bold")
    label.pack(pady=20)

    # Description
    description = Label(page, text="Steganography Application, version 1.01.01 \n Copyright(C) 2023 Crypotography Foundation \n Licensed under GNU GPL License, Version 1 \n\n E-mail: crypotograpghyfoundation@gmail.com \n Website: https://steganographyapplication.ak.net \n\n We are a team of developers passionate about cybersecurity and digital privacy.", bg="#2f4155", fg="white", font="arial 10")
    description.pack(pady=10)

    # Team Members
    members_label = Label(page, text="Team Members:", bg="#2f4155", fg="white", font="arial 16 bold")
    members_label.pack(pady=10)

    # List of Team Members
    team_members = [
        "Darijan Zumarvic - Developer",
        "Simranpreet Kaur - Developer",
    ]

    for member in team_members:
        member_label = Label(page, text=member, bg="#2f4155", fg="white", font="arial 12")
        member_label.pack()

# Switch to the Home Page by default
home_page()

# Menu
menu = Menu(root)
root.config(menu=menu)
menu.add_command(label="Home", command=home_page)
menu.add_command(label="Hide/Show", command=hide_show)
menu.add_command(label="About Us", command=about_page)




root.mainloop()


 

