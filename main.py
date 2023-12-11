import tkinter as tk
from tkinter import filedialog
import pyperclip
import os
from AES import encrypt, decrypt

class PasswordDialog(tk.simpledialog.Dialog):
    def body(self, master):
        tk.Label(master, text="Введите пароль:").grid(row=0)
        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.grid(row=0, column=1)
        return self.password_entry

    def apply(self):
        self.result = self.password_entry.get()

class AESEncryptionApp:
    def __init__(self, root):
        # Показываем диалог ввода пароля перед созданием основного окна
        password_dialog = PasswordDialog(root)
        if password_dialog.result != "admin":
            root.destroy()
            return

        self.root = root
        self.root.title("AES Encryption App")

        icon_path = "AES.ico"
        self.root.iconbitmap(icon_path)

        self.mode_var = tk.StringVar(value="text")
        self.mode_text_button = tk.Radiobutton(root, text="Работа с текстом", variable=self.mode_var, value="text", command=self.toggle_mode)
        self.mode_text_button.grid(row=0, column=0, pady=10, padx=10, sticky="w")

        self.mode_file_button = tk.Radiobutton(root, text="Работа с файлом", variable=self.mode_var, value="file", command=self.toggle_mode)
        self.mode_file_button.grid(row=0, column=1, pady=10, padx=10, sticky="w")

        self.text_label = tk.Label(root, text="Введите текст:")
        self.text_label.grid(row=1, column=0, pady=10, padx=10, sticky="w")

        self.text_entry = tk.Entry(root, width=40)
        self.text_entry.grid(row=1, column=1, pady=10, padx=10, sticky="w")

        self.key_label = tk.Label(root, text="Введите ключ:")
        self.key_label.grid(row=2, column=0, pady=10, padx=10, sticky="w")

        self.key_entry = tk.Entry(root, show="*", width=40)
        self.key_entry.grid(row=2, column=1, pady=10, padx=10, sticky="w")

        self.encrypt_button = tk.Button(root, text="Зашифровать", command=self.encrypt_text)
        self.encrypt_button.grid(row=3, column=0, pady=10, padx=10, sticky="w")

        self.decrypt_button = tk.Button(root, text="Расшифровать", command=self.decrypt_text)
        self.decrypt_button.grid(row=3, column=1, pady=10, padx=10, sticky="w")

        self.copy_button = tk.Button(root, text="Копировать", command=self.copy_to_clipboard)
        self.copy_button.grid(row=4, column=0, columnspan=2, pady=10, padx=10, sticky="w")

        self.paste_button = tk.Button(root, text="Вставить из буфера", command=self.paste_from_clipboard)
        self.paste_button.grid(row=5, column=0, columnspan=2, pady=10, padx=10, sticky="w")

        self.load_key_button = tk.Button(root, text="Загрузить ключ из файла", command=self.load_key_from_file)
        self.load_key_button.grid(row=6, column=0, columnspan=2, pady=10, padx=10, sticky="w")

        self.result_label = tk.Label(root, text="")
        self.result_label.grid(row=7, column=0, columnspan=2, pady=10, padx=10, sticky="w")

        # Добавлено ограничение на длину ключа
        self.validate_key_length = root.register(self.validate_key)
        self.key_entry.config(validate="key", validatecommand=(self.validate_key_length, "%P"))

        # Вызываем toggle_mode при запуске приложения
        self.toggle_mode()

    def toggle_mode(self):
        mode = self.mode_var.get()
        if mode == "text":
            self.text_label.grid(row=1, column=0, pady=10, padx=10, sticky="w")
            self.text_entry.grid(row=1, column=1, pady=10, padx=10, sticky="w")
            self.copy_button.grid(row=4, column=0, columnspan=2, pady=10, padx=10, sticky="w")
            self.paste_button.grid(row=5, column=0, columnspan=2, pady=10, padx=10, sticky="w")
        elif mode == "file":
            self.text_label.grid_forget()
            self.text_entry.grid_forget()
            self.copy_button.grid_forget()
            self.paste_button.grid_forget()

    def encrypt_text(self):
        mode = self.mode_var.get()
        if mode == "text":
            text = self.text_entry.get()
        elif mode == "file":
            file_path = self.choose_file()
            if file_path is None:
                return
            with open(file_path, "r", encoding="utf-8") as file:
                text = file.read()

        key = self.get_key()

        # Используем ваш код для шифрования
        ciphertext = encrypt(key, text)

        if mode == "text":
            self.result_label.config(text="Зашифрованный текст: {}".format(ciphertext.hex()))
        elif mode == "file":
            encrypted_file_path = os.path.join(os.path.dirname(file_path), "encrypted.txt")
            with open(encrypted_file_path, "wb") as encrypted_file:
                encrypted_file.write(ciphertext)
            self.result_label.config(text=f"Файл успешно зашифрован: {encrypted_file_path}")

    def decrypt_text(self):
        mode = self.mode_var.get()
        if mode == "text":
            result_text = self.result_label.cget("text")
            if "Текст скопирован в буфер обмена" in result_text:
                encrypted_text = pyperclip.paste()
            else:
                encrypted_text = result_text.split(":")[1].strip()

            key = self.get_key()

            # Используем ваш код для дешифрования
            decrypted_data = decrypt(key, bytes.fromhex(encrypted_text))

            self.result_label.config(text=f"Расшифрованный текст: {decrypted_data.decode('utf-8')}")
        elif mode == "file":
            file_path = self.choose_file()
            if file_path is None:
                return

            with open(file_path, "rb") as file:
                ciphertext = file.read()

            key = self.get_key()

            # Используем ваш код для дешифрования
            decrypted_data = decrypt(key, ciphertext)

            decrypted_file_path = os.path.join(os.path.dirname(file_path), "decrypted.txt")
            with open(decrypted_file_path, "w", encoding="utf-8") as decrypted_file:
                decrypted_file.write(decrypted_data.decode("utf-8"))

            self.result_label.config(text=f"Файл успешно расшифрован: {decrypted_file_path}")

    def copy_to_clipboard(self):
        encrypted_text = self.result_label.cget("text").split(":")[1].strip()
        pyperclip.copy(encrypted_text)
        self.result_label.config(text="Текст скопирован в буфер обмена")

    def paste_from_clipboard(self):
        clipboard_text = root.clipboard_get()
        self.text_entry.delete(0, tk.END)
        self.text_entry.insert(tk.END, clipboard_text)

    def load_key_from_file(self):
        key_file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if key_file_path:
            with open(key_file_path, "r", encoding="utf-8") as key_file:
                key = key_file.read(16)
                self.key_entry.delete(0, tk.END)
                self.key_entry.insert(tk.END, key)

    def choose_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        return file_path

    def validate_key(self, key):
        # Ограничиваем длину ключа до 16 символов
        return len(key) <= 16

    def get_key(self):
        # Получаем ключ из entry или используем пустую строку, если entry пустой
        key = self.key_entry.get().encode("utf-8")
        return key

if __name__ == "__main__":
    root = tk.Tk()
    app = AESEncryptionApp(root)
    root.mainloop()
