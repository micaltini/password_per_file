import tkinter as tk 
from tkinter import filedialog, simpledialog, messagebox
import sqlite3  # Gestione del database SQLite
import base64  # Codifica base64
import hashlib  # Generazione dell'hash SHA-256
from cryptography.fernet import Fernet  # Cifratura e decifratura dei dati
import os


# Creazione del database e della tabella

# Creazione e connessione al database
conn = sqlite3.connect('file_protetti.db')
cursor = conn.cursor()

# Creazione della tabella
cursor.execute('''
    CREATE TABLE IF NOT EXISTS file_protetti (
        nome_file TEXT PRIMARY KEY,
        password_cifrata TEXT NOT NULL
    )
''')
conn.commit()

'''
# Verifica della connessione al database
def verifica_connessione():
    try:
        cursor.execute('SELECT 1')
        print("Connessione al database riuscita.")
    except sqlite3.Error as e:
        print(f"Errore nella connessione al database: {e}")

verifica_connessione()
'''

# Creiamo adesso una funzione che generi una chiave crittografica da una password
# Le password devono essere prima convertite in byte, poi passate alla funzione di hashing per essere convertite in sha256
# Che restituisce un coidce di 256 bit (32 byte)
# L'hash viene quindi codificato in una stringa base64url. Questo converte l'hash binario in una rappresentazione di testo sicura e compatibile con le librerie crittografiche.




def key_from_password(password):
    # Calcola l'hash SHA-256 della password
    hash_object = hashlib.sha256(password.encode())
    digest = hash_object.digest()  # Ottieni il risultato dell'hash come sequenza di byte
    key = base64.urlsafe_b64encode(digest)  # Codifica l'hash in formato base64url
    return key



'''
# Esempio di utilizzo
password = "password_segreta"
key = key_from_password(password)
print("Chiave generata:", key)
'''

# Creiamo la funzione per cifrare i dati 

def encrypt_data(data, password):
    key = key_from_password(password) # Viene richiamata la funzione scritta in precedenza per generare una chiave base64url
    fernet = Fernet(key)              # Viene creato un oggetto Fernet 
    encrypted_data = fernet.encrypt(data.encode()) # Utilizziamo il metodo encrypt dell'oggetto Fernet per cifrare i dati
    return encrypted_data # La funzione ci restituisce i dati criptati

# Creiamo la funzione per decifrare i dati

def decrypt_data(encrypted_data, password):
    key = key_from_password(password)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data


'''
# Di seguito alcuni esempi di utilizzo delle funzioni per testare la correttezza

# Esempio 1: Cifratura di un nome di file
filename_to_encrypt = "documento_segreto.txt"
password = "password_segreta"

encrypted_filename = encrypt_data(filename_to_encrypt, password)
print("Nome del file cifrato:", encrypted_filename)

# Esempio 2: Decifratura di dati
data_encrypted = encrypt_data("Dati sensibili da proteggere!", password)
print("Dati cifrati:", data_encrypted)

decrypted_data = decrypt_data(data_encrypted, password)
print("Dati decifrati:", decrypted_data)
'''

# Funzione per impostare una password per un file o una cartella

def imposta_password(nome_file, password):
    password_cifrata = encrypt_data(password, password)  # Cifrare la password con se stessa
    cursor.execute('''
        INSERT OR REPLACE INTO file_protetti (nome_file, password_cifrata)
        VALUES (?, ?)
    ''', (nome_file, password_cifrata))
    conn.commit()
    print(f"Password impostata per {nome_file}.")


'''
# Di seguito propongo il codice per fare delle prove, per assicurarmi che tutto funzioni 
# Funzione per verificare l'inserimento di una riga

def verifica_inserimento(nome_file):
    cursor.execute('SELECT * FROM file_protetti WHERE nome_file = ?', (nome_file,))
    result = cursor.fetchone()
    if result:
        print(f"Riga trovata: {result}")
    else:
        print("Riga non trovata.")

# Funzione per cancellare una riga

def cancella_riga(nome_file):
    cursor.execute('DELETE FROM file_protetti WHERE nome_file = ?', (nome_file,))
    conn.commit()
    print(f"Riga cancellata per {nome_file}.")


# Esempio di utilizzo delle funzioni

nome_file_test = "test_file.txt"
password_test = "test_password"

# Impostazione della password

imposta_password(nome_file_test, password_test)

# Verifica dell'inserimento

verifica_inserimento(nome_file_test)

# Cancellazione della riga

cancella_riga(nome_file_test)

# Verifica della cancellazione

verifica_inserimento(nome_file_test)
'''

# Funzione che permette di impostare una password dall'interfaccia grafica

def imposta_password_gui(nome_file):
    password = simpledialog.askstring("Imposta Password", f"Inserisci una password per {nome_file}:", show='*')
    if password:
        imposta_password(nome_file, password)
        messagebox.showinfo("Successo", f"Password impostata per {nome_file}.")
    else:
        messagebox.showwarning("Attenzione", "Nessuna password inserita.")



# Funzione che permette di selezionare un file o una cartella a cui impostare una password

def seleziona_file_o_cartella():
    nome_file = filedialog.askopenfilename() or filedialog.askdirectory()
    if nome_file:
        imposta_password_gui(nome_file)




# Creazione interfaccia grafica

root = tk.Tk()
root.title("Protezione File e Cartelle") # Creata interfaccia grafica
root.geometry('300x150')

btn_seleziona = tk.Button(root, text="Seleziona File o Cartella", command=seleziona_file_o_cartella)
btn_seleziona.pack(pady=20)

root.mainloop()

# Funzione per aprire un file o una cartella

def apri_file_o_cartella(nome_file):
    if os.path.isfile(nome_file):
        os.startfile(nome_file)
    elif os.path.isdir(nome_file):
        os.startfile(nome_file)
    else:
        messagebox.showerror("Errore", "File o cartella non trovato.")

# Funzione per controllare la password di un file o una cartella

def controlla_password(nome_file):
    cursor.execute('SELECT password_cifrata FROM file_protetti WHERE nome_file = ?', (nome_file,))
    result = cursor.fetchone()
    if result:
        password_cifrata = result[0]
        password = simpledialog.askstring("Password richiesta", f"Inserisci la password per accedere a {nome_file}:", show='*')
        try:
            password_decifrata = decrypt_data(password_cifrata, password)
            if password_decifrata == password:
                print(f"Accesso consentito a {nome_file}.")
                apri_file_o_cartella(nome_file)
            else:
                messagebox.showerror("Errore", "Password errata.")
        except Exception as e:
            messagebox.showerror("Errore", f"Errore nella decifratura: {e}")
    else:
        print(f"Nessuna password impostata per {nome_file}. Apertura consentita.")
        apri_file_o_cartella(nome_file)

