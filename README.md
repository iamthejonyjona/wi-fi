import tkinter as tk
from tkinter import messagebox
from scapy.all import ARP, Ether, srp

# Definir la contraseña
CONTRASENA = "miContraseña123"  # Cambia esto por la contraseña que desees

# Función para escanear la red
def scan_network(target_ip):
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request 

    # Enviar la consulta ARP y recibir la respuesta
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device)

    return devices

# Función para mostrar los resultados del escaneo
def print_results(devices):
    result_window = tk.Toplevel()  # Crear nueva ventana para mostrar resultados
    result_window.title("Dispositivos conectados")

    tk.Label(result_window, text="Dispositivos conectados a la red:", font=("Arial", 14)).pack(pady=10)
    tk.Label(result_window, text="IP" + " "*10 + "MAC", font=("Arial", 12)).pack()
    tk.Label(result_window, text="-" * 40, font=("Arial", 12)).pack()
    
    for device in devices:
        tk.Label(result_window, text=f"{device['ip']:<15} {device['mac']}", font=("Arial", 12)).pack()

# Función para verificar la contraseña
def verify_password():
    entered_password = password_entry.get()
    
    if entered_password == CONTRASENA:
        # Si la contraseña es correcta, cerrar la ventana de inicio y realizar el escaneo
        password_window.destroy()
        target_ip = "192.168.1.1/24"  # Cambiar el rango IP si es necesario
        devices = scan_network(target_ip)
        print_results(devices)
    else:
        # Si la contraseña es incorrecta, mostrar mensaje de error
        messagebox.showerror("Error", "Contraseña incorrecta. Inténtalo de nuevo.")

# Crear la ventana de inicio para ingresar la contraseña
password_window = tk.Tk() #quiero que me de en tiempo real 
password_window.title("Ingreso de Contraseña")
password_window.geometry("300x150")

# Etiqueta para indicar la contraseña
tk.Label(password_window, text="Ingresa la contraseña", font=("Arial", 12)).pack(pady=10)

# Campo de entrada para la contraseña
password_entry = tk.Entry(password_window, show="*", font=("Arial", 12))
password_entry.pack(pady=5)

# Botón para verificar la contraseña
tk.Button(password_window, text="Entrar", font=("Arial", 12), command=verify_password).pack(pady=10)

# Ejecutar la ventana de inicio
password_window.mainloop()
