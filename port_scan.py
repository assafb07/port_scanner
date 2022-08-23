from tkinter import *
import tkinter as tk
import os
import socket
from threading import Thread
from threading import Event
import time
from PIL import ImageTk, Image
from pic2str import logo
import base64
from io import BytesIO

text_box_bg = "#8084AD"
frame_bg = "#545BAF"
label_bg = "black"
entry_bg = "#F6F7D2"
text_color = "white"
event = Event()
y_place_box = 120
y_place_low = 260
counter = 0
scan_time_out = 0.7
fast_scan = 0.1

def scan(start, end, target, last_port, event):
    global counter
    global scan_time_out
    print (scan_time_out)
    text_box.delete('1.0', END)
    low_box.delete('1.0', END)
    print_here = 1
    counter +=1

#    if counter == 1:
#        text_box.insert(1.0, "scanning...\n")
#        text_box.tag_add("left", 1.0, "end")
#        text_box.place(x=10, y=y_place_box)

    for port in range(start, end):

        if port > last_port:
            continue
        elif event.is_set():
            break
        else:
            low_windows_p = (f"Checking port {port}\n")
            low_box.insert(1.0, low_windows_p)
            low_box.tag_add("left", 1.0, "end")

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(scan_time_out)
            result = s.connect_ex((target, port)) #return an error indicator
            if result == 0:
                to_print = (f"Port {port} is open\n")
                text_box.insert('1.0', to_print)
                text_box.tag_add("left", 1.0, "end")
                text_box.place(x=10, y=y_place_box)
                print_here = print_here + 1
        s.close()


def threads(target):
    stop_it = 0
    event.clear()
    text_box.delete('1.0', END)
    low_box.delete('1.0', END)
    start_port = int(port_start.get())
    last_port = int(port_end.get())
    last_thread = int((last_port-start_port) / 50)+1

    if last_thread < 1:
        last_thread = 1

    for t in range(1,last_thread+1):
        thread = Thread(target = scan, args = (start_port,start_port+50, target, last_port, event))
        thread.start()
        start_port += 50


def check_ip(scan_speed):
    target = "0.0.0.0"
    global scan_time_out
    scan_time_out = scan_speed
    print (scan_time_out)
    ip_01 = ip_1.get()
    ip_02 = ip_2.get()
    ip_03 = ip_3.get()
    ip_04 = ip_4.get()

    start_port = port_start.get()
    last_port = port_end.get()

    if start_port == "" or last_port == "":
        port_invalid = "port"
        port_ip_valid(port_invalid, target)

    elif (ip_01) == "" or (ip_02) == "" or (ip_03) == "" or (ip_04) == "" :
        ip_invalid = "ip"
        port_ip_valid(ip_invalid, target)

    elif int(ip_01) > 255 or int(ip_02) > 255 or int(ip_03) >255 or int(ip_04) > 255 :
        ip_invalid = "ip"
        port_ip_valid(ip_invalid, target)

    elif int(start_port) < 0 or int(last_port) < 0 or int(start_port) > 65000 or int(last_port) < int(start_port) or int(last_port) > 65000 :
        port_invalid = "port"
        port_ip_valid(port_invalid, target)
    else:
        ip_ok = "ok"
        target = (f"{ip_01}.{ip_02}.{ip_03}.{ip_04}")
        port_ip_valid(ip_ok, target)

def port_ip_valid(port_ip, target):
    text_box.delete('1.0', END)
    low_box.delete('1.0', END)
    if port_ip == "ip":
        text_box.insert(1.0, "Invalid Ip")
        text_box.tag_add("left", 1.0, "end")
        text_box.place(x=10, y=y_place_box)

    elif port_ip == "port":
        text_box.insert(1.0, "Invalid port range")
        text_box.tag_add("left", 1.0, "end")
        text_box.place(x=10, y=y_place_box)

    elif port_ip == "ok" :
        text_box.delete('1.0', END)
        low_box.delete('1.0', END)
        threads(target)

def stop_scan():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.close()
    text_box.insert(8.0, "Scanning Stoped")
    text_box.tag_add("left", 1.0, "end")
    text_box.place(x=10, y=y_place_box)
    global counter
    counter = 0
    global scan_time_out
    scan_time_out = 0.7
    event.set()

top = tk.Tk()
top.geometry("349x475")
top.configure(bg = frame_bg)
top.title("Port Scanner @ Assaf.B")

byte_data = base64.b64decode(logo)
image_data = BytesIO(byte_data)
logo = Image.open(image_data)
logo = ImageTk.PhotoImage(logo)
#frame_bg = ImageTk.PhotoImage(file = logo)

label_image = tk.Label(top, image = logo).place(x=0, y=0)
label = tk.Label(top, text = "Port Scanner", font=("30"), bg = label_bg, fg = text_color).place(x = 30,y = 3)
label01 = tk.Label(top, text = "Ip Address", bg = label_bg, fg = text_color).place(x = 30,y = 30)
lable02 = tk.Label(top, text = "Port Range (x-y)", bg = label_bg, fg = text_color).place(x = 30, y = 55)


ip_1 = tk.StringVar()
ip_2 = tk.StringVar()
ip_3 = tk.StringVar()
ip_4 = tk.StringVar()
port_start = tk.StringVar()
port_end = tk.StringVar()

ip1 = tk.Entry(top, textvariable = ip_1, width = 4, bg = entry_bg).place(x = 100, y = 30)
point1 = tk.Label(top, text=".", width = 1, bg = label_bg, fg = text_color).place(x = 128, y = 30)
ip2 = tk.Entry(top, textvariable = ip_2, width = 4, bg = entry_bg).place(x = 139, y = 30)
point2 = tk.Label(top, text = ".", width = 1, bg = label_bg, fg = text_color).place(x = 165, y = 30)
ip3 = tk.Entry(top, textvariable = ip_3, width = 4, bg = entry_bg).place(x = 178, y = 30)
point3 = tk.Label(top, text = '.', width = 1, bg = label_bg, fg = text_color).place(x = 204, y = 30)
ip4 = tk.Entry(top, textvariable = ip_4, width = 4, bg = entry_bg).place(x = 216, y = 30)

port01 = tk.Entry(top, textvariable = port_start, width = 5, bg = entry_bg).place(x = 130, y = 55)
port_sape = tk.Label(top, text = "-", width = 2, bg = label_bg, fg = text_color).place(x = 165, y = 55)
port02 = tk.Entry(top, textvariable = port_end, width = 5, bg = entry_bg).place(x = 185, y = 55)

sbmitbtn = tk.Button(top, bg = entry_bg, text = "Scan",activebackground = "pink", activeforeground = "blue", command=lambda:check_ip(scan_time_out)).place(x = 30, y = 82)
sbmitbtn = tk.Button(top, bg = entry_bg, text = "Fast Scan",activebackground = "pink", activeforeground = "blue", command=lambda:check_ip(fast_scan)).place(x = 80, y = 82)
sbmitbtn = tk.Button(top, bg = entry_bg, text = "Stop",activebackground = "pink", activeforeground = "blue", command=lambda:stop_scan()).place(x = 160, y = 82)
text_box = tk.Text(top, height=12, width=40, bg = text_box_bg)
text_box.place(x=10, y=y_place_box)
text_box.insert(1.0, "Example: 192.168.14.1\n         1-1024\n\nUse Fast Scan carefully,\nit may miss open ports.\n\nEnjoy :)")
text_box.tag_add("left", 1.0, "end")
text_box.place(x=10, y=y_place_box)
low_box = tk.Text(top, height=12, width=40, bg = text_box_bg)
low_box.insert(1.0, "\n\n\n\n\n\n\n\n\n\n\n\t\tPython code @assaf bahar")
low_box.tag_add("left", 1.0, "end")
low_box.place(x=10, y=260)



top.mainloop()
