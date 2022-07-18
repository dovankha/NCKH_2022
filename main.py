from tkinter import *
import tkinter.messagebox
from pystray import MenuItem as item
import pystray
from PIL import Image
import pydivert
import re
import pickle
import warnings

tk = Tk()
tk.title('Web Phishing Blocker')
tk.iconbitmap('favicon.ico')
tk.geometry("350x250")
tk.resizable()

# global is_on
is_on = True

label = Label(tk, text="Enable", fg="green", font=("Helvetica", 32))
label.pack(pady=20)

warnings.filterwarnings("ignore")


# load = pickle.load(open('phishing.pkl', 'rb'))


def check_format_URL(url):
    return re.findall(r'(http|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)


def check_format_url(url):
    regex = r"(?i)\b(^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$)"
    return re.compile(regex).match(url)


def extract_url_http(payload_tcp):
    start_string = 'Host: '
    end_string = '\r\nConnection'
    start_index = payload_tcp.find(start_string.encode())
    end_index = payload_tcp.find(end_string.encode())
    host = payload_tcp[start_index + 6:end_index]

    start_string = 'GET '
    end_string = ' HTTP'
    start_index = payload_tcp.find(start_string.encode())
    end_index = payload_tcp.find(end_string.encode())
    path = payload_tcp[start_index + 4:end_index]
    url = host + path
    url1 = 'http://' + url.decode('utf-8')
    if len(url) != 0 and check_format_url(url.decode()):
        url = url.decode()
        return url
    return ""


def extract_url_https(payload_tcp):
    start_index = 127
    end_string = '\x00\x17'

    end_index = payload_tcp.find(end_string.encode('utf-8'), start_index)
    url = payload_tcp[start_index:end_index]
    if len(url) != 0 and check_format_url(url.decode('utf-8', 'backslashreplace')):
        url = url.decode('utf-8', 'backslashreplace')
        return url
    return ""


def extract_url(payload_tcp, dst_port):
    if dst_port == 80:
        return extract_url_http(payload_tcp)
    if dst_port == 443:
        return extract_url_https(payload_tcp)


def phishing():
    # global is_on
    if is_on:
        with pydivert.WinDivert("(tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.PayloadLength > 0") as w:
            for packet in w:
                if extract_url(packet.tcp.payload, packet.dst_port) == "bad":
                    pass
                    # else:
                    #     # if (load.predict([extract_url(packet.tcp.payload, packet.dst_port)]) == "bad"):
                    #     if extract_url(packet.tcp.payload, packet.dst_port) == "www.google.com":
                    #         tkinter.messagebox.showwarning(title="Phishing url",
                    #                                        message=extract_url(packet.tcp.payload, packet.dst_port))
                    #         # return extract_url(packet.tcp.payload, packet.dst_port)
                    #     else:
                    #         pass
                    print(extract_url(packet.tcp.payload, packet.dst_port))
                w.send(packet)


class phishing:
    def destroy_phishing(self):
        self.master.destroy()
        pass


def Switch():
    global is_on

    if is_on:
        button.config(image=off)
        label.config(text="Disable", fg="grey")
        is_on = False
        phishing.destroy_phishing(self='')

    else:
        button.config(image=on)
        label.config(text="Enable", fg="green")
        is_on = True
        phishing.phishing(self='')


def quit_window(icon, item):
    icon.stop()
    tk.destroy()


def show_window(icon, item):
    icon.stop()
    tk.after(0, tk.deiconify)


def Hidden():
    tk.withdraw()
    image = Image.open("favicon.ico")
    menu = (item('Quit', quit_window), item('Show', show_window))
    icon = pystray.Icon("name", image, "Phishing Blocker", menu)
    icon.run()


def Exit():
    answer = tkinter.messagebox.askyesno(title='Exit', message='Are you sure that you want to exit?')
    if answer:
        tk.destroy()


# --- assign image
on = PhotoImage(file="on.png")
off = PhotoImage(file="off.png")
img_hidden = PhotoImage(file="down.png")
img_exit = PhotoImage(file="exit.png")

# --- Button on - off
button = Button(tk, image=on, bd=0, command=Switch)
button.pack(pady=40)
# --- Button hidden
button_hidden = Button(tk, image=img_hidden, bd=0, command=Hidden)
button_hidden.pack()
button_hidden.place(x=13, y=120, width=76, height=76)
# --- Button exit
button_exit = Button(tk, image=img_exit, bd=0, command=Exit)
button_exit.pack()
button_exit.place(x=258, y=120, width=76, height=76)

label_auth = Label(tk, text="Made by Kha & Thoại", fg="black", font=("Arial", 11))
label_auth.pack(pady=8)

tk.mainloop()
