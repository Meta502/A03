import socket

BUFFER_SIZE = 1024
SERVER_IP = "127.0.0.1"
SERVER_PORT = 4896


def main():
    sc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("Contoh Socket Client UDP")
    print("Tekan Ctrl/CMD+C untuk menghentikan program")

    outgoing_message = input("Masukan sebuah string untuk dikirimkan ke server: ")
    outgoing_message_raw = outgoing_message.encode("UTF-8")

    sc.sendto(outgoing_message_raw, (SERVER_IP, SERVER_PORT))

    inbound_message_raw, source_addr = sc.recvfrom(BUFFER_SIZE)
    inbound_message = inbound_message_raw.decode("UTF-8")

    print(f"Balasan dari server {source_addr}: {inbound_message}")

    sc.close()


if __name__ == "__main__":
    main()
