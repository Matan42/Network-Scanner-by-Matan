from network_scanner_module import scanner, read_from_file, write_to_file, show_devices, check_arp_spoofing, devices

def get_answer():
    """
    Function asks the user what they would like to do and validates the input.
    """
    print("What would you like to do?")
    print("1 Start a scan")
    print("2 Read a scan from an exsiting file")
    print("3 Write current scan to a file")
    if devices:
        print("4 Show current scan")
    print("0 Exit")

    while True:
        try:
            ans = int(input("Enter your choice:"))
            if 0 <= ans <= 3 or (devices and ans == 4):
                return ans
            print("Unrecognized option")
        except ValueError:
            print("Unrecognized option")

def main():
    """
    Main function to run the network scanner program.
    """
    print("Hello Welcome To Matan's Network Scanner.")
    print("This program scans your device's network shows all connected devices and searches for security threats")

    while True:
        user_ans = get_answer()

        if user_ans == 1:
            scanner()
            show_devices()
            check_arp_spoofing()
        elif user_ans == 2:
            file_name = input("Enter file name:")
            read_from_file(file_name)
            if devices:
                show_devices()
                check_arp_spoofing()
        elif user_ans == 3:
            if devices:
                file_name = input("Enter file name:")
                write_to_file(file_name)
            else:
                print("No scan results to write. Please perform a scan or read from a file first.")
        elif user_ans == 4:
            if devices:
                show_devices()
                check_arp_spoofing()
            else:
                print("No scan results to show. Please perform a scan or read from a file first.")
        elif user_ans == 0:
            print("Goodbye")
            break

if __name__ == "__main__":
    main()
