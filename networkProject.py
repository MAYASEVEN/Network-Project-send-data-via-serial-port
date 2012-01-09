#!/usr/bin/env python
#-*- coding:UTF-8 -*-
import serial, os, hashlib, binascii, base64

def main():
    os.system(['clear', 'cls'][os.name == 'nt'])
    print '''
   _____                             _             
  /  __ \                           | |            
  | /  \/ ___  _ __ ___  _ __  _   _| |_  ___ _ __ 
  | |    / _ \| '_ ` _ \| '_ \| | | | __|/ _ \ '__|
  | \__/\ (_) | | | | | | |_) | |_| | |_|  __/ |   
   \____/\___/|_| |_| |_| .__/ \__,_|\__|\___|_|   
                        | |                        
                        |_|                        

           _   _      _                      _    
          | \ | |    | |                    | |   
          |  \| | ___| |___      _____  _ __| | __
          | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /
          | |\  |  __/ |_ \ V  V / (_) | |  |   < 
          \_| \_/\___|\__| \_/\_/ \___/|_|  |_|\_\\
                                                  
                                                  

                 ______           _           _        _____  _____  __   __  
                 | ___ \         (_)         | |      / __  \|  _  |/  | /  | 
                 | |_/ /_ __ ___  _  ___  ___| |_     `' / /'| |/' |`| | `| | 
                 |  __/| '__/ _ \| |/ _ \/ __| __|      / /  |  /| | | |  | | 
                 | |   | | | (_) | |  __/ (__| |_     ./ /___\ |_/ /_| |__| |_
                 \_|   |_|  \___/| |\___|\___|\__|    \_____/ \___/ \___/\___/
                                _/ |                                          
                               |__/                                           
       
'''
    print   "MaYaSeVeN -- http://mayaseven.blogspot.com"
    print   "Methuz -- http://joinstick.net"
    inputMode = raw_input("\nSelect Mode :\n    1.)SendSW\n    2.)ReceiveSW\n    3.)SendSR\n    4.)ReceiveSR\n\nInput number : ")
    print   "" 
    if (inputMode.isdigit()):
        inputMode = int(inputMode)
        if(inputMode == 1 or inputMode == 2 or inputMode == 3 or inputMode == 4):
            if(inputMode == 1):
                inputFile = raw_input("Input filename to send : ")
                sendSW(inputFile)
            elif(inputMode == 2):
                receiveSW()
            elif(inputMode == 3):
                inputFile = raw_input("Input filename to send : ")
                sendSR(inputFile)
            elif(inputMode == 4):
                receiveSR()
        else:
            print "\nInput number 1 - 4 !!!!"
    else:
        print "\nInput number !!!!"
        
def packetMake(data, sizeFile):
    header = "7E"
    packetSplit = []
    numberPacket = 0
    packet = []
    for i in range(0, sizeFile, 149):
        sizePacket = sizeFile - i
        if(sizePacket < 149):
            packetSplit.append(data[i:i + sizePacket])
            packetMake = header + "%04x" % numberPacket + "%X" % sizePacket + packetSplit[numberPacket]
            crc = binascii.crc32(packetMake) & 0xffffffff
            packetMake += "%08x" % crc
            packet.append(packetMake)
            numberPacket += 1
        else:
            packetSplit.append(data[i:i + 149])
            packetMake = header + "%04x" % numberPacket + "95" + packetSplit[numberPacket]
            crc = binascii.crc32(packetMake) & 0xffffffff
            packetMake += "%08x" % crc
            packet.append(packetMake)
            numberPacket += 1
    return packet, numberPacket
    
def sendSW(inputFile):
    ser = serial.Serial(
        port='COM3',
        baudrate=9600,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        bytesize=serial.EIGHTBITS,
        timeout=7
    )
    try:
        f = open(inputFile, 'rb')
        md5file = "MD5Sum of " + inputFile + " : " + hashlib.md5(f.read()).hexdigest()
        f.flush
        f = open(inputFile, 'rb')
        data = f.read()
        f.close()
    except IOError:
        print "Error: can\'t find file or read data"
    else:
        sizeFile = os.stat(inputFile).st_size
        packet, numberPacket = packetMake(data, sizeFile)    
        i = 0
        handshanke = str(numberPacket) + " " + inputFile + "\n"
        ser.write(handshanke)
        while i < (numberPacket):
            ser.write(base64.b64encode(packet[i]) + "\n")
            print "Sending packet number " + str(i) 
            if(int(ser.readline()) != i):
                continue 
            else:
                print "ACK " + str(i) + " Received\n"
                i += 1
        print "\nTotal number of packet is %s" % numberPacket
        print "Sending file size is %s" % sizeFile 
        print md5file
        print "\n[+] Sending Complete. Filename is %s" % inputFile
    ser.flush()       
    
def receiveSW():      
    ser = serial.Serial(
        port='COM4',
        baudrate=9600,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        bytesize=serial.EIGHTBITS,
        timeout=7
    )
    handshake = ser.readline()
    numberPacket = int(handshake.split()[0])
    k = 0
    packetR = []
    while k < numberPacket:       
        packetR.append(base64.b64decode(ser.readline()))
        crcCheck = packetR[k][-8:]
        crcPacket = binascii.crc32(packetR[k][:-8]) & 0xffffffff
        print "Packet number %s's header is %s" % (k, packetR[k][:8])
        if crcCheck == "%08x" % crcPacket:
            print "Packet number %s CRC is checked " % k + "(%s,%08x)" % (crcCheck, crcPacket)
            if int(packetR[k][2:6], 16) == k:
                ser.write("%d" % k + "\n")
                print "Sending ACK %s" % k + "\n"
            else:
                continue
        else:
            continue
        k += 1
    ser.close()
    p = 0
    data = ""
    while p < len(packetR):
        data += packetR[p][8:-8]
        p += 1
    receiveFile = 'Receive' + "_" + handshake.split()[1]
    f = open(receiveFile, 'wb')
    for l in data:
        f.write(l)
    f.flush()
    f = open(receiveFile, 'rb')
    print "MD5Sum of " + receiveFile + " : " + hashlib.md5(f.read()).hexdigest()
    print "\n[+] Receiving Complete. Filename is %s" % receiveFile
    f.flush       
    os.system(receiveFile)
def sendSR(inputFile):
    pass
def receiveSR():
    pass
main()