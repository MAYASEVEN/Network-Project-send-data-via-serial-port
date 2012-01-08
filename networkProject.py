#!/usr/bin/env python
#-*- coding:UTF-8 -*-
import serial, os, subprocess, hashlib, time, binascii, base64
from threading import Thread

def main():
    os.system(['clear', 'cls'][os.name == 'nt'])
    print   "###################################################"
    print    " __  __    __     __    _____   __      __  _   _"
    print    "|  \/  |   \ \   / /   / ____|  \ \    / / | \ | |"
    print    "| \  / | __ \ \_/ /_ _| (___   __\ \  / /__|  \| |"
    print    "| |\/| |/ _\ \   / _\ |\___ \ / _ \ \/ / _ \ . \ |"
    print    "| |  | | (_| || | (_| |____) |  __/\  /  __/ |\  |"
    print    "|_|  |_|\__,_||_|\__,_|_____/ \___| \/ \___|_| \_|"
    print   " "
    print   "###################################################"
    print   ""
    print   "http://mayaseven.blogspot.com"
    print   ""
    
    input_mode = raw_input("Computer Network Project 2011\n\nSelect Mode :\n    1.)Send\n    2.)Receive\n    3.)Show info send port\n    4.)Show info receive port\n\nInput number : ")
    if (input_mode.isdigit()):
        input_mode = int(input_mode)
        if(input_mode == 1 or input_mode == 2 or input_mode == 3 or input_mode == 4):
            if(input_mode == 1):
                input_file = raw_input("Input file to send : ")
                send(input_file, -1)
            elif(input_mode == 2): 
                receive(-1)  
            elif(input_mode == 3):
                print "\nShow info send port\n"
                send(-1, 1)
            elif(input_mode == 4):
                print "\nShow info receive port\n"
                receive(1)
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
    
def send(input_file, check):
    ser = serial.Serial(
    port='COM1',
    baudrate=9600,
    parity=serial.PARITY_NONE,
    stopbits=serial.STOPBITS_ONE,
    bytesize=serial.EIGHTBITS,
    timeout=2
    )
    if(check == 1):
        print ser.name
        print ser.isOpen
    else:
        try:
            f = open(input_file, 'rb')
            md5file = "MD5Sum of "+ input_file + " : " + hashlib.md5(f.read()).hexdigest()
            f.flush
            f = open(input_file, 'rb')
            data = f.read()
            f.close()
        except IOError:
            print "Error: can\'t find file or read data"
        else:
            sizeFile = os.stat(input_file).st_size
            packet, numberPacket = packetMake(data, sizeFile)
            print "Sending file size is %s" % sizeFile 
            print "Total number of packet is %s" % numberPacket
            
            i = 0
            handshanke = str(numberPacket) + " " + input_file + "\n"
            ser.write(handshanke)
            while i < (numberPacket):
                ser.write(base64.b64encode(packet[i]) + "\n")
                if(ser.read(3) != "ACK"):
                    continue 
                else:
                    print "Sending packet number " + str(i)
                    i += 1
            print "\n[+] Sending Complete. Filename is %s" %input_file
            print md5file
    ser.flush()       
    
def receive(check):      
    ser = serial.Serial(
            port='COM2',
            baudrate=9600,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=4
            )
    
    if(check == 1):
        print ser.name
        print ser.isOpen
    else:
        handshake = ser.readline()
        numberPacket = int(handshake.split()[0])
        k = 0
        packetR = []
        print numberPacket
        while k < numberPacket:       
            packetR.append(base64.b64decode(ser.readline()))
            crcCheck = packetR[k][-8:]
            crcPacket = binascii.crc32(packetR[k][:-8]) & 0xffffffff
            print "Packet number %s's header is %s" % (k, packetR[k][:8])
            print "Packet number %s CRC is checked " % k + "(%s,%08x)" % (crcCheck, crcPacket)
            ser.write("ACK")
            print "Sending ACK %s" % k + "\n"
            k += 1
        ser.close()
        p = 0
        data = ""
        while p < len(packetR):
            data += packetR[p][8:-8]
            p += 1
        receiveFile = 'Receive'+"_"+handshake.split()[1]
        f = open(receiveFile, 'wb')
        for l in data:
            f.write(l)
        f.flush()
        f = open(receiveFile, 'rb')
        print "[+] Receiving Complete. Filename is %s" %receiveFile
        print "MD5Sum of "+ receiveFile + " : " + hashlib.md5(f.read()).hexdigest()
        f.flush       
    os.system(receiveFile)
    print "Completed"
main()