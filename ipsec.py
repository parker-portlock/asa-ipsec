    #ipsec.py -> Quickly create Cisco ikev1 and ikev2 tunnels
    #Copyright (C) 2018 Parker M. Portlock

    #This program is free software: you can redistribute it and/or modify
    #it under the terms of the GNU General Public License as published by
    #the Free Software Foundation, either version 3 of the License, or
    #(at your option) any later version.

    #This program is distributed in the hope that it will be useful,
    #but WITHOUT ANY WARRANTY; without even the implied warranty of
    #MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    #GNU General Public License for more details.

    #You should have received a copy of the GNU General Public License
    #along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys
import password
import csv
import os


def CiscoTunGroup():
#opens CSVs
	with open('input/ipsecForm.csv','rt') as ipsecForm:
		vpnForm = csv.reader(ipsecForm, delimiter = ',', quotechar = '|')
		vpnForm = list(vpnForm)
	with open('input/localObjects.csv', 'rt') as csvLoc:
		localAddr = csv.reader(csvLoc, delimiter=',', quotechar='|')
		localAddr = list(localAddr)
	with open('input/remoteObjects.csv', 'rt') as csvRem:
		remoteAddr = csv.reader(csvRem, delimiter=',', quotechar='|')
		remoteAddr = list(remoteAddr)

	#creates object group names
	localGroupName = 'VPN_'+ vpnForm[1][1] + '_LOCAL'
	remoteGroupName ='VPN_'+ vpnForm[1][1] + '_REMOTE'
	with open('input/encGroups.csv', 'w', newline='') as csvEncGroup:
		groupWriter = csv.writer(csvEncGroup, delimiter = ',', quotechar = '|')
		groupWriter.writerow([localGroupName,remoteGroupName])
	#writes local object-group output
	print("Creating local group...")
	print("object-group network", localGroupName, file=open("output/ipsec.txt","a"))
	for i in range(len(localAddr)-1):
		print(" network-object object", localAddr[i+1][1], file=open("output/ipsec.txt","a"))
	print("exit", file=open("output/ipsec.txt","a"))
	
	#writes remote object-group output
	print("Creating remote group...")
	print("object-group network", remoteGroupName, file=open("output/ipsec.txt","a"))
	for i in range(len(remoteAddr)-1):
		print(" network-object object", remoteAddr[i+1][1], file=open("output/ipsec.txt","a"))
	print("exit", file=open("output/ipsec.txt","a"))

def CiscoGroup():
	groupName = input("What's the name for the object group? ")
	with open('input/addr.csv', 'rt') as csvObj:
    		address = csv.reader(csvObj, delimiter=',', quotechar='|')
    		address = list(address)

	print("object-group network", groupName, file=open("output/Objects.txt","a"))
	for i in range(len(address)-1):
		print("network-object object", address[i+1][1], file=open("output/Objects.txt","a"))
	print("exit", file=open("output/Objects.txt","a"))

def CiscoTunObject():
#CSV READ
			loadFile = input ("Did you load the localObjects.csv and remoteObjects.csv in /input? (y/n) ")
			if loadFile == "y":
#opens Local and remote CSV
				with open('input/localObjects.csv', 'rt') as csvLoc:
			    		localAddr = csv.reader(csvLoc, delimiter=',', quotechar='|')
			    		localAddr = list(localAddr)
				with open('input/remoteObjects.csv', 'rt') as csvRem:
			    		remoteAddr = csv.reader(csvRem, delimiter=',', quotechar='|')
			    		remoteAddr = list(remoteAddr)
			else:
				print ("Invalid input... exiting program")
				sys.exit()
#Local object Creation
			objectType = "network"
			print("Creating local objects...")
			for i in range(len(localAddr)-1):
				netType = localAddr[i+1][2]
				if netType =='':
					print("object", objectType, localAddr[i+1][1], "\n", "host", localAddr[i+1][0], file=open("output/ipsec.txt", "a"))
				elif netType !='':
					print("object", objectType, localAddr[i+1][1], "\n", "subnet", localAddr[i+1][0], localAddr[i+1][2], file=open("output/ipsec.txt", "a"))

#Remote object Creation
			print("creating remote objects...")
			for i in range(len(remoteAddr)-1):
				netType = remoteAddr[i+1][2]
				if netType =='':
					print("object", objectType, remoteAddr[i+1][1], "\n", "host", remoteAddr[i+1][0], file=open("output/ipsec.txt", "a"))
				elif netType != '':
					print("object", objectType, remoteAddr[i+1][1], "\n", "subnet", remoteAddr[i+1][0], remoteAddr[i+1][2], file=open("output/ipsec.txt", "a"))
				


with open('input/ipsecForm.csv','rt') as ipsecForm:
    vpnForm = csv.reader(ipsecForm, delimiter = ',', quotechar = '|')
    vpnForm = list(vpnForm)

###################
# object creation #
###################
print("Starting...")
CiscoTunObject()

##################
# group creation #
##################
CiscoTunGroup()

###########################
# crypto-map ACL creation #
###########################

print ("Creating crypto-map ACL...")
with open('input/encGroups.csv', 'rt') as csvGroupName:
	groupNames = csv.reader(csvGroupName, delimiter=',', quotechar='|')
	groupNames = list(groupNames)
cmapACL = 'VPN_'+ vpnForm[1][1] + '_CMAP'
for i in range(len(groupNames)):
	print ("\naccess-list", cmapACL, "extended permit ip object-group", groupNames[i][0], "object-group", groupNames[i][1], file=open("output/ipsec.txt","a"))

###########################
# vpn filter ACL creation #
###########################

print ("Creating VPN filter ACL...")
filterACL ='VPN_'+ vpnForm[1][1] + '_FLTR'
print("access-list", filterACL, "extended deny ip any any", file=open("output/ipsec.txt","a"))

#########################
# group policy creation #
#########################

print ("Creating group policy...")
policyName = 'VPN_'+ vpnForm[1][1] + '_POLICY'
print("\ngroup-policy", policyName, "internal", file=open("output/ipsec.txt","a"))
print("group-policy", policyName, "attributes", file=open("output/ipsec.txt","a"))
print(" vpn-filter value", filterACL, file=open("output/ipsec.txt","a"))

#########################
# determine IKE version #
#########################

ikeVer = vpnForm[1][2]
if ikeVer == "1":
    print(" vpn-tunnel-protocol ikev1", file=open("output/ipsec.txt","a"))
elif ikeVer =="2":
    print(" vpn-tunnel-protocol ikev2", file=open("output/ipsec.txt","a"))
else:
    print("Invalid input")
    sys.exit()

print("exit", file=open("output/ipsec.txt","a"))

#######################
# tunnel-group config #
#######################

secondaryConf = False
print ("Creating tunnel-group configuration...")
peerIP = vpnForm[1][3]
secondaryIP = vpnForm[1][4]
secret1 = password.generate()
secret2 = password.generate()

if secondaryIP != "":
    secondaryConf = True
    #primary
    print("\ntunnel-group", peerIP, "type ipsec-l2l", file=open("output/ipsec.txt","a"))
    print("tunnel-group", peerIP, "general-attributes", file=open("output/ipsec.txt","a"))
    print(" default-group-policy", policyName, file=open("output/ipsec.txt","a"))
    print("tunnel-group", peerIP, "ipsec-attributes", file=open("output/ipsec.txt","a"))
    print(" ikev1 pre-shared-key", secret1, file=open("output/ipsec.txt","a"))
    print("exit", file=open("output/ipsec.txt","a"))
    #secondary
    print("\ntunnel-group", secondaryIP, "type ipsec-l2l", file=open("output/ipsec.txt","a"))
    print("tunnel-group", secondaryIP, "general-attributes", file=open("output/ipsec.txt","a"))
    print(" default-group-policy", policyName, file=open("output/ipsec.txt","a"))
    print("tunnel-group", secondaryIP, "ipsec-attributes", file=open("output/ipsec.txt","a"))
    print(" ikev1 pre-shared-key", secret2, file=open("output/ipsec.txt","a"))
    print("exit", file=open("output/ipsec.txt","a"))

else:
    #primary
    print("\ntunnel-group", peerIP, "type ipsec-l2l", file=open("output/ipsec.txt","a"))
    print("tunnel-group", peerIP, "general-attributes", file=open("output/ipsec.txt","a"))
    print(" default-group-policy", policyName, file=open("output/ipsec.txt","a"))
    print("tunnel-group", peerIP, "ipsec-attributes", file=open("output/ipsec.txt","a"))
  
    if ikeVer == "1":
        print(" ikev1 pre-shared-key", secret1, file=open("output/ipsec.txt","a"))
        print("exit", file=open("output/ipsec.txt","a"))
    elif ikeVer =="2":
        print(" ikev2 remote-authentication pre-shared-key", secret1, file=open("output/ipsec.txt","a"))
        print(" ikev2 local-authentication pre-shared-key", secret2, file=open("output/ipsec.txt","a"))
        print("exit", file=open("output/ipsec.txt","a"))
    else:
        print("something broke.")

############################
# Crypto Map configuration #
############################

print ("Configuring crypto map...")
cmapIndex = vpnForm[1][10]
outsideMapName = vpnForm[1][11]
p2Prop = vpnForm[1][5]
p2Life = vpnForm[1][6]
if ikeVer == "1":
    ikeNegMode = vpnForm[1][9]
    print("\ncrypto map", outsideMapName, cmapIndex, "set ikev1 phase1-mode", ikeNegMode, file=open("output/ipsec.txt","a"))
    print("crypto map", outsideMapName, cmapIndex, "set ikev1 transform-set", p2Prop, file=open("output/ipsec.txt","a"))
elif ikeVer =="2":
    print("\ncrypto map", outsideMapName, cmapIndex, "set ikev2 ipsec-proposal", p2Prop, file=open("output/ipsec.txt","a"))
else:
    print("Invalid IKE version. Exiting...")
    sys.exit()
print("crypto map", outsideMapName, cmapIndex, "match address", cmapACL, file=open("output/ipsec.txt","a"))
print("crypto map", outsideMapName, cmapIndex, "set security-association lifetime seconds", p2Life, file=open("output/ipsec.txt","a"))
pfs = vpnForm[1][7]
if pfs == "y":
    dhGroup = vpnForm[1][8]
    print("crypto map ", outsideMapName," ",cmapIndex, " set pfs group", dhGroup, sep="", file=open("output/ipsec.txt","a"))
else:
    print("Setting defaults...")
if secondaryConf == True:
    print("crypto map", outsideMapName, cmapIndex, "set peer", peerIP, secondaryIP, file=open("output/ipsec.txt","a"))
else:
    print("crypto map", outsideMapName, cmapIndex, "set peer", peerIP, file=open("output/ipsec.txt","a"))
    

print ("Your IPSec tunnel configuration is complete. Use the output located in /output/ipsec.txt.")

#################
# Cleanup Items #
#################

os.remove("input/encGroups.csv")

print ("All done, please remember to configure the other side of the tunnel with the same password that was auto-generated.")