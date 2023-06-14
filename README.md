# PROX-py









# INFO 

designed for sending large data with fast speed and less handshake 




## info : 

MTU : 1500 

### Flags : 
- Start 
- Ack
- Ack-Ack
- Get-Ack
- Accept
- End
- Err

| State   | Flag : binary | Flag : Decimal|
|  -----  | ------------- | ------------- |
|  Start  |   11111111    |      255      |
|   Ack   |   01010101    |      85       |
| data-ok |   11110000    |      240      |
|  Accept |   11001100    |      204      |
|   Data  |   11101110    |      238      |
|   End   |   00000000    |       0       |
|   Err   |   10010010    |      146      |
|rst-chunk|   10111011    |      187      |
| ack-data|   10110100    |      180      |
| req-ack |   10010110    |      150      |

---
 ### Start Connection 
First starter send a request with start flag to start a connection 
start package also contain file info in structed format 
schema : 
- First 30 bytes is FileName 
- Second 5 bytes in FileSize in byte :
	-  Max : 1099511627775 = 1023.999999999068677 GBytes
- Third 2 bytes is split offset
	- calced from free size of each packet size 
- Forth: 4 bytes is expected number of packets 
	- calced by dividing filesize with split offset
- Fiveth 3 bytes is Ack offset 
	- calced with dividing expected number of packets with 1500 (static)
 



## Sender 




## Reciver 


when got a packet this steps should done :

1.  Check packet protocol 
	- Check for first 1 byte of IP packet data. for PROX should be 234 in decimal and 11101010 binary 

2. Check signature of the packet
	- Resign with Adler-32 and compare with second 4 bytes of PROX data

3. If protocol is support (Only PROX) parse it to create object 

4. Check for flag and state 
	- Convert second 1 byte of PROX packet to Decimal and check number based the flag table

