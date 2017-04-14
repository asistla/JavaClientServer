package prispert;

/* Transmitter program. 
 * To set destination, enter IP address in the main() method.
 * Port is set as 9696. To change port, go to line 68*/

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.io.*;
import java.net.DatagramPacket;
import java.util.Random;
import java.util.Arrays;
import java.net.SocketTimeoutException;
public class Trans1 {
	private static byte[] key={83, 127, 120, -26, 6, 37, 127, 125, 108, 8, 91, 88, -40, 69, 27, 84};
	private static byte[] data=new byte[500];
	private static int seqNum;																		//32 bits=4 bytes
	Packet[] toSend=new Packet[17];																	//Array of packets.
	byte[] payload=new byte[30];
	byte[] lastPayload=new byte[20];
	int index=0;
	Random rand=new Random();
	Trans1() throws IOException{
		/*FileOutputStream fs=new FileOutputStream(new File("Transmitter.txt"));					//Remove comment markers to get output in text file.
		PrintStream p=new PrintStream(fs);
		System.setOut(p);*/
		rand.nextBytes(data);
		seqNum=rand.nextInt();
		System.out.println("Transmission started");
		System.out.println("KEY: "+Arrays.toString(key));
		for(int i=0;i<17;i++){																		//Creating packets, filling packet array toSend.
			if(i<16){
				for(int j=0;j<30;j++){
					payload[j]=data[index];
					index+=1;
				}
				toSend[i]=new Packet(payload,key,seqNum);
				seqNum+=payload.length;
			}
			else{
				for(int j=0;j<20;j++){
					lastPayload[j]=data[index];
					index+=1;
				}
				toSend[i]=new Packet(lastPayload,key,seqNum);
			}
		}
	}


	public void send(Packet[] pack, String IPAddress) throws SocketException,UnknownHostException,IOException{
		DatagramSocket destSocket=new DatagramSocket();
		boolean ty,a,inc;
		InetAddress destination=InetAddress.getByName(IPAddress);
		byte[] response=new byte[9];
		byte type;
		byte[] exp;																					//Expected sequence number
		byte[] ack=new byte[4];
		byte[] intchk=new byte[4];																	//calculated integrity check
		byte[] chkrec;																				//received integrity check
		byte[] tail={0,0,0};
		DatagramPacket rec=new DatagramPacket(response,response.length);
		int index=0;
		int len;
		RC4 rc;
		for(int i=0;i<pack.length;i++){
			DatagramPacket send=new DatagramPacket(pack[i].packet,pack[i].packet.length,destination,9696);
			destSocket.send(send);
			System.out.println("Sending Packet "+i+": ");
//			System.out.println(Arrays.toString(pack[i].packet));									//Remove comment markers to print packet being sent.
			for(int j=0;j<4;j++){
				destSocket.setSoTimeout(1000*(int)Math.pow(2, j));
				try{
					System.out.println(Math.pow(2, j)+" seconds");
					destSocket.receive(rec);
					type=response[0];																 //type from response packet
					if(type==(byte)0xFF) ty=true;
					else ty=false;
					if(!ty) System.out.println("Type error.");
//	---------------------------------------------------------------------------------------------------------------------------------------				
					ByteArrayOutputStream bytes=new ByteArrayOutputStream();
					bytes.write(response,1,4);					
					ack=bytes.toByteArray();														 //acknowledgement number from response packet
					bytes.close();
					if (index==pack.length-1)len=20;
					else len=30;
					int t=ByteBuffer.wrap(pack[index].seqN).getInt()+len;						   	 //calculating next expected sequence number
					exp=ByteBuffer.allocate(4).putInt(t).array();
					a=Arrays.equals(ack,exp);
					if(!a) System.out.println("Sequence error");
//  ---------------------------------------------------------------------------------------------------------------------------------------					
					bytes.reset();
					bytes.write(response,5,4);														 //Integrity check section from response packet
					intchk=bytes.toByteArray();
					bytes.reset();
					bytes.write(response,0,5);
					bytes.write(tail);
					byte[] temp=bytes.toByteArray();												 //Integrity check performed on first five bytes of response packet
					rc=new RC4(temp,key);															 //Calculating ciphertext for response packet
					chkrec=rc.compress(rc.encrypt());											
					inc=Arrays.equals(intchk,chkrec);
					if (!inc) System.out.println("Integrity check error in response packet");
//  ------------------------------------------------------- --------------------------------------------------------------------------------					
					if(ty&&a&&inc){
						if(index==pack.length-1){
							System.out.println("Ack from packet "+i+" received.");
							System.out.println("Data successfully sent.");
							destSocket.close();
							System.exit(1);
						}
						else {
							System.out.println("Ack from packet "+i+" received.");
							index+=1;
						}
						break;   
					}
					else {
						throw new SocketTimeoutException();
					}
				}
				catch(SocketTimeoutException e){
					if(j==3) {
						System.out.println("Connection failure");
						System.exit(1);
					}
					else{
						destSocket.send(send);
						continue;
					}
				}
			}
		}	
	}
//  ----------------------------------------------------------------------------------------------------------------------------------------------
	public static void main(String[] args) throws IOException{
		Trans1 transone=new Trans1();
		transone.send(transone.toSend,"10.0.0.214");																	//Enter Required IP Address here.
	}

}
//  ----------------------------------------------------------------------------------------------------------------------------------------------
//  Class to create packets from data.
class Packet{
    byte[] checkVal=new byte[4];
    byte[] seqN;
	byte length;
	byte type;
	byte[] packet;
	byte[] encrypted;
   	Packet(byte[] payload,byte[] k,int seq)throws IOException{
		if (payload.length==30){
			length=(byte)30;
			type=(byte)0x55;
		}
		else {
			length=(byte)20;
			type=(byte)170;
		}
		ByteArrayOutputStream packetOut=new ByteArrayOutputStream();	
		seqN=ByteBuffer.allocate(4).putInt(seq).array();																					//Converts integer to byte array.
		packetOut.write(type);
		packetOut.write(seqN);
		packetOut.write(length);
		packetOut.write(payload);
		packet=packetOut.toByteArray();					
		RC4 chk=new RC4(packet,k);
		encrypted=chk.encrypt();
		checkVal=chk.compress(encrypted);
		packetOut.write(checkVal);
		packet=packetOut.toByteArray();
	}
}
//  -------------------------------------------------------------------------------------------------------------------------------------
