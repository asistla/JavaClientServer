package prispert;

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


/* Receives on port 9696 */
public class receiver {
	private static byte[] key={83, 127, 120, -26, 6, 37, 127, 125, 108, 8, 91, 88, -40, 69, 27, 84};
	private byte[] data=new byte[500];
	private byte[] seqNum=new byte[4];
	private byte[] intChk;
	private byte[] recChk;
	private byte[]	recData=new byte[40];
	private byte[] response=new byte[9];
	boolean l,t,i;
	DatagramPacket rec=new DatagramPacket(recData,recData.length);
	receiver()throws IOException{
		/*FileOutputStream fs=new FileOutputStream(new File("Receiver.txt"));       				//remove comment markers to get output in text file
		PrintStream p=new PrintStream(fs);
		System.setOut(p);*/
		ByteArrayOutputStream op=new ByteArrayOutputStream();
		ByteArrayOutputStream output=new ByteArrayOutputStream();
		DatagramSocket socket=new DatagramSocket(9696);
		int len;
		int index=0;
		boolean run=true;																		
		while(run){
			try{
				l=false;t=false;i=false;
				socket.receive(rec);
	//			System.out.println("Packet "+index+" "+Arrays.toString(recData));					//received data
				op.reset();
				len=recData[5];
				if(len<=30)l=true;																	//Checking length
				else System.out.println("Length error.");
				if(recData[0]==(byte)0x55||recData[0]==(byte)0xAA)t=true;							//Checking type
				op.write(recData,0,len+6);															//Collecting relevant part of packet for integrity check
				RC4 rc=new RC4(op.toByteArray(),key);												//RC4
				intChk=rc.compress(rc.encrypt());
				op.reset();
				op.write(recData,len+6,4);															//Collecting integrity check value from received packet
				recChk=op.toByteArray();
//				System.out.println("Expected: "+Arrays.toString(intChk));							//To view expected and received integrity checks.
//				System.out.println("Received "+Arrays.toString(recChk));
				if(Arrays.equals(intChk,recChk))i=true;												//Verifying integrity check match.
				else System.out.println("Integrity check error.");
				if(l&&t&&i){
//					System.out.println("Packet "+index+" received.");
					output.write(recData,6,len);
					if(recData[0]==(byte)0XAA)len=20;
					else len=30;
					response=response(recData,len);
//					System.out.println("Sending response packet: "+Arrays.toString(response));		//Remove comment markers to print response packet being sent.
					DatagramPacket sent=new DatagramPacket(response,response.length,rec.getAddress(),rec.getPort());
//					System.out.println("Sending acknowledgement for packet "+index+".");
					socket.send(sent);
					socket.setSoTimeout(1000);														//To provide controlled exit from while loop.
					index+=1;
//		 			run=false;																		//Remove comment to run in steps.
				}
				else {
					run=false;
					throw new IOException();
				}
			}
			catch(Exception e){
				if(recData[0]==(byte)0XAA){ 
					System.out.println(Arrays.toString(output.toByteArray()));
					System.out.println("Data successfully received.");
					index=0;
					socket.close();
					System.exit(1);
				}
				else if(run=false) System.exit(1);													//To run program in steps for testing.
				else continue;	
			}
		}
	}
	
	public static void main(String[] args)throws IOException{
		receiver res=new receiver();
	}

	byte[] response(byte[] x,int len)throws IOException{
		byte[] tail={0,0,0};
		byte[] res;
		ByteArrayOutputStream br=new ByteArrayOutputStream();
		br.write(x,1,4);
		int seq=ByteBuffer.wrap(br.toByteArray()).getInt()+len;										//Acknowledgement=next expected sequence number
		byte[] s=ByteBuffer.allocate(4).putInt(seq).array();
		br.reset();
		br.write(0xFF);
		br.write(s);
		br.write(tail);
		res=br.toByteArray();
		RC4 rc=new RC4(res,key);
		br.reset();
		br.write(0xFF);								
		br.write(s);
		br.write(rc.compress(rc.encrypt()));
		res=br.toByteArray();
		return res;
	}
}
//  ------------------------------------------------------------------------------------------------------------------------------------------------
