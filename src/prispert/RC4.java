package prispert;

class RC4{
	private byte[] stateVec=new byte[256];
	private byte[] tempVec=new byte[256];
	byte[] relevantPacket;
	RC4(byte[] packet,byte[] key){									//Constructor to create data packets 
		if (packet.length==26)
			{
			relevantPacket=new byte[28];
			relevantPacket[26]=0;
			relevantPacket[27]=0;
			  for(int i=0;i<26;i++){
					relevantPacket[i]=packet[i];	
					}
	        }
		else relevantPacket=packet;
		//Initializing state vector.	
		for (int i=0;i<256;i++){
			stateVec[i]=(byte)i;
			tempVec[i]=key[i%key.length];
		}
		int j=0;
		byte t;
			for (int i=0;i<256;i++){
				j=(j+stateVec[i]+tempVec[i])&0XFF;
				t=stateVec[j];
				stateVec[j]=stateVec[i];
				stateVec[i]=t;
			}
        }
	
	public byte[] encrypt(){
			byte[] ciphertext=new byte[relevantPacket.length];
			int i=0;int j=0;int k,t;
			byte tmp;
		    for (int c=0;c<relevantPacket.length;c++){
				i=(i+1)&0XFF;
				j=(j+stateVec[i])&0XFF;
				tmp=stateVec[j];
				stateVec[j]=stateVec[i];
				stateVec[i]=tmp;
				t=(stateVec[i]+stateVec[j])&0XFF;
				k=stateVec[t];
				ciphertext[c]=(byte)(relevantPacket[c]^k);
			}
			return ciphertext;
	   }
	public byte[] compress(byte[] x){
   		byte chk[]=new byte[4];
   		int count=x.length;
   			for(int i=4;i<count-3;i++){
   				chk[0]=(byte)(x[0]^x[i]);
   				i+=3;
   			}
   			for(int i=5;i<count-2;i++){
   				chk[1]=(byte)(x[1]^x[i]);
   				i+=3;
   		    }
   			for(int i=6;i<count-1;i++){
   				chk[2]=(byte)(x[2]^x[i]);
   				i+=3;
   		    }
   			for(int i=7;i<count;i++){
   				chk[3]=(byte)(x[3]^x[i]);
   				i+=3;
   			}
   		return chk;
   	}
}