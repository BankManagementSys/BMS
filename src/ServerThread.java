
package ServerTier;

import RemoteTier.Constants;
import RemoteTier.Message;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.util.HashMap;
import javax.net.ssl.SSLSocket;

    public class ServerThread extends Thread{
        //tge following should refere to the manager's username.
        private SSLSocket ssl_socket;
        private BufferedReader reader;
        private InputStream input_stream;
        private ByteArrayInputStream array_stream;
        private PrintWriter writer;
        public ServerThread(SSLSocket socket){
            this.ssl_socket=socket;
            try {
                this.input_stream=this.ssl_socket.getInputStream();
                this.array_stream=(ByteArrayInputStream)(this.input_stream);
                this.reader=new BufferedReader(new InputStreamReader(this.input_stream));
                this.writer=new PrintWriter(this.ssl_socket.getOutputStream());
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        public ServerThread(String username){

        }
        //this method is responsible for verifying the credentials
        private String verifyAccess(String username,byte[] password){
            return CentralServer.getRemoteDatabaseServer().login(username, password);
        }
        public void run(){
            try {
                this.ssl_socket.startHandshake();
                //the client sends its username with println ones handshaking is done...
                String username=reader.readLine();
                //we prepare a buffer for the password...
                //i think we should do Buffer Overflow check here
                byte[] password=new byte[this.array_stream.available()];
                //then it reads the password into the byte array...
                this.array_stream.read(password);
                //then we send to the client the response from the client;
                String reply=verifyAccess(username,password);
                this.writer.println(reply);
                while(!(reply.equalsIgnoreCase("manager") && reply.equalsIgnoreCase("clerk"))){
                    username=reader.readLine();
                    password=new byte[this.array_stream.available()];
                    this.array_stream.read(password);
                    reply=verifyAccess(username,password);
                    //if the reply is 'already signed in' the manager must be informed
                    //and the connection terminated
                    if(reply.equalsIgnoreCase(Constants.ALREADY_SIGNED_IN)){
                        String message="The account "+username+" was used to signin simultaneously";
                        SSLSocket manager_socket=CentralServer.getSocketof("manager");
                        if(manager_socket!=null){
                            ObjectOutputStream manager_writer=new ObjectOutputStream(manager_socket.getOutputStream());
                            HashMap<String,Object> details=new HashMap<>();
                            details.put(Constants.ALREADY_SIGNED_IN, message);
                            manager_writer.writeObject(new Message(details,Constants.URGENT));
                            manager_writer.close();
                            CentralServer.getRemoteDatabaseServer().saveTempObject("manager", message,
                                    username, password, Constants.STATUS_DELIVERED);
                        }else{
                            CentralServer.getRemoteDatabaseServer().saveTempObject("manager", message, username,
                                    password, Constants.STATUS_PENDING);
                        }
                        this.writer.println(reply);
                        return;
                    }
                    this.writer.println(reply);
                }
                CentralServer.updateConnecteds(username, this.ssl_socket);
                //then the other side shoudl request the personalProfile and messages
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }


