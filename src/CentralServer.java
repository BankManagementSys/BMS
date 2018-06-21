public class CentralServer {

package ServerTier;

import RemoteTier.Constants;
import RemoteTier.RemoteDatabaseServer;
import RemoteTier.SslConnection;
import java.io.IOException;
import java.net.ServerSocket;
import java.rmi.AlreadyBoundException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLSocket;
import javax.rmi.ssl.SslRMIServerSocketFactory;

    /**
     *
     * @author Windows
     */
    public class CentralServer {
        //this should reference the IP of the database server
        private static final String DATABASE_OBJECT_IP="";
        private static RemoteDatabaseServer databseStub;
        private static SslRMIServerSocketFactory server;
        private static ServerSocket serverSocket;
        //private static final int server_port=12345;
        private static SSLSocket socket;
        private static HashMap<String,ArrayList<Byte>> random_ids;
        private static Registry clerkRegistry;
        private static Registry managerRegistry;
        private static HashMap<String,SSLSocket> connecteds;
        private static final String MANAGER_OBJECT_KEY="manager";
        //private static final String CLERK_OBJECT_KEY="clerk";
        public static void main(String[] args) throws NoSuchAlgorithmException, IOException{
            getDatabaseStub();
            createRMIObject();
            AcceptConnection();
        }
        protected static RemoteDatabaseServer getRemoteDatabaseServer(){
            return CentralServer.databseStub;
        }
        private static void getDatabaseStub(){
            try {
                Registry registry=LocateRegistry.getRegistry(DATABASE_OBJECT_IP,
                        Constants.DATABASE_OBJECT_PORT, SslConnection.getClientFactory());
                CentralServer.databseStub=(RemoteDatabaseServer)(registry.lookup(Constants.DATABASE_OBJECT_KEY));
            } catch (RemoteException ex) {
                Logger.getLogger(CentralServer.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NotBoundException ex) {
                Logger.getLogger(CentralServer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        private static void AcceptConnection()throws NoSuchAlgorithmException, IOException{
            random_ids=new HashMap();
            server=SslConnection.getServerFactory();
            serverSocket =server.createServerSocket(Constants.SERVER_PORT);
            System.out.println("listening...");
            while(true){
                socket=(SSLSocket)serverSocket.accept();
                new ServerThread(socket).start();
            }
        }
        //this method will be responsible for updating the buffer that contains the random employee identifiers
        protected static void updateBuffer(String username,byte[] id){
            ArrayList<Byte> bytes=new ArrayList();
            for(Byte b:id) bytes.add(b);
            random_ids.put(username, bytes);
        }
        protected static void updateConnecteds(String username,SSLSocket socket){
            CentralServer.connecteds.put(username,socket);
        }
        protected static SSLSocket getSocketof(String username){
            return CentralServer.connecteds.get(username);
        }
        protected static void removeConnecteds(String username){
            CentralServer.connecteds.remove(username);
        }
        //whenever all the remote objects are called the users will be required to supply their id and
        //this method will be called to verify that id
        protected static boolean contains_as(String username,byte[] id){
            ArrayList<Byte> bytes=new ArrayList();
            if(random_ids.containsKey(username)){
                ArrayList<Byte> value=random_ids.get(username);
                for(byte v:id) bytes.add(v);
                return bytes.equals(value);
            }
            return false;
        }
        //this method will be respendible for creating the ManagerTask and ClientTask remote objects and exporting them...
        private static void createRMIObject(){
            try {
                clerkRegistry=LocateRegistry.createRegistry(Constants.CLERK_OBJECT_PORT, null, server);
                clerkRegistry.bind(Constants.CLERK_OBJECT_KEY,new Clerk());
                managerRegistry=LocateRegistry.createRegistry(Constants.MANAGER_OBJECT_PORT, null, server);
                managerRegistry.bind(CentralServer.MANAGER_OBJECT_KEY,new Manager());
            } catch (RemoteException ex) {
                ex.printStackTrace();
            } catch (AlreadyBoundException ex) {
                ex.printStackTrace();
            }


        }
        //ones the server is done with all connections and before closing it unbinds the thw remote objects..
        private static void destroyRMIObject(){
            try {
                if(!(clerkRegistry==null && managerRegistry==null)){
                    clerkRegistry.unbind(Constants.CLERK_OBJECT_KEY);
                    managerRegistry.unbind(CentralServer.MANAGER_OBJECT_KEY);
                }
                else{
                    //log that the registry is not yet created
                }
            } catch (RemoteException ex) {
                ex.printStackTrace();
            } catch (NotBoundException ex) {
                ex.printStackTrace();
            }
        }
        //this methiod will be responsible for doing a security check...
        private void doSecurityCheck(){

        }
    }

}
