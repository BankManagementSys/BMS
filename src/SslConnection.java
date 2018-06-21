/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package RemoteTier;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;

/**
 *
 * @author Windows
 */
public class SslConnection {
    //when deployed these parameters must be host specific
    private static final String KEYSTORE_LOCATION="C:\\Windows\\System32\\bank.keys";
    private static final String KEYSTORE_PASSWORD="bank12";
    public static SslRMIServerSocketFactory getServerFactory(){
        ArrayList<String> non_certificates=new ArrayList();
        try {
            for(String cipher:SSLContext.getDefault().getSupportedSSLParameters().getCipherSuites()){
                //if the current Cipher suite does not require certificates than add it to the list of preffered cipher suites..
                if(cipher.contains("anon")){
                    non_certificates.add(cipher);
                }
            }
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        String[] buffer=new String[non_certificates.size()];
        String[] enabledProtocols;
        try {
            enabledProtocols = SSLContext.getDefault().getSupportedSSLParameters().getProtocols();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return null;
        }
        System.setProperty("javax.net.ssl.keyStore",KEYSTORE_LOCATION);
        System.setProperty("javax.net.ssl.keyStorePassword",KEYSTORE_PASSWORD);
        return new SslRMIServerSocketFactory(non_certificates.toArray(buffer),enabledProtocols,false);
    }
    public static SslRMIClientSocketFactory getClientFactory(){
        String enabledCipherSuites="";
        String enabledProtocols="";
        String[] enabledCipherSuitesArray;
        try {
            enabledCipherSuitesArray = SSLContext.getDefault().getSupportedSSLParameters().getCipherSuites();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return null;
        }
        int i;
        for(i=0;i<enabledCipherSuitesArray.length-1;i++) {
            if(enabledCipherSuitesArray[i].contains("anon"))
                enabledCipherSuites+=enabledCipherSuitesArray[i]+",";
        }
        enabledCipherSuites+=enabledCipherSuitesArray[i];
        String[] enabledProtocolsArray;
        try {
            enabledProtocolsArray = SSLContext.getDefault().getSupportedSSLParameters().getProtocols();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return null;
        }
        for(i=0;i<enabledProtocolsArray.length-1;i++) {
            enabledProtocols+=enabledProtocolsArray[i]+",";
        }
        enabledProtocols+=enabledProtocolsArray[i];
        System.setProperty("javax.rmi.ssl.client.enabledCipherSuites",enabledCipherSuites);
        System.setProperty("javax.rmi.ssl.client.enabledProtocols",enabledProtocols);
        System.setProperty("javax.net.ssl.keyStore",SslConnection.KEYSTORE_LOCATION);
        System.setProperty("javax.net.ssl.keyStorePassword",SslConnection.KEYSTORE_PASSWORD);
        return new SslRMIClientSocketFactory();
    }
    //this method will be used to synchronously send message to an online host
    public static void send(SSLSocket sendto,String message){
        //this method will be used to send messsge
        //but since this operation has been defined in the Message class this should probabaly call that implementation
    }
    //when an employee comes online this method will be used to probe the database if message is stored for that employee
    public static/*I dont know what will be returned but definietly is not void*/void receive(String username){

    }
}
