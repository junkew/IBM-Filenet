// https://www.ibm.com/docs/en/filenet-p8-platform/5.6.0?topic=development-getting-started
package fnp8util2;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;

import com.filenet.api.collection.ObjectStoreSet;
import com.filenet.api.core.Connection;
import com.filenet.api.core.Domain;
import com.filenet.api.core.Factory;
import com.filenet.api.core.ObjectStore;
import com.filenet.api.util.UserContext;

public class FNP8 {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.out.println("Hello World!");
		
		SkipSSLVerification.skipSSLVerification();
		
		//Do not forget to add the right certificate and alias
		String uri = "https://localhost:9443/wsi/FNCEWS40MTOM/";
		//String uri = "https://buildkitsandbox:9443/wsi/FNCEWS40MTOM/";
		
		// Connect to Filenet
        // Set connection parameters; substitute for the placeholders.
        String username = "<adminuser>";
        String password = "<adminpassword>";

        // Make connection.   
        Connection conn = Factory.Connection.getConnection(uri);
        
        //Do not forget the Stanza parameter
        Subject subject = UserContext.createSubject(conn, username, password, "FileNetP8WSI");
        UserContext.get().pushSubject(subject);
        		
		// Get the default domain
	    //Domain domain = Factory.Domain.getInstance(conn, null);
	    Domain domain = Factory.Domain.fetchInstance(conn, null, null);
	    
	    // Just a list of objectstores
	 // Get domain.
	    ObjectStoreSet osColl =  domain.get_ObjectStores();
	                
	    // Get each object store.
	    Iterator<ObjectStore> iterator = osColl.iterator();
	    while(iterator.hasNext())
	    {
	        // Get next object store.
	        ObjectStore objStore = (ObjectStore)iterator.next();
	                        
	        // Get the display name of the object store.
	        String objStoreName = objStore.get_DisplayName();
	        System.out.println("Object store name = " + objStoreName); 
	    }	  
	}
}

class SkipSSLVerification {
	public static void skipSSLVerification() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
            };

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            HostnameVerifier allHostsValid = (hostname, session) -> true;
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

   
}
