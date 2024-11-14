using System;

using FileNet.Api.Core;
using FileNet.Api.Admin;
using FileNet.Api.Authentication;
using FileNet.Api.Collection;
using FileNet.Api.Util;
using static FileNet.Api.Core.Factory;
using System.Diagnostics;
using System.Net;
using System.Security.Policy;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            // Replace with your FileNet connection details
            string userName = "<acceadmin>";
            string passWord = "<password>";
            string uri = "https://localhost:9443/wsi/FNCEWS40MTOM/";
            string domainName = "<domainname>";

            // Ignore SSL certificate errors
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            // Initialize connection and user context
            try
            {

                // Create credentials (either Kerberos or user name and password).
                // In this case, username/password are supplied from an existing configuration file.
                UsernameCredentials creds = new UsernameCredentials(userName, passWord);

                // Associate this ClientContext with the whole process. 
                ClientContext.SetProcessCredentials(creds);

                // Get the connection and default domain.
                IConnection conn = Factory.Connection.GetConnection(uri);
                // Get domain.
                IDomain domain = Factory.Domain.FetchInstance(conn, domainName, null);

                IObjectStoreSet osColl = domain.ObjectStores;

                // Get each object store.        
                foreach (IObjectStore objStore in osColl)
                {
                    // Get the display name of the object store.
                    String objStoreName = objStore.DisplayName;
                    Console.WriteLine("Object store name = " + objStoreName);
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("An error occurred: " + e.Message);
            }
        }
    }
}
