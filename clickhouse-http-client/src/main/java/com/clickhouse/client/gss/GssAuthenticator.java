package com.clickhouse.client.gss;

import org.apache.hc.client5.http.utils.Base64;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class GssAuthenticator {

    private final GSSContext secContext;

    public GssAuthenticator(String user, String serverName, String host) throws GSSException {
        GSSManager manager = GSSManager.getInstance();
        GSSName gssServerName = manager.createName(serverName + "@" + host, GSSName.NT_HOSTBASED_SERVICE);
        Oid krb5SpnegoOid = new Oid("1.3.6.1.5.5.2");
        GSSName gssClientName = manager.createName(user, GSSName.NT_USER_NAME);
        GSSCredential clientCreds = manager.createCredential(gssClientName, 8 * 3600, krb5SpnegoOid, GSSCredential.INITIATE_ONLY);

        this.secContext = manager.createContext(gssServerName, krb5SpnegoOid, clientCreds, GSSContext.DEFAULT_LIFETIME);
    }

    public String getAuthToken() throws GSSException {
        return Base64.encodeBase64String(secContext.initSecContext(new byte[0], 0, 0));
    }

    public boolean isEstablished() {
        return secContext.isEstablished();
    }
}
