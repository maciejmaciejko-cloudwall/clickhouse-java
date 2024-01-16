package com.clickhouse.client.gss;

import org.apache.hc.client5.http.utils.Base64;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class GssAuthorizer {

    private final GSSContext clientContext;

    public GssAuthorizer(String serverName, String host) throws GSSException {
        GSSManager manager = GSSManager.getInstance();
        GSSName gssName = manager.createName(serverName + "@" + host, GSSName.NT_HOSTBASED_SERVICE);
        Oid krb5SpnegoOid = new Oid("1.3.6.1.5.5.2");
        this.clientContext = manager.createContext(gssName, krb5SpnegoOid, null, GSSContext.DEFAULT_LIFETIME);
    }

    public String getToken() throws GSSException {
        return Base64.encodeBase64String(clientContext.initSecContext(new byte[0], 0, 0));
    }

    public boolean isEstablished() {
        return clientContext.isEstablished();
    }
}
