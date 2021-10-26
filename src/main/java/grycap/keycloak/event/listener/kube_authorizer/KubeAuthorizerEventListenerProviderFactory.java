/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package grycap.keycloak.event.listener.kube_authorizer;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ServerInfoAwareProviderFactory;

/**
 *
 * @author Sergio López Huguet (serlohu@upv.es)
 */
public class KubeAuthorizerEventListenerProviderFactory implements EventListenerProviderFactory, ServerInfoAwareProviderFactory {
    
    private static final Logger log = Logger.getLogger(KubeAuthorizerEventListenerProviderFactory.class);
    private Set<String> groups;
    private ResourceType target_event;
    private String kubeauthorizer_endpoint, kubeauthorizer_token, kubeauthorizer_userclaim;
    
    public KubeAuthorizerEventListenerProvider create(KeycloakSession session) {
        return new KubeAuthorizerEventListenerProvider(session, this.target_event, this.groups, this.kubeauthorizer_endpoint, this.kubeauthorizer_token, this.kubeauthorizer_userclaim);
    }
        
    public String getId() {
        return "event-listener-kubeauthorizer";
    }

    public void init(Config.Scope config) {
        groups = new HashSet<>();
        log.info( String.format( "### ------------  %s.init() ------------ ###", this.getId() ) );
        
        String[] group_names = config.get("OIDCGroups","").split(",");
        if (group_names != null) {
            for (String name : group_names) {
                this.groups.add(name);
            }
        }
        this.target_event = ResourceType.valueOf(config.get("adminEvent", "GROUP_MEMBERSHIP" ) );
        this.kubeauthorizer_endpoint = config.get("kubeAuthorizerEndpoint", "");
        this.kubeauthorizer_token = config.get("kubeAuthorizerToken", "");
        this.kubeauthorizer_userclaim = config.get("kubeAuthorizerUserClaim", "username");
        
        log.info ("Configuration variables: ");
        
        log.info ("\tOIDC groups: " + this.groups.toString());
        log.info ("\tAdmin event target: " + this.target_event.toString());
        log.info ("\tKube-authorizer endpoint: " + this.kubeauthorizer_endpoint );
        log.info ("\tKube-authorizer token: " + this.kubeauthorizer_token);
        log.info ("\tKube-authorizer username claim [sub,username] : " + this.kubeauthorizer_userclaim );

        

        
        log.info( String.format("-----------------------------------------------------------") );
    }

    public void postInit(KeycloakSessionFactory factory) {
    }

    public void close() {
    } 
    
    @Override
    public Map<String, String> getOperationalInfo() {
        Map<String, String> ret = new LinkedHashMap<>();
        ret.put("OIDCgroups", this.groups.toString());
        ret.put("AdminEventTarget", this.target_event.toString());
        ret.put("KubeauthorizerEndpoint", this.kubeauthorizer_endpoint);
        ret.put("KubeauthorizerUserClaim", this.kubeauthorizer_userclaim);
        return ret;
    }
}
