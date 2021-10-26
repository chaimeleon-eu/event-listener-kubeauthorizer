/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package grycap.keycloak.event.listener.kube_authorizer;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import org.jboss.logging.Logger;
import java.util.Set;
import java.util.logging.Level;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

/**
 *
 * @author Sergio López Huguet (serlohu@upv.es)
 */
public class KubeAuthorizerEventListenerProvider implements EventListenerProvider{
    
    private static final Logger log = Logger.getLogger(KubeAuthorizerEventListenerProvider.class);

    private final KeycloakSession session;
    private final RealmProvider model;
    private ResourceType target_event; 
    private Set<String> target_groups; 
    private String kubeauthorizer_endpoint, kubeauthorizer_token, kubeauthorizer_userclaim;
    
    public KubeAuthorizerEventListenerProvider(KeycloakSession session, ResourceType event, Set<String> groups, String kubeauthorizer_endpoint, String kubeauthorizer_token, String kubeauthorizer_userclaim) {
        this.session = session;
        this.model = session.realms();
        this.target_event = event;
        this.target_groups = groups;
        this.kubeauthorizer_endpoint = kubeauthorizer_endpoint;
        this.kubeauthorizer_token = kubeauthorizer_token;
        this.kubeauthorizer_userclaim = kubeauthorizer_userclaim;
    }

    @Override
    public void onEvent(Event event) {
    }

    @Override
    public void close() {

    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        String user_id, user_name, user_email, group_id, group_name;
        String post_endpoint, post_json;
        
        RealmModel realm = this.model.getRealm(event.getRealmId());
        

        
        if ( target_event.equals(event.getResourceType()) && event.getOperationType().equals(OperationType.CREATE) ){
            log.info( String.format( "### ------------ NEW ADMIN ENVENT - %s - %s ------------ ###", event.getResourceType().toString(), event.getOperationType().toString() ) );
            
            user_id = event.getResourcePath().split("/")[1];
            user_name = this.session.users().getUserById(realm, user_id).getUsername();
            user_email = this.session.users().getUserById(realm, user_id).getEmail();
            group_id = event.getResourcePath().split("/")[3];
            group_name = realm.getGroupById(group_id).getName() ;
            
            
            log.info( String.format( "User %s (%s) added to %s (%s) group", user_name, user_id, group_name, group_id) );
            
            if (target_groups.contains(group_name)) {
                log.info( String.format( "Send authorization request to kube-authorizer for user: name=%s; id/sub=%s, email=%s", user_name, user_id, user_email) );
                
                post_endpoint = String.format("%s/authorize/%s", this.kubeauthorizer_endpoint, user_name) ;
                
                if (this.kubeauthorizer_userclaim.equals("sub") || this.kubeauthorizer_userclaim.equals("id")){
                    post_endpoint = String.format("%s/authorize/%s", this.kubeauthorizer_endpoint, user_id) ;
                }
                
                HttpPost post = new HttpPost(post_endpoint);
                post_json = String.format( "{ \"email\": \"%s\" }", user_email) ;
                StringEntity entity;
                
                entity = new StringEntity(post_json, ContentType.APPLICATION_JSON);
                post.setEntity(entity);
                post.addHeader("Accept", "application/json");
                post.addHeader("Content-type", "application/json");
                post.addHeader("Authorization", this.kubeauthorizer_token);
                                    
                CloseableHttpClient httpclient = HttpClients.createDefault();

                try( CloseableHttpResponse response = httpclient.execute(post) ) {
                    HttpEntity response_entity = response.getEntity();
                    String responseString = EntityUtils.toString(response_entity, "UTF-8");
                    log.info(String.format( "kube-authorizer response (status code=%d). Message: %s", response.getStatusLine().getStatusCode(), responseString) );
                } catch (IOException ex) {
                    java.util.logging.Logger.getLogger(KubeAuthorizerEventListenerProvider.class.getName()).log(Level.SEVERE, null, ex);
                }   
            }
            
        log.info("-----------------------------------------------------------");   
        }
        
       
                
    }
    
}
