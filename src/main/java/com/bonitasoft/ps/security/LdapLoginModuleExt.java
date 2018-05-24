package com.bonitasoft.ps.security;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;

import com.sun.security.auth.module.LdapLoginModule;

/**
 * @author Pablo Alonso de Linaje García
 */
public class LdapLoginModuleExt extends LdapLoginModule {

    private static final Logger LOGGER = Logger.getLogger(LdapLoginModuleExt.class.getName());

    // Use the default classloader for this class to load the prompt strings.
    private static final ResourceBundle rb = AccessController.doPrivileged(
            new PrivilegedAction<ResourceBundle>() {
                public ResourceBundle run() {
                    return ResourceBundle.getBundle(
                            "sun.security.util.AuthResources");
                }
            }
    );
    private static final String TECHUSERS_KEY = "techUsers";
    private List<String> techUsers = new ArrayList<String>();
    private boolean techUser = false;
    private String username;
    private char[] password;
    private Map<String, Object> sharedState;

    // Keys to retrieve the stored username and password
    private static final String USERNAME_KEY = "javax.security.auth.login.name";
    private static final String PASSWORD_KEY =
            "javax.security.auth.login.password";
    private CallbackHandler callbackHandler;

    @Override
    public boolean login() throws LoginException {
        getUsernamePassword();
        if(checkIfUserDoesNotHaveToLogin(username)){
                techUser = true;
                return true;
        }
        return super.login();
    }

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String,?> sharedState, Map<String,?> options){

        this.sharedState = (Map<String, Object>)sharedState;
        this.callbackHandler = callbackHandler;
        this.techUsers = Arrays.asList(((String)options.get(TECHUSERS_KEY)).split("\\s*,\\s*"));

        super.initialize(subject, callbackHandler, sharedState, options);
    }

    private boolean checkIfUserDoesNotHaveToLogin(String name){
        if(techUsers.contains(name))
            return true;
        else
            return false;
    }

    private void getUsernamePassword()
            throws LoginException {
        
            // use the password saved by the first module in the stack
            username = (String)sharedState.get(USERNAME_KEY);
            password = (char[])sharedState.get(PASSWORD_KEY);
        if (username!=null && !username.isEmpty()) {
            return;
        }

        // prompt for a username and password
        if (callbackHandler == null)
            throw new LoginException("No CallbackHandler available " +
                    "to acquire authentication information from the user");

        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback(rb.getString("username."));
        callbacks[1] = new PasswordCallback(rb.getString("password."), false);

        try {
            callbackHandler.handle(callbacks);
            username = ((NameCallback)callbacks[0]).getName();
            char[] tmpPassword = ((PasswordCallback)callbacks[1]).getPassword();
            password = new char[tmpPassword.length];
            System.arraycopy(tmpPassword, 0,
                    password, 0, tmpPassword.length);
            ((PasswordCallback)callbacks[1]).clearPassword();

        } catch (java.io.IOException ioe) {
            throw new LoginException(ioe.toString());

        } catch (UnsupportedCallbackException uce) {
            throw new LoginException("Error: " + uce.getCallback().toString() +
                    " not available to acquire authentication information" +
                    " from the user");
        }
    }

    @Override
    public boolean commit() throws LoginException {
        if(!techUser){
            return super.commit();
        }else{
            return true;
        }
    }
}
