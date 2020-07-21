package dev.appsody.starter.secure;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWTOptions;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

@Path("/oauth")
@Tag(name = "Auth microservice", description = "This is the auth microservice and is responsible for generating tokens")
@ApplicationScoped
/**
 * The responsibility of this controller is to send a secure REST call to the Customer Microservice.
 * It generates a JWT token given a Key
 * It reads a PEM file
 *
 */
public class SecureCustomerController {

    private String key;

    /**
     * The responsibility of this function is to generate a JWT token given a Key
     * @param key is the secret key
     * @return the JWT token
     */
    private static String generateJWT(String key) {
        JWTAuth provider = JWTAuth.create(null, new JWTAuthOptions()
                .addPubSecKey(new PubSecKeyOptions()
                        .setAlgorithm("RS256")
                        .setSecretKey(key)
                ));

        MPJWTToken token = new MPJWTToken();
        token.setAud("targetService");
        token.setIss("https://server.example.com");  // Must match the expected issues configuration values
        token.setJti(UUID.randomUUID().toString());

        token.setSub("Jessie");  // Sub is required for WildFly Swarm
        token.setUpn("Jessie");

        token.setIat(System.currentTimeMillis());
        token.setExp(System.currentTimeMillis() + 30000); // 30 Seconds expiration!

        token.addAdditionalClaims("custom-value", "Jessie specific value");

        token.setGroups(Arrays.asList("user", "protected"));

        return provider.generateToken(new JsonObject().mergeIn(token.toJSONString()), new JWTOptions().setAlgorithm("RS256"));
    }

    /**
     * The responsibility of this function is to read a PEM file which is format PKCS#8 (BEGIN PRIVATE KEY)
     * NOT PKCS#1 (BEGIN RSA PRIVATE KEY)
     * @return the PEM file in string format
     */
    private static String readPemFile() {
        StringBuilder sb = new StringBuilder(8192);
        try (BufferedReader is = new BufferedReader(
                new InputStreamReader(
                        SecureCustomerController.class.getResourceAsStream("/privateKey.pem"), StandardCharsets.US_ASCII))) {
            String line;
            while ((line = is.readLine()) != null) {
                if (!line.startsWith("-")) {
                    sb.append(line);
                    sb.append('\n');
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return sb.toString();
    }

    @PostConstruct
    public void init() {
        key = readPemFile();
    }

    @POST
    @Path("/token")
    @Operation(description = "Given a username and password, validate the token to determine if it has access to retrieve " +
            "customer. ")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Successful, returning the customer")
    })

    /*
     * The responsibility of this function is given 2 arguments, username and password
     * it checks if the key is null if so it throws an exception, otherwise it makes a call
     * to the Customer API, more specifically to the /search?username=...password=...
     * The Customer API then returns the customer details.
     */
    public String customerSecureCall(String user, @QueryParam("username") String username, @QueryParam("password") String password) {
        Client client = ClientBuilder.newClient();
        if (key == null) {
            throw new WebApplicationException("Unable to read privateKey.pem", 500);
        }
        String jwt = generateJWT(key);
        // any method to send a REST request with an appropriate header will work of course.
        System.out.println("KEY " + jwt);
        WebTarget target = ClientBuilder.newClient().target("http://localhost:9999/micro/customer/search?=" + username);

        Response response = target.request().header("authorization", "Bearer " + jwt).buildGet().invoke();
        return String.format("Claim value within JWT of 'custom-value' : %s", response.readEntity(String.class));
        //WebTarget myResource = ClientBuilder.newClient().target("http://host.docker.internal:9999/data/search/");
    }
}
