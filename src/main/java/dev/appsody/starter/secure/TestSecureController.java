package dev.appsody.starter.secure;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWTOptions;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

@Path("/oauth")
@ApplicationScoped
public class TestSecureController {

    private String key;

    @PostConstruct
    public void init() {
        key = readPemFile();
    }

    @POST
    @Path("/token")
    public String testSecureCall() {
        Client client = ClientBuilder.newClient();
        if (key == null) {
            throw new WebApplicationException("Unable to read privateKey.pem", 500);
        }
        String jwt = generateJWT(key);
        // any method to send a REST request with an appropriate header will work of course.
        String username = "WASABI";
        System.out.println("KEY " + jwt);
        //WebTarget target = ClientBuilder.newClient().target("http://localhost:8080/micro/customer/search/");

        //WebTarget target = ClientBuilder.newClient().target("http://localhost:8080/micro/customer/search?username="+username);
        //WebTarget target = ClientBuilder.newClient().target("http://localhost:9081/data/protected");

        WebTarget myResource = client.target("http://host.docker.internal:8080/micro/customer/search/");
        String user = myResource.request(MediaType.APPLICATION_JSON)
                .post(Entity.json(username), String.class);
        System.out.println("ALPHA " + user);

        //System.out.println("TARGET  " + target.request());

        //Response response = target.request().header("username", "Bearer " + jwt).buildGet().invoke();
        Response response = myResource.request().header("username", "Bearer " + jwt).buildGet().invoke();
        return String.format("Claim value within JWT of 'custom-value' : %s", response.readEntity(String.class));
    }

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

    // NOTE:   Expected format is PKCS#8 (BEGIN PRIVATE KEY) NOT PKCS#1 (BEGIN RSA PRIVATE KEY)
    // See gencerts.sh
    private static String readPemFile() {
        StringBuilder sb = new StringBuilder(8192);
        try (BufferedReader is = new BufferedReader(
                new InputStreamReader(
                        TestSecureController.class.getResourceAsStream("/privateKey.pem"), StandardCharsets.US_ASCII))) {
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
}
