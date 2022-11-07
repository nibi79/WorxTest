package org.worx.test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import software.amazon.awssdk.crt.auth.credentials.DefaultChainCredentialsProvider;
import software.amazon.awssdk.crt.http.HttpRequest;
import software.amazon.awssdk.crt.io.ClientBootstrap;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.iot.AwsIotMqttConnectionBuilder;

public class Test {

    private static final String USERDATA_MQTT_ENDPOINT = "mqtt_endpoint";
    private static final String USERDATA_ID = "id";
    private static Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

    public static void main(String[] args)
            throws ClientProtocolException, IOException, URISyntaxException, InterruptedException {

        // !!!!!! enter your uaername and password !!!!!
        String username = "XXX";
        String password = "XXX";

        // get token
        String token = getAccessToken(username, password);

        // get userData
        HashMap<String, String> userData = getUserData(token);
        String userId = userData.get(USERDATA_ID);
        String mqttEndpoint = userData.get(USERDATA_MQTT_ENDPOINT);

        // TEST implementation for mqtt connection TEST

        String customAuthorizerName = "com-worxlandroid-customer";
        // maybe you have to change the region -> read it from getMqttEndpoint
        String region = "eu-west-1";

        // split token ??
        String[] tok = token.split("\\.");
        String customAuthorizerSig = tok[2];
        String jwt = tok[0] + "." + tok[1];

        // ???
        String clientID = String.format("WX/USER/%s/oh/%s", userId, UUID.randomUUID().toString());

        MqttClientConnection mqttClientConnection = AwsIotMqttConnectionBuilder.newDefaultBuilder().withWebsockets(true)
                .withClientId(clientID).withWebsocketSigningRegion(region)
                .withWebsocketCredentialsProvider(
                        new DefaultChainCredentialsProvider.DefaultChainCredentialsProviderBuilder()
                                .withClientBootstrap(ClientBootstrap.getOrCreateStaticDefault()).build())
                .withEndpoint(mqttEndpoint)
                // .withConnectionEventCallbacks(callbacks)
                .withWebsocketHandshakeTransform((handshakeArgs) -> {
                    HttpRequest httpRequest = handshakeArgs.getHttpRequest();

                    // ??
                    httpRequest.addHeader("x-amz-customauthorizer-name", customAuthorizerName);
                    httpRequest.addHeader("x-amz-customauthorizer-signature", customAuthorizerSig);
                    httpRequest.addHeader("Content-Type", "application/json; utf-8");
                    // ??
                    DecodedJWT jwth = new JWT().decodeJwt(token);
                    // httpRequest.addHeader("jwt", jwt);
                    httpRequest.addHeader("Authorization", "Bearer " + jwt);

                    handshakeArgs.complete(httpRequest);
                }).build();

        CompletableFuture<Boolean> s = mqttClientConnection.connect();

        Thread.sleep(3000);
        logger.info(s.toString());

        // CompletableFuture<Void> s1 = mqttClientConnection.disconnect();

    }

    /**
     * @param token
     * @return
     * @throws IOException
     * @throws ClientProtocolException
     */
    private static HashMap<String, String> getUserData(String token) throws IOException, ClientProtocolException {

        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet("https://api.worxlandroid.com/api/v2/users/me");
        request.setHeader("Content-Type", "application/json; utf-8");
        request.setHeader("Authorization", "Bearer " + token);
        HttpResponse response = httpClient.execute(request);
        HttpEntity e = response.getEntity();
        String responseString = EntityUtils.toString(e, "UTF-8");

        logger.info(String.format("statuscode %d", response.getStatusLine().getStatusCode()));

        ObjectMapper mapper = new ObjectMapper();
        JsonNode actualObj = mapper.readTree(responseString);

        HashMap<String, String> result = new HashMap<>();
        result.put(USERDATA_ID, String.valueOf(actualObj.get(USERDATA_ID).asInt()));
        result.put(USERDATA_MQTT_ENDPOINT, actualObj.get(USERDATA_MQTT_ENDPOINT).textValue());

        return result;
    }

    /**
     * @param username
     * @param password
     * @return
     * @throws IOException
     * @throws ClientProtocolException
     * @throws JsonProcessingException
     * @throws JsonMappingException
     */
    private static String getAccessToken(String username, String password)
            throws IOException, ClientProtocolException, JsonProcessingException, JsonMappingException {

        JsonObject jsonContent = new JsonObject();
        jsonContent.add("grant_type", new JsonPrimitive("password"));
        jsonContent.add("username", new JsonPrimitive(username));
        jsonContent.add("password", new JsonPrimitive(password));
        jsonContent.add("scope", new JsonPrimitive("*"));
        jsonContent.add("client_id", new JsonPrimitive("150da4d2-bb44-433b-9429-3773adc70a2a"));

        String payload = jsonContent.toString();
        StringEntity entity = new StringEntity(payload, ContentType.APPLICATION_JSON);

        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost request = new HttpPost("https://id.eu.worx.com/oauth/token");
        request.setEntity(entity);

        HttpResponse response = httpClient.execute(request);
        HttpEntity e = response.getEntity();
        String responseString = EntityUtils.toString(e, "UTF-8");

        logger.info(String.format("statuscode %d", response.getStatusLine().getStatusCode()));

        ObjectMapper mapper = new ObjectMapper();
        JsonNode actualObj = mapper.readTree(responseString);
        String token = actualObj.get("access_token").textValue();

        return token;
    }
}
