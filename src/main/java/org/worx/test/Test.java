package org.worx.test;

import java.io.IOException;
import java.util.HashMap;
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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import software.amazon.awssdk.crt.http.HttpRequest;
import software.amazon.awssdk.crt.mqtt.MqttClientConnection;
import software.amazon.awssdk.iot.AwsIotMqttConnectionBuilder;

public class Test {

    private static final String USERDATA_MQTT_ENDPOINT = "mqtt_endpoint";
    private static final String USERDATA_ID = "id";
    private static Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

    public static void main(String[] args) throws Exception {

        // !!!!!! enter your uaername and password !!!!!
        String username = "";
        String password = "";

        // get token
        String token = getAccessToken(username, password);
        String[] deviceSettings = getDevices(token);
        String deviceId = deviceSettings[0];
        String deviceMqttEndpoint = deviceSettings[1];
        // get userData
        HashMap<String, String> userData = getUserData(token);
        String userId = userData.get(USERDATA_ID);
        // String mqttEndpoint = userData.get(USERDATA_MQTT_ENDPOINT);
        String mqttEndpoint = deviceMqttEndpoint;
        // TEST implementation for mqtt connection TEST

        String customAuthorizerName = "com-worxlandroid-customer";
        String usernameMqtt = "iobroker";
        // maybe you have to change the region -> read it from getMqttEndpoint
        String region = "eu-west-1";
        String[] split_mqtt = mqttEndpoint.split(".");
        if (split_mqtt.length == 3) {
            region = split_mqtt[2];
        }
        final String regionF = region;
        // split token ??
        String[] tok = token.replaceAll("_", "/").replaceAll("-", "+").split("\\.");
        String customAuthorizerSig = tok[2];
        String jwt = tok[0] + "." + tok[1];

        // ???
        String clientID = String.format("WX/USER/%s/iobroker/%s", userId, deviceId);
        /*
         * AwsIotMqtt5ClientBuilder.MqttConnectCustomAuthConfig customAuthConfig = new
         * AwsIotMqtt5ClientBuilder.MqttConnectCustomAuthConfig();
         * customAuthConfig.authorizerName = customAuthorizerName;
         * customAuthConfig.username = usernameMqtt;
         * customAuthConfig.tokenKeyName = "jwt";
         * customAuthConfig.tokenValue = jwt;
         * customAuthConfig.tokenSignature = customAuthorizerSig;
         */
        // AwsIotMqtt5ClientBuilder.WebsocketSigv4Config customWssConfig = new
        // AwsIotMqtt5ClientBuilder.WebsocketSigv4Config();
        // customWssConfig.region = region;

        // DefaultChainCredentialsProvider.DefaultChainCredentialsProviderBuilder creds = new
        // DefaultChainCredentialsProvider.DefaultChainCredentialsProviderBuilder()
        // .withClientBootstrap(ClientBootstrap.getOrCreateStaticDefault());

        // customWssConfig.credentialsProvider = creds.build();

        // AwsIotMqtt5ClientBuilder builder = AwsIotMqtt5ClientBuilder.newDirectMqttBuilderWithCustomAuth(mqttEndpoint,
        // customAuthConfig);

        ConnectionCallbacks callback = new ConnectionCallbacks();
        // MyLifecycleEvents lifeCycleEvents = new MyLifecycleEvents();
        // builder.withLifeCycleEvents(lifeCycleEvents);

        // mqttEndpoint += "?x-amz-customauthorizer-name=" + customAuthorizerName + "&x-amz-customauthorizer-signature="
        // + customAuthorizerSig + "&jwt=" + jwt;

        MqttClientConnection mqttClientConnection = AwsIotMqttConnectionBuilder.newDefaultBuilder().withWebsockets(true)
                .withClientId(clientID)
                // .withWebsocketSigningRegion(region)
                // .withWebsocketCredentialsProvider(
                // new DefaultChainCredentialsProvider.DefaultChainCredentialsProviderBuilder()
                // .withClientBootstrap(ClientBootstrap.getOrCreateStaticDefault()).build())
                .withEndpoint(mqttEndpoint)
                // .withCustomAuthorizer("", customAuthorizerName, customAuthorizerSig, null)
                .withUsername(usernameMqtt)

                .withConnectionEventCallbacks(callback).withWebsocketHandshakeTransform((handshakeArgs) -> {

                    HttpRequest httpRequest = handshakeArgs.getHttpRequest();
                    // String p = httpRequest.getEncodedPath();

                    // p += "?x-amz-customauthorizer-name=" + customAuthorizerName +
                    // "&x-amz-customauthorizer-signature="
                    // + customAuthorizerSig + "&jwt=" + jwt;
                    // httpRequest.setEncodedPath(p);
                    // httpRequest.addHeader("protocol", "wss-custom-auth");
                    // httpRequest.addHeader("username", "iobroker");
                    // httpRequest.addHeader("clientId", clientID);
                    // httpRequest.addHeader("region", regionF);
                    httpRequest.addHeader("x-amz-customauthorizer-name", customAuthorizerName);
                    // ??
                    // httpRequest.addHeader("x-amz-customauthorizer-name", customAuthorizerName);
                    httpRequest.addHeader("x-amz-customauthorizer-signature", customAuthorizerSig);
                    // httpRequest.addHeader("Content-Type", "application/json; utf-8");
                    // httpRequest.addHeader("protocol", "wss-custom-auth");
                    // ??
                    // DecodedJWT jwth = new JWT().decodeJwt(token);
                    httpRequest.addHeader("jwt", jwt);
                    // httpRequest.addHeader("Authorization", "Bearer " + jwt);
                    // httpRequest.addHeader("Bearer", jwt);
                    logger.info(httpRequest.getEncodedPath());
                    handshakeArgs.complete(httpRequest);
                }).build();

        // Connect and disconnect
        CompletableFuture<Boolean> connected = mqttClientConnection.connect();

        boolean sessionPresent = connected.get();
        logger.info("Connected to " + (!sessionPresent ? "new" : "existing") + " session!");

        logger.info("Disconnecting...");
        CompletableFuture<Void> disconnected = mqttClientConnection.disconnect();
        disconnected.get();
        logger.info("Disconnected.");

        /*
         * Mqtt5Client client = builder.build();
         * if (client == null) {
         * System.out.println("Client creation failed!");
         * }
         * client.start();
         * DisconnectPacketBuilder disconnectBuilder = new DisconnectPacketBuilder();
         * disconnectBuilder.withReasonCode(DisconnectPacket.DisconnectReasonCode.NORMAL_DISCONNECTION);
         * client.stop(disconnectBuilder.build());
         *
         * // Once fully finished with the Mqtt5Client:
         * client.close();
         */
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

    private static String[] getDevices(String accessToken)
            throws IOException, ClientProtocolException, JsonProcessingException, JsonMappingException {
        final String apiUrl = "https://api.worxlandroid.com/api/v2/product-items?status=1&gps_status=1";

        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet(apiUrl);
        request.addHeader("accept", "application/json");
        request.addHeader("content-type", "application/json");
        request.addHeader("user-agent", "oh");
        request.addHeader("authorization", "Bearer " + accessToken);
        request.addHeader("accept-language", "de-de");

        HttpResponse response = httpClient.execute(request);
        HttpEntity e = response.getEntity();
        String responseString = EntityUtils.toString(e, "UTF-8");

        logger.info(String.format("statuscode %d", response.getStatusLine().getStatusCode()));

        ObjectMapper mapper = new ObjectMapper();
        JsonNode actualObj = mapper.readTree(responseString);
        String deviceId = actualObj.get(0).get("uuid").textValue();
        String deviceMqttEndpoint = actualObj.get(0).get("mqtt_endpoint").textValue();
        return new String[] { deviceId, deviceMqttEndpoint };

    }
}
