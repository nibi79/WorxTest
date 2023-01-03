package org.worx.test;

import software.amazon.awssdk.crt.mqtt.MqttClientConnectionEvents;

public class ConnectionCallbacks implements MqttClientConnectionEvents {

    @Override
    public void onConnectionInterrupted(int errorCode) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onConnectionResumed(boolean sessionPresent) {
        // TODO Auto-generated method stub

    }

}
