import paho.mqtt.client as mqtt
import time


def test_mqtt_security():
    print("Testing MQTT Broker mTLS Security...")
    print("=" * 50)
    
    # Test 1: Without certificates (should FAIL)
    print("1. Testing WITHOUT certificates...")
    client1 = mqtt.Client()
    try:
        # Try to connect without any TLS setup
        client1.connect("192.168.0.222", 8883, 5)
        client1.loop_start()
        time.sleep(2)
        if client1.is_connected():
            print("INSECURE: Connected without TLS!")
        else:
            print("SECURE: Connection failed without TLS (expected)")
        client1.loop_stop()
        client1.disconnect()
    except Exception as e:
        print(f"SECURE: Connection failed - {e}")
    
    print("\n" + "-" * 50)
    
    # Test 2: With TLS but no client cert (should FAIL)
    print("2. Testing WITH TLS but NO client certificate...")
    client2 = mqtt.Client()
    try:
        # Setup TLS but no client certificate
        client2.tls_set(ca_certs=None, certfile=None, keyfile=None)
        client2.tls_insecure_set(True)  # Don't verify broker cert
        client2.connect("192.168.0.222", 8883, 5)
        client2.loop_start()
        time.sleep(2)
        if client2.is_connected():
            print("INSECURE: Connected with TLS but no client cert!")
        else:
            print("SECURE: Connection failed without client cert (expected)")
        client2.loop_stop()
        client2.disconnect()
    except Exception as e:
        print(f"SECURE: Connection failed - {e}")
    
    print("\n" + "-" * 50)
    

if __name__ == "__main__":
    test_mqtt_security()