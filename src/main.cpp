


#ifdef TLSCLIENT_DEV

#include <Arduino.h>
#include <WiFi.h>
#include <TLSClient.h>

TLSClient _tls;

void setup()
{
	// put your setup code here, to run once:
	pinMode(LED_BUILTIN, OUTPUT);

	Serial.begin(115200);
	delay(3000);

	WiFi.mode(WIFI_STA); // Optional
	WiFi.begin("NET_2", "senha123");
	Serial.println("\nConnecting");

	while (WiFi.status() != WL_CONNECTED)
	{
		Serial.print(".");
		delay(100);
	}

	Serial.println("\nConnected to the WiFi network");
	Serial.print("Local ESP32 IP: ");
	Serial.println(WiFi.localIP());

	delay(1000);

	Serial.println("Connecting...");
	uint32_t start = millis();

	int res = _tls.connect("gate1.alagoa.top", 443);
	delay(500);
}

void loop()
{
	// put your main code here, to run repeatedly:

	digitalWrite(LED_BUILTIN, 1);
	delay(100);
	digitalWrite(LED_BUILTIN, 0);
	delay(100);


	static uint32_t last = millis();
	if(millis()-last > 1000l*3)
	{
		if(_tls.connected())
		{
			Serial.println("connected");
		}
		else
		{
			Serial.println("not connected");
		}

		last = millis();
	}


}


#endif