


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
	WiFi.begin("NET", "senha123");
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

}

void loop()
{
	// put your main code here, to run repeatedly:

	digitalWrite(LED_BUILTIN, 1);
	delay(100);
	digitalWrite(LED_BUILTIN, 0);
	delay(100);


	static uint32_t last = millis();
	if(millis()-last > 1000l*5)
	{
		if(_tls.connected())
		{
			const char text[] = "this is a test";
			_tls.write((uint8_t*)text, strlen(text)); 
			log_d("sent message");
		}
		else
		{
			int res = _tls.connectAsync("192.168.1.145", 9000);
			log_d("connectAsync() res %d", res);
		}

		last = millis();
	}


	_tls.status();

}


#endif