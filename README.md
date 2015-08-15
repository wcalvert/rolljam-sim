# "Rolljam" attack simulation

This Python code simulates what is being called a "Rolljam" attack. In this attack, the attacker steals a rolling code and replays it to gain access to a locked vehicle.

To prevent the Rolljam attack, I store a list of codes which have been "rolled" through, and do not trust them, as they could have been stolen by the attacker.

# Info

Here is a Wired article about the Rolljam attack: http://www.wired.com/2015/08/hackers-tiny-device-unlocks-cars-opens-garages/

# How-To

To run the code:

	```
	python rolljam.py
	```
And observe the output.