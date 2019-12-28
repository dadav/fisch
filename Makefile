PREFIX ?= /usr/local

all: deps install

deps:
	apt-get install -y hostapd dnsmasq

install:
	install -D example.html "$(PREFIX)/share/fisch/example.html"
	install -D -m 0755 fisch.py "$(PREFIX)/bin/fisch"
	install -D -m 0644 fisch.service "$(PREFIX)/lib/systemd/system/fisch.service"
	@systemctl daemon-reload

clean:
	rm "$(PREFIX)/share/fisch/example.html"
	rm "$(PREFIX)/bin/fisch"
	rm "$(PREFIX)/lib/systemd/system/fisch.service"
