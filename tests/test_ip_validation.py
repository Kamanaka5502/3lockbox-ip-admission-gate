import pytest
from app.ip2location_client import IP2LocationClient,IP2LocationError
@pytest.mark.parametrize('ip',["127.0.0.1","10.0.0.1","192.168.1.2","::1"])
def test_private_refused(ip):
    with pytest.raises(IP2LocationError): IP2LocationClient.validate_public_ip(ip)
def test_public_ok(): assert str(IP2LocationClient.validate_public_ip("8.8.8.8"))=="8.8.8.8"
