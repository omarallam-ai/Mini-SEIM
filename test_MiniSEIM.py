from MiniSEIM import is_valid_syslog , is_valid_ipv4, extract_ip, is_failed_login


def test_is_valid_syslog():
    assert is_valid_syslog("Jan 06 07:02:37 combo sshd(pam_unix)[28846]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=207.243.167.114  user=root") == True
    assert is_valid_syslog("Jan 06 05:47:51 combo ftpd[28708]: connection from 172.181.208.156 () at Tue Jan 06 05:47:51 2005") == True
    assert is_valid_syslog(" combo ftpd[28708]: connection from () at Tue Jan 06 05:47:51 2005") == False

def test_is_valid_ipv4():
    assert is_valid_ipv4("207.243.167.114") == True
    assert is_valid_ipv4("207.243.167.270") == False


def test_extract_ip():
    assert extract_ip("Jan 06 05:47:51 combo ftpd[28708]: connection from 172.181.208.156 () at Tue Jan 06 05:47:51 2005") == "172.181.208.156"
    assert extract_ip("Jan 06 07:02:37 combo sshd(pam_unix)[28846]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=207.243.167.114  user=root") == "207.243.167.114"


def test_is_failed_login():
    assert is_failed_login("Jan 06 07:02:37 combo sshd(pam_unix)[28846]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=207.243.167.114  user=root") == True
    assert is_failed_login("Jan 10 20:53:04 combo klogind[19272]: Kerberos authentication failed") == True
    assert is_failed_login("Jan 08 23:01:27 combo sshd(pam_unix)[28991]: check pass; user unknown") == True
    assert is_failed_login("Jan 06 05:47:51 combo ftpd[28708]: connection from 172.181.208.156 () at Tue Jan 06 05:47:51 2005") == False
