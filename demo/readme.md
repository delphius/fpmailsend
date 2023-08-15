# instruction

Create `simplesend.ini` file in this folder. With content like that:

``` INI
[smtp]
server=smtp.sample.com
sender=demo@sample.com
password=SMTP_PASSWORD
recipient=recipient@sample.com
subject=Test Mail
body=This is a test email sent using sockets. And we check special symbols like emoji 😁 also.

```

This values used for demo `socket_simplesend.exe` app