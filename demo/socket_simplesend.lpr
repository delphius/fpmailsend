program socket_simplesend;

{$mode objfpc}{$H+}

uses
  opensslsockets, sendmail
  ;

begin
  if sendmail.SendMail('smtp.mail.ru', 'suleymanovr@mail.ru', '', 'suleymanovr@yandex.ru',
    'Test Mail',
    'This is a test email sent using sockets.', 465) then
    WriteLn('Mail sent successfully.')
  else
    WriteLn('Error sending mail.');
end.

