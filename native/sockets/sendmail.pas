program sendmail;

{$mode objfpc}{$H+}

uses
  sockets, // работа с Sockets
  resolve, // Преобразование доменных имен в IP адреса и обратно с помощью DNS
  base64; // base64 кодирование/декодирование

function SendMail(const SmtpServer, SenderEmail, Password, RecipientEmail, MailSubject, MailBody: string; SmtpPort: Integer): Boolean;
var
  CSocket: TSocket;
  Address: TInetSockAddr;
  Buffer: array[0..1023] of Char;
  BytesRead: Integer;
  IPAddr: string;
  MailContent, Base64Encoded: string;
  hrs: THostResolver;

  procedure SendCommand(Socket: TSocket; const Command: string);
  begin
    WriteLn('Client: ', Command);
    fpsend(Socket, PChar(Command + #13#10), longword(Length(Command) + 2), 0);
    BytesRead := fprecv(Socket, @Buffer[0], SizeOf(Buffer), 0);
    Buffer[BytesRead] := #0;
    WriteLn('Server: ', Buffer);
  end;

begin
  Result := False; // По умолчанию считаем, что отправка не удалась

  // Создание сокета
  CSocket := fpsocket(AF_INET, SOCK_STREAM, 0);
  if CSocket = -1 then
  begin
    WriteLn('Error creating socket.');
    Exit;
  end;

  // Преобразование доменного имени SMTP сервера в IP адрес
  hrs := THostResolver.Create(nil);
  if hrs.NameLookup(SmtpServer) then
  begin
    IPAddr := hrs.AddressAsString;
    WriteLn('Resolved IP Address: ', IPAddr);
  end
  else
  begin
    WriteLn('Failed to resolve the hostname: ', SmtpServer);
    Exit;
  end;

  // Подключение к SMTP серверу
  with Address do
   begin
      sin_family := AF_INET; //TCP/IP
      sin_port:= htons(word(SmtpPort)); //Порт
      sin_addr:=StrToNetAddr(hrs.AddressAsString); // IP адрес
   end;

  hrs.Free; // Освобождаем переменную

  if fpconnect(CSocket, @Address, SizeOf(Address)) < 0 then
  begin
    WriteLn('Error connecting to SMTP server.');
    Exit;
  end;

  // Отправка команды EHLO
  SendCommand(CSocket, 'EHLO client');

  // Производим аутентификацию, отправляя команды AUTH LOGIN
  SendCommand(CSocket, 'AUTH LOGIN');

  // Отправка логина (email отправителя) в формате Base64
  Base64Encoded := EncodeStringBase64(SenderEmail);
  if Base64Encoded = '' then
  begin
    WriteLn('Error encoding login.');
    Exit;
  end;
  SendCommand(CSocket, Base64Encoded);

  // Отправка пароля в формате Base64
  Base64Encoded := EncodeStringBase64(Password);
  if Base64Encoded = '' then
  begin
    WriteLn('Error encoding password.');
    Exit;
  end;
  SendCommand(CSocket, Base64Encoded);

  // Отправка команды MAIL FROM
  MailContent := 'MAIL FROM: <' + SenderEmail + '>';
  SendCommand(CSocket, MailContent);

  // Отправка команды RCPT TO
  MailContent := 'RCPT TO: <' + RecipientEmail + '>';
  SendCommand(CSocket, MailContent);

  // Отправка команды DATA
  SendCommand(CSocket, 'DATA');

  // Отправка данных письма
  MailContent :=
    'Subject: ' + MailSubject + #13#10 +
    'From: <' + SenderEmail + '>' + #13#10 +
    'To: <' + RecipientEmail + '>' + #13#10 +
    #13#10 +
    MailBody + #13#10 +
    '.';

  SendCommand(CSocket, MailContent);

  // Отправка команды QUIT
  SendCommand(CSocket, 'QUIT');

  // Закрытие сокета
  CloseSocket(CSocket);

  Result := True; // Отправка прошла успешно
end;

begin
  if SendMail('smtp.rambler.ru', 'yourlogin@rambler.ru', 'yourpassword', 'adressto@mail.com', 'Test Mail', 'This is a test email sent using sockets.', 25) then
    WriteLn('Mail sent successfully.')
  else
    WriteLn('Error sending mail.');
end.
