program sendmail;

{$mode objfpc}{$H+}

uses
  WinSock, // WinSock2 Socket Library for Win32
  base64; // base64 encoder & decoder

function SendMail(const SmtpServer, SenderEmail, Password, RecipientEmail, MailSubject, MailBody: string; SmtpPort: Integer): Boolean;
var
  CSocket: TSocket;
  Address: TSockAddrIn;
  Buffer: array[0..1023] of Char;
  BytesRead: Integer;
  IPAddr: string;
  HostEnt: PHostEnt;
  Addr: TInAddr;
  WSAData: TWSAData;
  MailContent, Base64Encoded: string;

  procedure SendCommand(Socket: TSocket; const Command: string);
  begin
    WriteLn('Client: ', Command);
    Send(Socket, PChar(Command + #13#10), Length(Command) + 2, 0);
    BytesRead := Recv(Socket, Buffer[0], SizeOf(Buffer), 0);
    Buffer[BytesRead] := #0;
    WriteLn('Server: ', Buffer);
  end;

begin
  Result := False; // По умолчанию считаем, что отправка не удалась

  // Инициализация WinSock
  if WSAStartup($202, WSAData) <> 0 then
  begin
    WriteLn('Error initializing WinSock.');
    Exit;
  end;

  // Создание сокета
  CSocket := Socket(AF_INET, SOCK_STREAM, 0);
  if CSocket = INVALID_SOCKET then
  begin
    WriteLn('Error creating socket.');
    Exit;
  end;

  // Преобразование доменного имени SMTP сервера в IP адрес
  HostEnt := gethostbyname(PChar(SmtpServer));
  if HostEnt <> nil then
  begin
    Addr := PInAddr(HostEnt^.h_addr_list^)^;
    IPAddr := inet_ntoa(Addr);
  end
  else
  begin
    WriteLn('Host not found: ' + SmtpServer);
    Exit;
  end;

  // Подключение к SMTP серверу
  Address.sin_family := AF_INET;
  Address.sin_port := htons(u_short(SmtpPort));
  Address.sin_addr.s_addr := inet_addr(PChar(IPAddr));

  if connect(CSocket, Address, SizeOf(Address)) < 0 then
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

  // Очистка WinSock
  WSACleanup;

  Result := True; // Отправка прошла успешно
end;

begin
  if SendMail('smtp.rambler.ru', 'yourlogin@rambler.ru', 'yourpassword', 'adressto@mail.com', 'Test Mail', 'This is a test email sent using sockets.', 25) then
    WriteLn('Mail sent successfully.')
  else
    WriteLn('Error sending mail.');
end.
