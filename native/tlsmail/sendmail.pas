unit sendmail;

{$mode objfpc}{$H+}   

interface

uses
  base64, // base64 кодирование/декодирование
  fptls;

function SendMail(const SmtpServer, SenderEmail, Password, RecipientEmail, MailSubject, MailBody: string; SmtpPort: Integer): Boolean;

implementation

function SendMail(const SmtpServer, SenderEmail, Password, RecipientEmail, MailSubject, MailBody: string; SmtpPort: Integer): Boolean;
var
  Buffer: array of Byte;
  MailContent, Base64Encoded: string;

  procedure SendCommand(const Command: string);
  begin
    WriteLn('Client: ', Command);
    fptls.Send(Command + #13#10);
    fptls.Recv(Buffer);
  end;

begin
  Result := False; // По умолчанию считаем, что отправка не удалась
  
  fptls.Connect(SmtpServer, SmtpPort);

  // Отправка команды EHLO
  SendCommand('EHLO client');

  // Производим аутентификацию, отправляя команды AUTH LOGIN
  SendCommand('AUTH LOGIN');

  // Отправка логина (email отправителя) в формате Base64
  Base64Encoded := EncodeStringBase64(SenderEmail);
  if Base64Encoded = '' then
  begin
    WriteLn('Error encoding login.');
    Exit;
  end;
  SendCommand(Base64Encoded);

  // Отправка пароля в формате Base64
  Base64Encoded := EncodeStringBase64(Password);
  if Base64Encoded = '' then
  begin
    WriteLn('Error encoding password.');
    Exit;
  end;
  SendCommand(Base64Encoded);

  // Отправка команды MAIL FROM
  MailContent := 'MAIL FROM: <' + SenderEmail + '>';
  SendCommand(MailContent);

  // Отправка команды RCPT TO
  MailContent := 'RCPT TO: <' + RecipientEmail + '>';
  SendCommand(MailContent);

  // Отправка команды DATA
  SendCommand('DATA');

  // Отправка данных письма
  MailContent :=
    'Subject: ' + MailSubject + #13#10 +
    'From: <' + SenderEmail + '>' + #13#10 +
    'To: <' + RecipientEmail + '>' + #13#10 +
    #13#10 +
    MailBody + #13#10 +
    '.';

  SendCommand(MailContent);

  // Отправка команды QUIT
  SendCommand('QUIT');

  // Закрытие сокета
  fptls.ConClose;

  Result := True; // Отправка прошла успешно
end;

end.
