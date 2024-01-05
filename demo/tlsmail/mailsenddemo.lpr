program socket_simplesend;

{$mode objfpc}{$H+}

uses
  opensslsockets, IniFiles, sendmail
  ;

var
  aIniFile: TMemIniFile;
  aSMTPServer, aRecipient, aPwd, aSubject, aBody, aSender: String;
  aPort: Integer;

begin
  aIniFile:=TMemIniFile.Create('../simplesend.ini');
  try
    aSMTPServer:=aIniFile.ReadString('smtp', 'server', 'smtp.sample.com');
    aSender:=aIniFile.ReadString('smtp', 'sender', 'sender@sample.com');
    aPwd:=aIniFile.ReadString('smtp', 'password', 'abcdef');
    aRecipient:=aIniFile.ReadString('smtp', 'recipient', 'recipient@sample.com');
    aSubject:=aIniFile.ReadString('smtp', 'subject', 'Test Mail');
    aBody:=aIniFile.ReadString('smtp', 'body', 'This is a test email sent using sockets.');
    aPort:=aIniFile.ReadInteger('smtp', 'port', 465);
    if sendmail.SendMail(aSMTPServer, aSender, aPwd, aRecipient, aSubject, aBody, aPort) then
      WriteLn('Mail sent successfully.')
    else
      WriteLn('Error sending mail.');
  finally
    aIniFile.Free;
  end;
end.

