program sendmail;

{$mode delphi}{$H+}

uses classes, sysutils, base64, IdMessage, IdSMTP, IdLogEvent,
IdSSLOpenSSL, IdSSLOpenSSLHeaders, IdExplicitTLSClientServerBase;

// Объект заглушка для обработки событий
type
  TLogEventHandlers = class
    procedure LogReceived(ASender: TComponent; const AText, AData: string);
    procedure LogSent(ASender: TComponent; const AText, AData: string);
    procedure LogStatus(ASender: TComponent; const AText: string);
  end;

procedure TLogEventHandlers.LogReceived(ASender: TComponent; const AText, AData: string);
begin
  WriteLn('<--- ' + AData);
end;

procedure TLogEventHandlers.LogSent(ASender: TComponent; const AText, AData: string);
begin
WriteLn('---> ' + AData);
end;

procedure TLogEventHandlers.LogStatus(ASender: TComponent; const AText: string);
begin
  WriteLn('Status: ' + AText);
end;

// Параметры для отправки письма
    const
      SmtpServer = 'smtp.mail.ru';
      SmtpPort = 465;
      SmtpLogin = '***@mail.ru';
      SmtpPassword = '***';
      FromAddress = '***@mail.ru';
      FromName = 'Отправитель Sender';
      ToAddress = '***@yandex.ru';
      Subject = 'Тема письма. Mail Subject';
      BodyText = 'Привет! Это тестовое письмо. Hello! This is a test message.';

procedure SendEmail(
    aSmtpServer: string;
    aSmtpPort: integer;
    aSmtpLogin: string;
    aSmtpPassword: string;
    aFromAddress: string;
    aFromName: string;
    aToAddress: string;
    aMessageSubject: string;
    aMessageText: string;
    aUseSSL: boolean = false
    );
var
  lMessage : TIDMessage;
  lSMTP    : TIdSMTP;
  lLogEvent: TIdLogEvent;
  lHandlers: TLogEventHandlers;
  sslHandler: TIdSSLIOHandlerSocketOpenSSL;

begin
  IdOpenSSLSetLibPath(ExtractFilePath(ParamStr(0))); // Указание использовать библиотеки из папки программы
  lLogEvent := TIdLogEvent.Create(nil);
  lHandlers := TLogEventHandlers.Create;
  lMessage:= TIDMessage.Create(nil);
  lSmtp:= TIDSmtp.Create(nil);
  sslHandler:= TIdSSLIOHandlerSocketOpenSSL.Create(nil);

  try
    // Подключение обработчиков событий к объекту TIdLogEvent
    lLogEvent.OnReceived := lHandlers.LogReceived;
    lLogEvent.OnSent := lHandlers.LogSent;
    lLogEvent.OnStatus := lHandlers.LogStatus;
   
    // Установка параметров отправки
    lSMTP.AuthType := satDefault;
    lSMTP.Host     := aSmtpServer;   //Хост
    lSMTP.Port     := aSmtpPort;     //Порт
    lSMTP.Username := aSmtpLogin;    //Логин
    lSMTP.Password := aSmtpPassword; //Пароль

    //-- отправляем почту через SSL, если надо
    if (aUseSSL) then
    begin
      SSLHandler.Destination := aSmtpServer+':'+IntToStr(aSmtpPort);
      SSLHandler.Host := aSmtpServer;
      SSLHandler.Port := aSmtpPort;
      SSLHandler.DefaultPort := 0;
      SSLHandler.SSLOptions.Method := sslvSSLv23;
      SSLHandler.SSLOptions.Mode := sslmUnassigned;
      lSMTP.IOHandler := SSLHandler;
      lSMTP.UseTLS := utUseImplicitTLS;
    end;
   
    lSMTP.Intercept := lLogEvent; // Установка перехватчика событий SMTP
    lLogEvent.Active := True; // Активация логирования
   
    lMessage.NoEncode := True; // Отключение кодирования заголовков и тела письма при отправке средствами Indy

    // Принудительное кодирование и установка необходимых заголовков письма
    lMessage.Headers.AddValue('Subject', '=?UTF-8?B?' + EncodeStringBase64(aMessageSubject) + '?=');
    lMessage.Headers.AddValue('From', '=?UTF-8?B?' + EncodeStringBase64(aFromName) + '?=' + ' <' + aFromAddress + '>');
    lMessage.Headers.AddValue('Content-Type', 'text/plain; charset=utf-8');
    lMessage.Headers.AddValue('Content-Transfer-Encoding', 'base64');
    lMessage.ProcessHeaders; // Установленные через AddValue заголовки парсятся в соответствующие им поля TIdMessage
    // Если установить значение адреса получателя до ProcessHeaders, то оно сбросится,
    // так как не было установлено через AddValue
    lMessage.Recipients.EMailAddresses:= aToAddress;

    lMessage.Body.Text := EncodeStringBase64(aMessageText);
   
    //-- собственно отправка
    lSMTP.Connect;
    try
      lSMTP.Send(lMessage);
    finally
      lSMTP.Disconnect;
    end;

  finally
    lHandlers.Free;
    lLogEvent.Free;
    sslHandler.Free;
    lMessage.Free;
    lSmtp.Free;
  end;
end;

begin 
  try
    // Отправка письма
    SendEmail(
      SmtpServer,
      SmtpPort,
      SmtpLogin,
      SmtpPassword,
      FromAddress,
      FromName,
      ToAddress,
      Subject,
      BodyText,
      true
    );

    Writeln('The email has been sent successfully.');
  except
    on E: Exception do
      Writeln('Error when sending an email: ' + E.Message);
  end;
end.
